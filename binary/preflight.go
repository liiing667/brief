package binary

import (
	"debug/elf"
	stdbin "encoding/binary"
	"fmt"
	"io"
)

// Header field offsets, per the ELF-64 / ELF-32 generic ABI and the PE/COFF
// specification.
const (
	elfHeaderLen32  = 52
	elfHeaderLen64  = 64
	elfShent32      = 40
	elfShent64      = 64
	elfShnumReserve = 0xffff // SHN_XINDEX/PN_XNUM: real count lives in section 0
	elfShnLoReserve = 0xff00

	peDosStubOffsetAt      = 0x3c
	peSignatureLen         = 4
	peCoffHeaderLen        = 20
	peSectionHeaderLen     = 40
	peCoffNumberOfSections = 2
	peCoffSizeOptionalHdr  = 16
)

// preflightELF validates the ELF header's section-table bookkeeping against
// the declared file size before debug/elf.NewFile is called. The standard
// library parser is explicitly not hardened against adversarial input, so a
// forged section count would otherwise make it read or allocate far beyond
// the sample.
func preflightELF(r io.ReaderAt, size int64) error {
	var ident [16]byte
	if _, err := r.ReadAt(ident[:], 0); err != nil {
		return fmt.Errorf("reading elf ident: %w", err)
	}
	switch elf.Class(ident[elf.EI_CLASS]) {
	case elf.ELFCLASS32, elf.ELFCLASS64:
	default:
		return fmt.Errorf("%w: unknown elf class %d", ErrInvalidObject, ident[elf.EI_CLASS])
	}
	is64 := ident[elf.EI_CLASS] == byte(elf.ELFCLASS64)
	var bo stdbin.ByteOrder
	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		bo = stdbin.LittleEndian
	case elf.ELFDATA2MSB:
		bo = stdbin.BigEndian
	default:
		return fmt.Errorf("%w: unknown elf data encoding %d", ErrInvalidObject, ident[elf.EI_DATA])
	}

	hdrLen := elfHeaderLen32
	shent := elfShent32
	if is64 {
		hdrLen = elfHeaderLen64
		shent = elfShent64
	}
	if size < int64(hdrLen) {
		return fmt.Errorf("%w: truncated elf header", ErrInvalidObject)
	}
	hdr := make([]byte, hdrLen)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return fmt.Errorf("reading elf header: %w", err)
	}

	var shoff int64
	var shentsize, shnum uint64
	if is64 {
		shoff = int64(bo.Uint64(hdr[40:48]))
		shentsize = uint64(bo.Uint16(hdr[58:60]))
		shnum = uint64(bo.Uint16(hdr[60:62]))
	} else {
		shoff = int64(bo.Uint32(hdr[32:36]))
		shentsize = uint64(bo.Uint16(hdr[46:48]))
		shnum = uint64(bo.Uint16(hdr[48:50]))
	}
	if shoff < 0 {
		return fmt.Errorf("%w: invalid elf section table offset", ErrInvalidObject)
	}
	if shoff == 0 {
		// No section table; the parser relies on program headers only.
		return nil
	}
	if shentsize < uint64(shent) {
		return fmt.Errorf("%w: elf section entry size %d smaller than %d",
			ErrInvalidObject, shentsize, shent)
	}

	// When shnum is reserved, the real count is the sh_size of section 0.
	if shnum == 0 || shnum == elfShnumReserve {
		ent0 := make([]byte, shent)
		if shoff+int64(shent) > size {
			return fmt.Errorf("%w: elf section table header extends past file", ErrInvalidObject)
		}
		if _, err := r.ReadAt(ent0, shoff); err != nil {
			return fmt.Errorf("reading elf section 0: %w", err)
		}
		if elf.SectionType(bo.Uint32(ent0[4:8])) != elf.SHT_NULL {
			return fmt.Errorf("%w: elf extended section index requires SHT_NULL section 0",
				ErrInvalidObject)
		}
		if is64 {
			shnum = bo.Uint64(ent0[32:40])
		} else {
			shnum = uint64(bo.Uint32(ent0[16:20]))
		}
		if shnum < elfShnLoReserve {
			return fmt.Errorf("%w: invalid extended elf section count %d", ErrInvalidObject, shnum)
		}
	}

	if shnum > maxSectionCount {
		return fmt.Errorf("%w: elf claims %d sections", ErrInvalidObject, shnum)
	}
	tableLen, overflow := checkedMul(shnum, shentsize)
	if overflow {
		return fmt.Errorf("%w: elf section table size overflow", ErrInvalidObject)
	}
	tableEnd, overflow := checkedEnd(uint64(shoff), tableLen)
	if overflow || tableEnd > uint64(size) {
		return fmt.Errorf("%w: elf section table extends past file: off=%#x entries=%d file=%d",
			ErrInvalidObject, shoff, shnum, size)
	}
	return nil
}

// preflightPE validates the PE/COFF section table placement and count before
// debug/pe.NewFile is called.
func preflightPE(r io.ReaderAt, size int64) error {
	var dos [peDosStubOffsetAt + 4]byte
	if int64(len(dos)) > size {
		return fmt.Errorf("%w: truncated pe dos header", ErrInvalidObject)
	}
	if _, err := r.ReadAt(dos[:], 0); err != nil {
		return fmt.Errorf("reading pe dos header: %w", err)
	}
	signoff := int64(stdbin.LittleEndian.Uint32(dos[peDosStubOffsetAt:]))
	if signoff < peDosStubOffsetAt+4 || signoff > size-peSignatureLen {
		return fmt.Errorf("%w: pe signature offset out of bounds", ErrInvalidObject)
	}
	var sig [peSignatureLen]byte
	if _, err := r.ReadAt(sig[:], signoff); err != nil {
		return fmt.Errorf("reading pe signature: %w", err)
	}
	if sig[0] != 'P' || sig[1] != 'E' || sig[2] != 0 || sig[3] != 0 {
		return fmt.Errorf("%w: bad pe signature", ErrInvalidObject)
	}

	coffOff := signoff + peSignatureLen
	if coffOff+peCoffHeaderLen > size {
		return fmt.Errorf("%w: truncated pe coff header", ErrInvalidObject)
	}
	coff := make([]byte, peCoffHeaderLen)
	if _, err := r.ReadAt(coff, coffOff); err != nil {
		return fmt.Errorf("reading pe coff header: %w", err)
	}
	nsec := uint64(stdbin.LittleEndian.Uint16(coff[peCoffNumberOfSections:]))
	if nsec > maxSectionCount {
		return fmt.Errorf("%w: pe claims %d sections", ErrInvalidObject, nsec)
	}
	optSize := uint64(stdbin.LittleEndian.Uint16(coff[peCoffSizeOptionalHdr:]))

	tableLen, overflow := checkedMul(nsec, peSectionHeaderLen)
	if overflow {
		return fmt.Errorf("%w: pe section table size overflow", ErrInvalidObject)
	}
	tableStart, overflow := checkedEnd(uint64(coffOff)+peCoffHeaderLen, optSize)
	if overflow {
		return fmt.Errorf("%w: pe optional header size overflow", ErrInvalidObject)
	}
	tableEnd, overflow := checkedEnd(tableStart, tableLen)
	if overflow || tableEnd > uint64(size) {
		return fmt.Errorf("%w: pe section table extends past file: entries=%d file=%d",
			ErrInvalidObject, nsec, size)
	}
	return nil
}

// checkedMul reports an overflow of a*b.
func checkedMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, true
	}
	return a * b, false
}
