package binary

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	stdbin "encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
)

// trackingReader records the furthest byte range ever requested so tests can
// prove inspection never reads past the declared sample size.
type trackingReader struct {
	data   []byte
	maxEnd int64
}

func (t *trackingReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if end := off + int64(len(p)); end > t.maxEnd {
		t.maxEnd = end
	}
	if off >= int64(len(t.data)) {
		return 0, io.EOF
	}
	n := copy(p, t.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func elf64TestHeader() []byte {
	h := make([]byte, 64)
	copy(h[0:4], []byte{0x7f, 'E', 'L', 'F'})
	h[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	stdbin.LittleEndian.PutUint16(h[16:], uint16(elf.ET_EXEC))
	stdbin.LittleEndian.PutUint16(h[18:], uint16(elf.EM_X86_64))
	stdbin.LittleEndian.PutUint32(h[20:], uint32(elf.EV_CURRENT))
	stdbin.LittleEndian.PutUint32(h[52:], 64) // e_ehsize
	stdbin.LittleEndian.PutUint16(h[58:], 64) // e_shentsize
	return h
}

func elf64Section(nameOff uint32, typ elf.SectionType, off, size uint64) []byte {
	sh := make([]byte, 64)
	stdbin.LittleEndian.PutUint32(sh[0:], nameOff)
	stdbin.LittleEndian.PutUint32(sh[4:], uint32(typ))
	stdbin.LittleEndian.PutUint64(sh[24:], off)  // sh_offset
	stdbin.LittleEndian.PutUint64(sh[32:], size) // sh_size
	return sh
}

// malformedELFHugeShnum claims 0xffff sections; the extended-count section 0
// then declares an enormous sh_size that a naive parser would try to read.
func malformedELFHugeShnum() []byte {
	h := elf64TestHeader()
	stdbin.LittleEndian.PutUint64(h[40:], 64)     // e_shoff
	stdbin.LittleEndian.PutUint16(h[60:], 0xffff) // e_shnum (SHN_XINDEX)
	var b bytes.Buffer
	b.Write(h)
	sh := elf64Section(0, elf.SHT_NULL, 0, math.MaxUint64/2)
	b.Write(sh)
	return b.Bytes()
}

// malformedELFTableEOF puts a large section table past the end of a small
// sample, using a plain (non-extended) section count.
func malformedELFTableEOF() []byte {
	h := elf64TestHeader()
	stdbin.LittleEndian.PutUint64(h[40:], 4096) // e_shoff beyond EOF
	stdbin.LittleEndian.PutUint16(h[60:], 32)   // 32 sections, no table present
	stdbin.LittleEndian.PutUint16(h[62:], 0)
	return h
}

// malformedELF32HugeCount exercises the 32-bit header layout, whose section
// table fields live at different offsets.
func malformedELF32HugeCount() []byte {
	h := make([]byte, elfHeaderLen32)
	copy(h[0:4], []byte{0x7f, 'E', 'L', 'F'})
	h[elf.EI_CLASS] = byte(elf.ELFCLASS32)
	h[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	stdbin.LittleEndian.PutUint16(h[16:], uint16(elf.ET_EXEC))
	stdbin.LittleEndian.PutUint16(h[18:], uint16(elf.EM_386))
	stdbin.LittleEndian.PutUint32(h[20:], uint32(elf.EV_CURRENT))
	stdbin.LittleEndian.PutUint32(h[32:], elfHeaderLen32) // e_shoff
	stdbin.LittleEndian.PutUint16(h[46:], elfShent32)     // e_shentsize
	stdbin.LittleEndian.PutUint16(h[48:], 64)             // 64 sections, none present
	return h
}

// malformedELFBigEndian uses MSB encoding to cover the big-endian path.
func malformedELFBigEndian() []byte {
	h := make([]byte, elfHeaderLen64)
	copy(h[0:4], []byte{0x7f, 'E', 'L', 'F'})
	h[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	h[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	stdbin.BigEndian.PutUint16(h[16:], uint16(elf.ET_EXEC))
	stdbin.BigEndian.PutUint16(h[18:], uint16(elf.EM_S390))
	stdbin.BigEndian.PutUint32(h[20:], uint32(elf.EV_CURRENT))
	stdbin.BigEndian.PutUint64(h[40:], 4096)
	stdbin.BigEndian.PutUint32(h[52:], 64)
	stdbin.BigEndian.PutUint16(h[58:], 64)
	stdbin.BigEndian.PutUint16(h[60:], 8)
	return h
}

// malformedELFOverlap builds two named sections that claim the same bytes,
// carrying forged producer and static-link banner strings.
func malformedELFOverlap() []byte {
	const shoff = 256
	h := elf64TestHeader()
	stdbin.LittleEndian.PutUint64(h[40:], shoff)
	stdbin.LittleEndian.PutUint16(h[60:], 4) // null, .comment, .rodata, shstrtab
	stdbin.LittleEndian.PutUint16(h[62:], 3)

	var b bytes.Buffer
	b.Write(h)
	comment := "GCC: (Forged Trusted Toolchain 99.0) 99.0"
	payload := append([]byte(comment), 0)
	payload = append(payload, []byte("OpenSSL 9.9.9\x00")...)
	b.Write(payload)
	b.Write(make([]byte, shoff-b.Len()))

	b.Write(make([]byte, 64)) // section 0: SHT_NULL
	b.Write(elf64Section(1, elf.SHT_PROGBITS, 64, uint64(len(comment))))
	b.Write(elf64Section(10, elf.SHT_PROGBITS, 64, uint64(len(payload))))
	names := []byte("\x00.comment\x00.rodata\x00")
	b.Write(elf64Section(0, elf.SHT_STRTAB, uint64(shoff+4*64), uint64(len(names))))
	b.Write(names)
	return b.Bytes()
}

// malformedELFSectionEOF declares an in-table section whose raw bytes lie
// beyond the declared file size.
func malformedELFSectionEOF() []byte {
	const shoff = 256
	h := elf64TestHeader()
	stdbin.LittleEndian.PutUint64(h[40:], shoff)
	stdbin.LittleEndian.PutUint16(h[60:], 3) // null, .comment, shstrtab
	stdbin.LittleEndian.PutUint16(h[62:], 2)

	var b bytes.Buffer
	b.Write(h)
	b.Write(make([]byte, shoff-b.Len()))
	b.Write(make([]byte, 64))                            // section 0
	b.Write(elf64Section(1, elf.SHT_PROGBITS, 1<<20, 8)) // offset beyond EOF
	names := []byte("\x00.comment\x00")
	b.Write(elf64Section(0, elf.SHT_STRTAB, uint64(shoff+2*64), uint64(len(names))))
	b.Write(names)
	return b.Bytes()
}

func peTestFile(nsec uint16, sections ...[]byte) []byte {
	var b bytes.Buffer
	dos := make([]byte, 64)
	dos[0], dos[1] = 'M', 'Z'
	stdbin.LittleEndian.PutUint32(dos[0x3c:], 64)
	b.Write(dos)
	b.Write([]byte{'P', 'E', 0, 0})
	coff := make([]byte, peCoffHeaderLen)
	stdbin.LittleEndian.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	stdbin.LittleEndian.PutUint16(coff[2:], nsec)
	b.Write(coff)
	for _, sh := range sections {
		b.Write(sh)
	}
	return b.Bytes()
}

func peSection(name string, virtualAddr, rawSize, rawOff uint32) []byte {
	sh := make([]byte, peSectionHeaderLen)
	copy(sh[0:8], name)
	stdbin.LittleEndian.PutUint32(sh[8:], virtualAddr) // VirtualSize
	stdbin.LittleEndian.PutUint32(sh[12:], virtualAddr)
	stdbin.LittleEndian.PutUint32(sh[16:], rawSize) // SizeOfRawData
	stdbin.LittleEndian.PutUint32(sh[20:], rawOff)  // PointerToRawData
	return sh
}

func malformedPEHugeCount() []byte {
	return peTestFile(0xffff) // 65535 section headers, none present
}

func malformedPETableEOF() []byte {
	return peTestFile(64) // 64 section headers, none present
}

func malformedPESectionEOF() []byte {
	var b bytes.Buffer
	b.Write(peTestFile(1, peSection(".rdata", 0, math.MaxUint32, 64)))
	b.Write([]byte("KERNEL32.dll\x00"))
	return b.Bytes()
}

func malformedPEOverlap() []byte {
	var b bytes.Buffer
	b.Write(peTestFile(2,
		peSection(".rdata", 0x1000, 64, 96),
		peSection(".rodata", 0x2000, 64, 100), // overlaps .rdata
	))
	b.Write(make([]byte, 128))
	return b.Bytes()
}

func TestInspectRejectsMalformedELF(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"forged section count", malformedELFHugeShnum()},
		{"forged section count elf32", malformedELF32HugeCount()},
		{"forged section count big endian", malformedELFBigEndian()},
		{"section table past EOF", malformedELFTableEOF()},
		{"overlapping sections", malformedELFOverlap()},
		{"section past EOF", malformedELFSectionEOF()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trackingReader{data: tc.data, maxEnd: int64(len(tc.data))}
			obj, err := InspectReader(tr, int64(len(tc.data)))
			if !errors.Is(err, ErrInvalidObject) {
				t.Fatalf("err = %v, want ErrInvalidObject; obj = %+v", err, obj)
			}
			if tr.maxEnd > int64(len(tc.data)) {
				t.Fatalf("read %d bytes past declared size %d", tr.maxEnd, len(tc.data))
			}
		})
	}
}

func TestInspectRejectsMalformedPE(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"forged section count", malformedPEHugeCount()},
		{"section table past EOF", malformedPETableEOF()},
		{"section past EOF", malformedPESectionEOF()},
		{"overlapping sections", malformedPEOverlap()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trackingReader{data: tc.data, maxEnd: int64(len(tc.data))}
			obj, err := InspectReader(tr, int64(len(tc.data)))
			if !errors.Is(err, ErrInvalidObject) {
				t.Fatalf("err = %v, want ErrInvalidObject; obj = %+v", err, obj)
			}
			if tr.maxEnd > int64(len(tc.data)) {
				t.Fatalf("read %d bytes past declared size %d", tr.maxEnd, len(tc.data))
			}
		})
	}
}

func TestMalformedELFDoesNotLeakHints(t *testing.T) {
	// The overlapping sample embeds strings that the old code would have
	// reported as a producer and a statically-linked OpenSSL banner.
	data := malformedELFOverlap()
	if _, err := InspectReader(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("overlapping ELF sections were accepted")
	}
}

func TestPreflightPEAcceptsHeaderOnlyStub(t *testing.T) {
	// A PE with a valid signature but zero sections (some packed or stub
	// binaries) must still be recognized rather than treated as malformed.
	data := peTestFile(0)
	if err := preflightPE(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("zero-section PE rejected: %v", err)
	}
}

func TestPreflightELFWithoutSectionTable(t *testing.T) {
	// shoff == 0 is legal for objects described solely by program headers.
	h := elf64TestHeader() // leaves e_shoff at zero
	if err := preflightELF(bytes.NewReader(h), int64(len(h))); err != nil {
		t.Fatalf("section-table-less ELF rejected: %v", err)
	}
}

func TestPreflightELFRejectsBadClass(t *testing.T) {
	h := elf64TestHeader()
	h[elf.EI_CLASS] = 9 // neither ELFCLASS32 nor ELFCLASS64
	if err := preflightELF(bytes.NewReader(h), int64(len(h))); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("err = %v, want ErrInvalidObject", err)
	}
}

func TestPreflightELFRejectsBadEntrySize(t *testing.T) {
	h := elf64TestHeader()
	stdbin.LittleEndian.PutUint64(h[40:], 64)
	stdbin.LittleEndian.PutUint16(h[58:], 32) // smaller than the 64-byte entry
	stdbin.LittleEndian.PutUint16(h[60:], 1)
	if err := preflightELF(bytes.NewReader(h), int64(len(h))); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("err = %v, want ErrInvalidObject", err)
	}
}

func TestPreflightELFRejectsZeroExtendedCount(t *testing.T) {
	// shnum == 0 with a section table means the real count must come from
	// section 0's sh_size; a zero there is invalid.
	h := elf64TestHeader()
	stdbin.LittleEndian.PutUint64(h[40:], 64)
	stdbin.LittleEndian.PutUint16(h[60:], 0) // extended-count form
	var b bytes.Buffer
	b.Write(h)
	ent0 := elf64Section(0, elf.SHT_NULL, 0, 0) // sh_size == 0
	b.Write(ent0)
	if err := preflightELF(bytes.NewReader(b.Bytes()), int64(b.Len())); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("err = %v, want ErrInvalidObject", err)
	}
}

func TestValidateELFRejectsOffsetOverflow(t *testing.T) {
	f := &elf.File{
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{
				Name: ".rodata", Type: elf.SHT_PROGBITS,
				Offset: math.MaxUint64 - 4, FileSize: 16,
			}},
		},
	}
	if err := validateELF(f, 1024); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("err = %v, want ErrInvalidObject", err)
	}
}

func TestValidatePERejectsHeaderTableMismatch(t *testing.T) {
	f := &pe.File{
		FileHeader: pe.FileHeader{NumberOfSections: 3},
		Sections:   []*pe.Section{{}, {}},
	}
	if err := validatePE(f, 1024); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("err = %v, want ErrInvalidObject", err)
	}
}

func TestPreflightPERejectsBadSignatureOffset(t *testing.T) {
	data := make([]byte, 128)
	copy(data[0:2], "MZ")
	stdbin.LittleEndian.PutUint32(data[0x3c:], math.MaxUint32)
	if err := preflightPE(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("err = %v, want ErrInvalidObject", err)
	}
}

func TestValidateELFAllowsNobits(t *testing.T) {
	// SHT_NOBITS sections have no file footprint and must not be treated
	// as out-of-bounds regardless of their size.
	f := &elf.File{
		Sections: []*elf.Section{
			{SectionHeader: elf.SectionHeader{Type: elf.SHT_NOBITS, Size: 1 << 30}},
			{SectionHeader: elf.SectionHeader{
				Name: ".rodata", Type: elf.SHT_PROGBITS, Offset: 0, FileSize: 4,
			}},
		},
	}
	if err := validateELF(f, 16); err != nil {
		t.Fatalf("validateELF rejected SHT_NOBITS: %v", err)
	}
}

func TestValidatePEAllowsUninitializedSection(t *testing.T) {
	// A .bss-like PE section with PointerToRawData == 0 occupies no file.
	f := &pe.File{
		FileHeader: pe.FileHeader{NumberOfSections: 2},
		Sections: []*pe.Section{
			{SectionHeader: pe.SectionHeader{Name: ".text", Offset: 0, Size: 8}},
			{SectionHeader: pe.SectionHeader{Name: ".bss", Offset: 0, Size: 4096}},
		},
	}
	if err := validatePE(f, 16); err != nil {
		t.Fatalf("validatePE rejected uninitialized section: %v", err)
	}
}

func TestValidateMachOBoundsAndOverlap(t *testing.T) {
	good := &macho.File{
		Sections: []*macho.Section{
			{SectionHeader: macho.SectionHeader{Name: "__bss", Offset: 0, Size: 1 << 20}},
			{SectionHeader: macho.SectionHeader{Name: "__text", Offset: 0, Size: 8}},
			{SectionHeader: macho.SectionHeader{Name: "__cstring", Offset: 8, Size: 8}},
		},
	}
	if err := validateMachO(good, 16); err != nil {
		t.Fatalf("valid mach-o layout rejected: %v", err)
	}

	pastEOF := &macho.File{
		Sections: []*macho.Section{
			{SectionHeader: macho.SectionHeader{Name: "__text", Offset: 16, Size: 8}},
		},
	}
	if err := validateMachO(pastEOF, 16); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("past-EOF section err = %v, want ErrInvalidObject", err)
	}

	overlap := &macho.File{
		Sections: []*macho.Section{
			{SectionHeader: macho.SectionHeader{Name: "__text", Offset: 16, Size: 12}},
			{SectionHeader: macho.SectionHeader{Name: "__cstring", Offset: 20, Size: 8}},
		},
	}
	if err := validateMachO(overlap, 32); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("overlapping sections err = %v, want ErrInvalidObject", err)
	}

	tooMany := &macho.File{Sections: make([]*macho.Section, maxSectionCount+1)}
	if err := validateMachO(tooMany, 1<<20); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("excessive section count err = %v, want ErrInvalidObject", err)
	}
}

func TestCheckedEndOverflow(t *testing.T) {
	if _, ok := checkedEnd(math.MaxUint64-3, 10); !ok {
		t.Fatal("overflow not detected")
	}
	end, ok := checkedEnd(10, 20)
	if ok || end != 30 {
		t.Fatalf("checkedEnd(10,20) = %d,%v", end, ok)
	}
}

func TestRejectOverlaps(t *testing.T) {
	if err := rejectOverlaps([]sectionSpan{
		{name: "a", start: 0, end: 10},
		{name: "b", start: 10, end: 20}, // adjacent, not overlapping
	}, "elf"); err != nil {
		t.Fatalf("adjacent spans rejected: %v", err)
	}
	if err := rejectOverlaps([]sectionSpan{
		{name: "a", start: 0, end: 10},
		{name: "b", start: 9, end: 20},
	}, "elf"); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("overlapping spans err = %v, want ErrInvalidObject", err)
	}
}
