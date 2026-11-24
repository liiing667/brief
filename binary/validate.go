package binary

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"sort"
)

// ErrInvalidObject is returned when a native object's internal metadata
// (section tables, offsets, or sizes) cannot be trusted. The container
// magic may still identify the file format, but the claims made inside the
// object are not safe to report.
var ErrInvalidObject = errors.New("invalid native object metadata")

// maxSectionCount bounds the number of section/segment descriptors a single
// object may carry. Real-world toolchains emit at most a few hundred; a count
// at this scale is only reachable through forged headers and would otherwise
// let a tiny sample drive large allocations and scans.
const maxSectionCount = 4096

// sectionSpan is a [start, end) byte range inside the declared file.
type sectionSpan struct {
	name  string
	start uint64
	end   uint64
}

// validateELF verifies the ELF section table before any section content is
// turned into reported metadata. debug/elf only performs basic parsing and is
// explicitly not hardened against adversarial input, so untrusted objects get
// an explicit bounds and identity check here.
func validateELF(f *elf.File, size int64) error {
	if len(f.Sections) > maxSectionCount {
		return fmt.Errorf("%w: elf claims %d sections", ErrInvalidObject, len(f.Sections))
	}

	spans := make([]sectionSpan, 0, len(f.Sections))
	for i, s := range f.Sections {
		// SHT_NOBITS sections (.bss and friends) occupy no file space;
		// their size describes memory only.
		// A zero offset likewise means the section has no file footprint,
		// which ordinary linkers use for BSS-like sections.
		if s.Type == elf.SHT_NOBITS || s.Offset == 0 {
			continue
		}
		end, overflow := checkedEnd(s.Offset, s.FileSize)
		if overflow || end > uint64(size) {
			return fmt.Errorf("%w: elf section %d (%s) extends past file: off=%#x size=%#x file=%d",
				ErrInvalidObject, i, sectionName(s.Name), s.Offset, s.FileSize, size)
		}
		spans = append(spans, sectionSpan{name: sectionName(s.Name), start: s.Offset, end: end})
	}
	return rejectOverlaps(spans, "elf")
}

// validatePE verifies the PE/COFF section table before the import directory or
// section data is trusted. debug/pe performs no bounds checking of section
// offsets and sizes against the actual file.
func validatePE(f *pe.File, size int64) error {
	if int(f.FileHeader.NumberOfSections) != len(f.Sections) {
		return fmt.Errorf("%w: pe header claims %d sections but table holds %d",
			ErrInvalidObject, f.FileHeader.NumberOfSections, len(f.Sections))
	}
	if len(f.Sections) > maxSectionCount {
		return fmt.Errorf("%w: pe claims %d sections", ErrInvalidObject, len(f.Sections))
	}

	spans := make([]sectionSpan, 0, len(f.Sections))
	for i, s := range f.Sections {
		// Sections with no raw data (.bss) have no file footprint.
		if s.Offset == 0 {
			continue
		}
		end, overflow := checkedEnd(uint64(s.Offset), uint64(s.Size))
		if overflow || end > uint64(size) {
			return fmt.Errorf("%w: pe section %d (%s) extends past file: off=%#x size=%#x file=%d",
				ErrInvalidObject, i, sectionName(s.Name), s.Offset, s.Size, size)
		}
		spans = append(spans, sectionSpan{name: sectionName(s.Name), start: uint64(s.Offset), end: end})
	}
	return rejectOverlaps(spans, "pe")
}

// validateMachO applies the same in-file bounds check to Mach-O sections.
// The fat-container wrapper already rejects out-of-bounds or table-overlapping
// slices; this covers the sections within each slice.
func validateMachO(f *macho.File, size int64) error {
	if len(f.Sections) > maxSectionCount {
		return fmt.Errorf("%w: mach-o claims %d sections", ErrInvalidObject, len(f.Sections))
	}

	spans := make([]sectionSpan, 0, len(f.Sections))
	for i, s := range f.Sections {
		// Mach-O BSS sections carry no file data and use Offset == 0.
		if s.Offset == 0 {
			continue
		}
		end, overflow := checkedEnd(uint64(s.Offset), s.Size)
		if overflow || end > uint64(size) {
			return fmt.Errorf("%w: mach-o section %d (%s) extends past slice: off=%#x size=%#x slice=%d",
				ErrInvalidObject, i, sectionName(s.Name), uint64(s.Offset), s.Size, size)
		}
		spans = append(spans, sectionSpan{name: sectionName(s.Name), start: uint64(s.Offset), end: end})
	}
	return rejectOverlaps(spans, "mach-o")
}

// checkedEnd returns start+length and reports an overflow.
func checkedEnd(start, length uint64) (uint64, bool) {
	if length > ^uint64(0)-start {
		return 0, true
	}
	return start + length, false
}

// rejectOverlaps rejects two in-file sections that claim overlapping byte
// ranges. Sections produced by ordinary linkers are disjoint; overlap lets a
// forged region back multiple identities (for example a .comment producer
// string and a .rodata static-link banner) at once.
func rejectOverlaps(spans []sectionSpan, format string) error {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})
	for i := 1; i < len(spans); i++ {
		prev, cur := spans[i-1], spans[i]
		if cur.start < prev.end {
			return fmt.Errorf("%w: %s sections %s and %s overlap at %#x",
				ErrInvalidObject, format, sectionName(prev.name), sectionName(cur.name), cur.start)
		}
	}
	return nil
}

func sectionName(name string) string {
	if name == "" {
		return "<unnamed>"
	}
	return name
}
