package report

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Repo-controlled metadata (package names, URLs, citation fields, paths,
// git remotes, ...) can contain terminal control characters, Unicode
// bidi/zero-width marks, and structural separators. The human, Markdown and
// BibTeX summaries all render the same JSON values, so they share one safe
// representation instead of each dropping or mangling characters on its own.
//
// The representation is reversible: safeText turns every rune that could
// disrupt an output channel into a \uXXXX (or \UXXXXXXXX for supplementary
// planes) escape, leaving ordinary printable Unicode, including non-ASCII
// names such as "Björk" or "北京", byte-for-byte untouched. decodeText
// recovers the original value, which keeps textual evidence consistent with
// the JSON report.

const escapeRune = '\\'

// markdownEscapes quotes the Markdown structure characters that
// repo-controlled values could otherwise use to forge headings, links,
// emphasis, tables or HTML.
var markdownEscapes = strings.NewReplacer(
	"\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
	"<", "&lt;", ">", "&gt;", "&", "&amp;", "|", "\\|", "#", "\\#",
)

// safeText renders s as a single line of safe text. Control characters,
// Unicode format marks (bidi controls, zero-width spaces, ...), and
// line-breaking or non-printable whitespace are encoded as \uXXXX escapes
// rather than dropped, so the result is reversible and contains no raw
// control byte. Printable Unicode and ordinary spaces are preserved.
func safeText(s string) string {
	return encodeSafe(s, true)
}

// safeMultiline keeps newline and tab characters usable while still encoding
// every other control/format rune. It is used for the terminal report where
// intentional line structure is part of the output.
func safeMultiline(s string) string {
	return encodeSafe(s, false)
}

func encodeSafe(s string, singleLine bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			if singleLine {
				writeUnicodeEscape(&b, r)
			} else {
				b.WriteRune(r)
			}
		case r == escapeRune:
			b.WriteString(`\u005c`)
		case isEncodedRune(r):
			writeUnicodeEscape(&b, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isEncodedRune reports whether r must be escaped in a safe text value:
// C0/C1 control characters, Unicode format (Cf) marks such as bidi controls
// and zero-width spaces, and whitespace other than the ordinary space (tabs,
// newlines, line/paragraph separators, NBSP, ...).
func isEncodedRune(r rune) bool {
	if r == ' ' {
		return false
	}
	if r < ' ' || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	if unicode.IsSpace(r) {
		return true
	}
	return false
}

func writeUnicodeEscape(b *strings.Builder, r rune) {
	if r <= 0xffff {
		b.WriteString(`\u`)
		for shift := 12; shift >= 0; shift -= 4 {
			b.WriteByte(hexDigits[byte(r>>shift)&0xf])
		}
		return
	}
	b.WriteString(`\U`)
	for shift := 28; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[byte(r>>shift)&0xf])
	}
}

const hexDigits = "0123456789abcdef"

// decodeText reverses safeText/safeMultiline, recovering the original
// repo-controlled value. Unknown backslash sequences are returned verbatim
// so decoding never fails or loses data.
func decodeText(s string) string {
	if !strings.ContainsRune(s, escapeRune) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r != escapeRune {
			b.WriteRune(r)
			i += size
			continue
		}
		if i+6 <= len(s) && s[i+1] == 'u' {
			if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil && utf8.ValidRune(rune(v)) {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
		}
		if i+10 <= len(s) && s[i+1] == 'U' {
			if v, err := strconv.ParseUint(s[i+2:i+10], 16, 32); err == nil && utf8.ValidRune(rune(v)) {
				b.WriteRune(rune(v))
				i += 10
				continue
			}
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// markdownSafeText makes a repo-controlled value inert in Markdown prose,
// lists and table cells. Markdown structure characters are quoted first;
// encodeSafe then only escapes the leading backslash of each quote (and all
// control/format runes), so the \uXXXX escapes themselves are never
// re-quoted. decodeMarkdownText recovers the original value.
func markdownSafeText(s string) string {
	return safeText(markdownEscapes.Replace(s))
}

// markdownUnescapes reverses markdownEscapes, including the HTML entities.
var markdownUnescapes = strings.NewReplacer(
	"\\`", "`", "\\*", "*", "\\_", "_", "\\[", "[", "\\]", "]",
	"\\|", "|", "\\#", "#", "\\\\", "\\",
	"&lt;", "<", "&gt;", ">", "&amp;", "&",
)

// decodeMarkdownText recovers the original repo-controlled value from a
// rendered Markdown field.
func decodeMarkdownText(s string) string {
	return markdownUnescapes.Replace(decodeText(s))
}

// markdownCode renders a repo-controlled value for an inline code span.
// Structure characters are quoted in addition to the shared safe
// representation, so a value cannot terminate the span or inject active
// Markdown/HTML even in renderers that interpret code-span contents.
func markdownCode(s string) string {
	return "`" + safeText(markdownEscapes.Replace(s)) + "`"
}

// linkTarget renders a repo-controlled URL for an inline Markdown link.
// Parentheses and whitespace would terminate or extend the link target, so
// they are percent-encoded; everything else first goes through the shared
// safe representation. decodeText followed by URL-unquoting recovers the
// original URL.
func linkTarget(s string) string {
	s = safeText(s)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldPercentEncode(c) {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func shouldPercentEncode(c byte) bool {
	switch c {
	case ' ', '(', ')', '<', '>', '"', '`', '\\', '^', '{', '}', 0x7f:
		return true
	}
	return c < 0x20
}
