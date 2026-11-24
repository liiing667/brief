package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/git-pkgs/brief"
)

func TestSafeTextReversibility(t *testing.T) {
	values := []string{
		"", "plain ascii", "Björk 北京 — naïve café",
		"tab\there", "newline\nbreak", "cr\rdone", "nul" + string(rune(0)) + "byte",
		"ansi\x1b[31mred\x1b[0m", "osc\x1b]0;title\x07end",
		"bidi\u202esecret\u2028line\u2029para\u202ezwsp\u200b\u2066\u2069",
		"nbsp\u00a0and\u00a0spaces", "back\\slash", "del\x7fbyte", "c1" + string(rune(0x85)) + "control",
		"emoji 😀 🎉", "mixed\x1b\\\u202e\n\tend",
	}
	for _, v := range values {
		for _, enc := range []struct {
			name string
			fn   func(string) string
		}{
			{"safeText", safeText},
			{"safeMultiline", safeMultiline},
			{"markdownSafeText", markdownSafeText},
		} {
			encoded := enc.fn(v)
			if strings.ContainsAny(encoded, "\x00\x07\x0a\x0d\x1b\x7f\u202e\u200b") && enc.name != "safeMultiline" {
				t.Errorf("%s(%q) = %q contains a raw unsafe rune", enc.name, v, encoded)
			}
			var decoded string
			if enc.name == "markdownSafeText" {
				decoded = decodeMarkdownText(encoded)
			} else {
				decoded = decodeText(encoded)
			}
			if decoded != v {
				t.Errorf("%s round trip for %q: got %q", enc.name, v, decoded)
			}
		}
	}
}

func TestSafeTextPreservesOrdinaryUnicode(t *testing.T) {
	for _, v := range []string{"Björk", "北京", "naïve café", "Συστήματα", "🎉 release"} {
		if got := safeText(v); got != v {
			t.Errorf("safeText altered ordinary Unicode %q into %q", v, got)
		}
		if got := markdownSafeText(v); got != v {
			t.Errorf("markdownSafeText altered ordinary Unicode %q into %q", v, got)
		}
	}
}

func TestMarkdownCodeRoundTrip(t *testing.T) {
	cases := []string{
		"plain", "tab\there", "emoji 😀", `back\slash`, `a\\b`,
		"& < > | # ` * _ [ ]",
		"https://example.com/a) [evil](https://x.test)",
		"supplementary \U0001F600 end",
	}
	for _, c := range cases {
		code := markdownCode(c)
		if !strings.HasPrefix(code, "`") || !strings.HasSuffix(code, "`") {
			t.Fatalf("markdownCode(%q) missing span delimiters: %q", c, code)
		}
		if strings.Contains(code, "\t") || strings.Contains(code, "\x1b") {
			t.Errorf("markdownCode(%q) leaves a raw control character: %q", c, code)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(code, "`"), "`")
		if got := decodeMarkdownText(inner); got != c {
			t.Errorf("markdownCode round trip for %q: got %q", c, got)
		}
	}
}

func TestLinkTargetCannotBreakOutOfMarkdownLink(t *testing.T) {
	urls := []string{
		"https://example.com/a b",
		"https://example.com/x) [evil](https://attacker.test)",
		"https://example.com/\n[forged](javascript:alert(1))",
		"https://example.com/(path)\t\x1b]0;x\x07",
	}
	for _, u := range urls {
		target := linkTarget(u)
		for _, raw := range []string{" ", "(", ")", "\n", "\t", "\x1b", "\x07"} {
			if strings.Contains(target, raw) {
				t.Errorf("linkTarget(%q) = %q still contains raw %q", u, target, raw)
			}
		}
		if strings.Contains(target, "][") || strings.Contains(target, "](") {
			t.Errorf("linkTarget(%q) = %q allows link injection", u, target)
		}
		rendered := "[docs](" + target + ")"
		if strings.Count(rendered, "](") != 1 {
			t.Errorf("rendered link %q has an unexpected number of link separators", rendered)
		}
	}
	// Ordinary URLs keep their shape.
	if got := linkTarget("https://golangci-lint.run/usage/"); got != "https://golangci-lint.run/usage/" {
		t.Errorf("ordinary URL altered: %q", got)
	}
}

func TestMarkdownReportRendersAllMetadataSafely(t *testing.T) {
	evil := "x\x1b[31m\n## forged\u202e| [click](javascript:alert(1))<script>"
	r := &brief.Report{
		Version: "dev", Path: "/tmp/test",
		Languages:       []brief.Detection{{Name: evil, Category: "language", Confidence: "high"}},
		PackageManagers: []brief.Detection{{Name: evil, Command: &brief.Command{Run: evil}, Lockfile: evil}},
		Scripts:         []brief.Script{{Name: evil, Run: evil, Source: evil}},
		Tools: map[string][]brief.Detection{"lint": {{
			Name: evil, Command: &brief.Command{Run: evil}, ConfigFiles: []string{evil},
			Homepage: "https://example.com/a) [x](https://evil.test)", Docs: "https://example.com/\nx",
		}}},
		Resources: &brief.ResourceInfo{Readme: evil, Community: map[string]string{"c": evil}},
		Git: &brief.GitInfo{
			Branch: evil, DefaultBranch: evil,
			Remotes: map[string]string{"origin": "git@example.com:org/repo.git " + evil},
		},
		Skills: []brief.Skill{{Name: evil, Description: evil, Path: evil, Format: "claude"}},
	}
	var md, human bytes.Buffer
	Markdown(&md, r, true)
	Human(&human, r, true)
	for name, out := range map[string]string{"markdown": md.String(), "human": human.String()} {
		for _, unwanted := range []string{"\x1b", "\u202e"} {
			if strings.Contains(out, unwanted) {
				t.Errorf("%s output contains unsafe token %q:\n%s", name, unwanted, out)
			}
		}
	}
	for _, unwanted := range []string{"<script>", "## forged", "[click](javascript:alert(1))"} {
		if strings.Contains(md.String(), unwanted) {
			t.Errorf("markdown output contains active markup %q:\n%s", unwanted, md.String())
		}
	}
	if strings.Contains(md.String(), "[x](https://evil.test)") {
		t.Errorf("markdown link injection succeeded:\n%s", md.String())
	}
	// The safe representation must be recoverable from the Markdown output.
	if !strings.Contains(decodeMarkdownText(md.String()), "[click]") {
		t.Errorf("markdown evidence is not reversible:\n%s", md.String())
	}
	if !strings.Contains(decodeText(human.String()), "## forged") {
		t.Errorf("human evidence is not reversible:\n%s", human.String())
	}
}

func TestCitationAndBibTeXShareSafeRepresentation(t *testing.T) {
	evil := "title\x1b\n\u202e [x](javascript:alert(1))"
	r := &brief.Report{Resources: &brief.ResourceInfo{
		Citation: &brief.CitationInfo{Path: "CITATION.cff", ParseStatus: "parsed", Title: evil},
		BibTeX: &brief.BibTeXInfo{
			Path: "CITATION.bib", ParseStatus: "parsed",
			Entries: []brief.BibTeXEntry{{Type: "misc", Key: "k", Title: evil,
				Authors: []brief.CitationAuthor{{Name: "Björk 北京"}}}},
		},
	}}
	var md, human bytes.Buffer
	Markdown(&md, r, true)
	Human(&human, r, true)
	for name, out := range map[string]string{"markdown": md.String(), "human": human.String()} {
		for _, unwanted := range []string{"\x1b", "\u202e"} {
			if strings.Contains(out, unwanted) {
				t.Errorf("%s output contains unsafe token %q:\n%s", name, unwanted, out)
			}
		}
		if !strings.Contains(out, "Björk 北京") {
			t.Errorf("%s output lost ordinary Unicode author name:\n%s", name, out)
		}
	}
	// Both consumers encode the same JSON value the same way.
	if !strings.Contains(decodeMarkdownText(md.String()), evil) {
		t.Errorf("markdown citation value not reversible:\n%s", md.String())
	}
	if !strings.Contains(decodeText(human.String()), evil) {
		t.Errorf("human citation value not reversible:\n%s", human.String())
	}
}

func TestSharedRepresentationAcrossConsumers(t *testing.T) {
	evil := "Name\x1b[31m\nrow\u202e|break"
	r := &brief.Report{Resources: &brief.ResourceInfo{Citation: &brief.CitationInfo{
		Path: "CITATION.cff", ParseStatus: "parsed", Title: evil, Version: "1.2.3",
		Authors: []brief.CitationAuthor{{Name: "Ada"}},
	}}}
	var h, m bytes.Buffer
	Human(&h, r, false)
	Markdown(&m, r, false)
	// Control and bidi characters use the identical escape sequences in
	// every public report consumer.
	for _, token := range []string{`\u001b`, `\u000a`, `\u202e`} {
		if !strings.Contains(h.String(), token) {
			t.Errorf("human output missing shared token %q:\n%s", token, h.String())
		}
		if !strings.Contains(m.String(), token) {
			t.Errorf("markdown output missing shared token %q:\n%s", token, m.String())
		}
	}
	hi := strings.Index(h.String(), "Citation:")
	ha := strings.Index(h.String(), "Authors:")
	hr := strings.Index(h.String(), "Release:")
	if !(hi >= 0 && ha > hi && hr > ha) {
		t.Errorf("human field order changed: %d %d %d", hi, ha, hr)
	}
	mi := strings.Index(m.String(), "- Citation:")
	ma := strings.Index(m.String(), "- Authors:")
	mr := strings.Index(m.String(), "- Release:")
	if !(mi >= 0 && ma > mi && mr > ma) {
		t.Errorf("markdown field order changed: %d %d %d", mi, ma, mr)
	}
}
