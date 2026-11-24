package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/git-pkgs/brief"
)

const citationAuthorLimit = 3

type citationRow struct{ label, value string }

func printCitation(w io.Writer, info *brief.CitationInfo, verbose bool) {
	for _, row := range citationRows(info, verbose) {
		_, _ = fmt.Fprintf(w, "%-12s %s\n", row.label+":", safeText(row.value))
	}
}

func mdCitation(w io.Writer, info *brief.CitationInfo, verbose bool) {
	rows := citationRows(info, verbose)
	if len(rows) == 0 {
		return
	}
	_, _ = fmt.Fprint(w, "\n**Citation:**\n\n")
	for _, row := range rows {
		_, _ = fmt.Fprintf(w, "- %s: %s\n", row.label, markdownSafeText(row.value))
	}
}

func citationRows(info *brief.CitationInfo, verbose bool) []citationRow {
	if info == nil {
		return nil
	}
	var rows []citationRow
	add := func(label, value string) {
		if value != "" {
			rows = append(rows, citationRow{label, boundedText(value)})
		}
	}
	title := info.Title
	if title == "" {
		title = info.Path
	}
	add("Citation", title)
	add("Authors", citationAuthorSummary(info.Authors))
	add("Release", strings.TrimSpace(info.Version+" "+info.DateReleased))
	add("DOI", info.DOI)
	for _, id := range info.Identifiers[:min(len(info.Identifiers), maxDisplayItems)] {
		add("Identifier", strings.TrimSpace(id.Type+" "+id.Value+" "+id.Description))
	}
	if ref := info.PreferredCitation; ref != nil {
		add("Cite", ref.Title)
		add("Preferred DOI", ref.DOI)
		if verbose {
			add("Cite authors", citationAuthorSummary(ref.Authors))
			add("Publication", strings.TrimSpace(ref.Journal+" "+ref.Year+" "+ref.DatePublished))
			add("Cite URL", ref.URL)
		}
	}
	if info.ParseStatus == "parsed" {
		add("CFF", strings.TrimSpace(info.CFFVersion+" "+info.ValidationStatus))
	} else {
		add("CFF", info.ParseStatus)
	}
	for _, issue := range info.Diagnostics[:min(len(info.Diagnostics), citationAuthorLimit)] {
		location := diagnosticLocation(info.Path, issue.Path, issue.Line, issue.Column)
		add("CFF issue", strings.TrimSpace(location+" "+issue.Code+": "+issue.Message))
	}
	if verbose {
		rows = append(rows, citationDetailRows(info)...)
	}
	return rows
}

func citationDetailRows(info *brief.CitationInfo) []citationRow {
	rows := []citationRow{
		{"Type", info.Type}, {"URL", info.URL}, {"Repository", info.Repository},
		{"Source code", info.RepositoryCode}, {"Artifact", info.RepositoryArtifact},
		{"Licenses", strings.Join(info.Licenses, ", ")}, {"Keywords", strings.Join(info.Keywords, ", ")},
		{"Abstract", info.Abstract}, {"Instructions", info.Message},
	}
	for _, author := range info.Authors[:min(len(info.Authors), maxDisplayItems)] {
		if author.Affiliation != "" || author.ORCID != "" {
			rows = append(rows, citationRow{"Author details", strings.TrimSpace(citationAuthorName(author) + " " + author.Affiliation + " " + author.ORCID)})
		}
	}
	var out []citationRow
	for _, row := range rows {
		if row.value != "" {
			out = append(out, citationRow{row.label, boundedText(row.value)})
		}
	}
	return out
}

func citationAuthorSummary(authors []brief.CitationAuthor) string {
	var names []string
	for _, author := range authors[:min(len(authors), citationAuthorLimit)] {
		if name := citationAuthorName(author); name != "" {
			names = append(names, name)
		}
	}
	if len(authors) > citationAuthorLimit {
		names = append(names, fmt.Sprintf("and %d more", len(authors)-citationAuthorLimit))
	}
	return strings.Join(names, ", ")
}

func citationAuthorName(author brief.CitationAuthor) string {
	if author.Name != "" {
		return author.Name
	}
	var parts []string
	for _, part := range []string{author.GivenNames, author.NameParticle, author.FamilyNames, author.NameSuffix} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, " ")
}

// boundedText caps long repo-controlled values while keeping the value
// intact and reversible: the continuation marker is itself a \uXXXX escape
// of the horizontal ellipsis, so decodeText can locate and remove it before
// recovering the original characters.
func boundedText(value string) string {
	const maxRunes = 300
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes]) + truncationMarker
	}
	return value
}

const truncationMarker = `\u2026`
