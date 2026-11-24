package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/git-pkgs/brief"
)

// Markdown writes the report in markdown format.
func Markdown(w io.Writer, r *brief.Report, verbose bool) {
	_, _ = fmt.Fprintf(w, "# brief %s — %s\n\n", markdownSafeText(r.Version), markdownSafeText(r.Path))

	if r.DiffRef != "" {
		_, _ = fmt.Fprintf(w, "diff %s (%d files changed)\n\n", markdownSafeText(r.DiffRef), len(r.ChangedFiles))
	}

	mdSafeTruncatedList(w, "Commits", r.DiffCommits)
	mdSafeTruncatedList(w, "Changed", r.ChangedFiles)
	mdLanguages(w, r.Languages)
	mdPackageManagers(w, r.PackageManagers)
	mdDependencySummary(w, r.Dependencies)
	mdScripts(w, r.Scripts)
	mdTools(w, r.Tools, verbose)
	mdStyle(w, r.Style)
	mdLayout(w, r.Layout)
	mdPlatforms(w, r.Platforms)
	mdResources(w, r.Resources)
	if r.Resources != nil {
		mdCitation(w, r.Resources.Citation, verbose)
		mdCodemeta(w, r.Resources.Codemeta, verbose)
		mdBibTeX(w, r.Resources.BibTeX, verbose)
		mdBibTeX(w, r.Resources.ReadmeBibTeX, verbose)
	}
	mdSkills(w, r.Skills)
	mdGit(w, r.Git)
	mdLines(w, r.Lines)
	mdEnrichment(w, r.Enrichment)

	_, _ = fmt.Fprintf(w, "---\n\n%.1fms | %d files checked | %d/%d tools matched%s\n",
		r.Stats.DurationMS, r.Stats.FilesChecked, r.Stats.ToolsMatched, r.Stats.ToolsChecked, scanStatus(r.Stats, " | "))
}

func mdTruncatedList(w io.Writer, header string, items []string) {
	if len(items) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "**%s:**\n\n", header)
	limit := min(len(items), maxDisplayItems)
	for _, item := range items[:limit] {
		_, _ = fmt.Fprintf(w, "- %s\n", item)
	}
	if len(items) > maxDisplayItems {
		_, _ = fmt.Fprintf(w, "- ... and %d more\n", len(items)-maxDisplayItems)
	}
	_, _ = fmt.Fprintln(w)
}

// mdSafeTruncatedList renders repo-controlled items through the shared safe
// representation before handing them to mdTruncatedList.
func mdSafeTruncatedList(w io.Writer, header string, items []string) {
	if len(items) == 0 {
		return
	}
	safe := make([]string, len(items))
	for i, item := range items {
		safe[i] = markdownSafeText(item)
	}
	mdTruncatedList(w, header, safe)
}

func mdLanguages(w io.Writer, languages []brief.Detection) {
	if len(languages) == 0 {
		return
	}
	names := detectionNames(languages)
	if len(names) == 1 {
		_, _ = fmt.Fprintf(w, "**Language:** %s\n", markdownSafeText(names[0]))
	} else {
		_, _ = fmt.Fprintf(w, "**Language:** %s (also: %s)\n", markdownSafeText(names[0]), markdownSafeText(strings.Join(names[1:], ", ")))
	}
}

func mdPackageManagers(w io.Writer, managers []brief.Detection) {
	for _, pm := range managers {
		line := markdownSafeText(pm.Name)
		if pm.Command != nil {
			line += " (" + markdownCode(pm.Command.Run) + ")"
		}
		_, _ = fmt.Fprintf(w, "**Package Manager:** %s\n", line)
		if pm.Lockfile != "" {
			_, _ = fmt.Fprintf(w, "Lockfile: %s\n", markdownSafeText(pm.Lockfile))
		}
	}
}

func mdDependencySummary(w io.Writer, deps []brief.DepInfo) {
	if s := depSummary(deps); s != "" {
		_, _ = fmt.Fprintf(w, "Dependencies: %s\n", s)
	}
}

func mdScripts(w io.Writer, scripts []brief.Script) {
	if len(scripts) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w)
	source := scripts[0].Source
	_, _ = fmt.Fprintf(w, "## Scripts (%s)\n\n", markdownSafeText(source))
	_, _ = fmt.Fprintln(w, "| Name | Command |")
	_, _ = fmt.Fprintln(w, "|------|---------|")
	for _, s := range scripts {
		if s.Source != source {
			_, _ = fmt.Fprintf(w, "\n## Scripts (%s)\n\n", markdownSafeText(s.Source))
			_, _ = fmt.Fprintln(w, "| Name | Command |")
			_, _ = fmt.Fprintln(w, "|------|---------|")
			source = s.Source
		}
		_, _ = fmt.Fprintf(w, "| %s | %s |\n", markdownSafeText(s.Name), markdownCode(s.Run))
	}
	_, _ = fmt.Fprintln(w)
}

func mdTools(w io.Writer, tools map[string][]brief.Detection, verbose bool) {
	if !hasAnyTools(tools) {
		return
	}

	_, _ = fmt.Fprintf(w, "\n## Tools\n\n")
	_, _ = fmt.Fprintln(w, "| Category | Tool | Command | Config |")
	_, _ = fmt.Fprintln(w, "|----------|------|---------|--------|")

	for _, cat := range CategoryOrder {
		label := CategoryLabels[cat]
		if label == "" {
			label = cat
		}
		dets, ok := tools[cat]
		if !ok {
			continue
		}
		mdToolRows(w, label, dets)
	}

	// Print any categories not in the fixed order
	for cat, dets := range tools {
		if CategoryLabels[cat] != "" {
			continue
		}
		mdToolRows(w, cat, dets)
	}

	if verbose {
		mdToolLinks(w, tools)
	}

	_, _ = fmt.Fprintln(w)
}

func hasAnyTools(tools map[string][]brief.Detection) bool {
	for _, dets := range tools {
		if len(dets) > 0 {
			return true
		}
	}
	return false
}

func mdToolRows(w io.Writer, label string, dets []brief.Detection) {
	for _, t := range dets {
		cmd := ""
		if t.Command != nil {
			cmd = markdownCode(t.Command.Run)
		}
		config := ""
		if len(t.ConfigFiles) > 0 {
			config = markdownSafeText(strings.Join(t.ConfigFiles, ", "))
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |\n", markdownSafeText(label), markdownSafeText(t.Name), cmd, config)
	}
}

func mdToolLinks(w io.Writer, tools map[string][]brief.Detection) {
	_, _ = fmt.Fprintln(w)
	for _, cat := range CategoryOrder {
		dets, ok := tools[cat]
		if !ok {
			continue
		}
		for _, t := range dets {
			if t.Homepage == "" && t.Docs == "" {
				continue
			}
			_, _ = fmt.Fprintf(w, "**%s:**", markdownSafeText(t.Name))
			if t.Homepage != "" {
				_, _ = fmt.Fprintf(w, " [homepage](%s)", linkTarget(t.Homepage))
			}
			if t.Docs != "" {
				_, _ = fmt.Fprintf(w, " [docs](%s)", linkTarget(t.Docs))
			}
			_, _ = fmt.Fprintln(w)
		}
	}
}

func mdStyle(w io.Writer, style *brief.StyleInfo) {
	if style == nil {
		return
	}
	var parts []string
	if style.Indentation != "" {
		s := style.Indentation
		if style.IndentSource != "" {
			s += " (" + style.IndentSource + ")"
		}
		parts = append(parts, s)
	}
	if style.LineEnding != "" {
		parts = append(parts, style.LineEnding)
	}
	if style.TrailingNewline != nil {
		if *style.TrailingNewline {
			parts = append(parts, "trailing newline")
		} else {
			parts = append(parts, "no trailing newline")
		}
	}
	if len(parts) > 0 {
		_, _ = fmt.Fprintf(w, "**Style:** %s\n", markdownSafeText(strings.Join(parts, " | ")))
	}
}

func mdLayout(w io.Writer, layout *brief.LayoutInfo) {
	if layout == nil {
		return
	}
	var parts []string
	if len(layout.SourceDirs) > 0 {
		parts = append(parts, "source: "+joinDirs(layout.SourceDirs))
	}
	if len(layout.TestDirs) > 0 {
		parts = append(parts, "test: "+joinDirs(layout.TestDirs))
	}
	if len(parts) > 0 {
		_, _ = fmt.Fprintf(w, "**Layout:** %s\n", markdownSafeText(strings.Join(parts, " | ")))
	}
}

func mdPlatforms(w io.Writer, platforms *brief.PlatformInfo) {
	if platforms == nil {
		return
	}
	_, _ = fmt.Fprintln(w)
	for _, name := range sortedKeys(platforms.CIMatrixVersions) {
		_, _ = fmt.Fprintf(w, "**Platforms:** %s %s (CI matrix)\n", name, markdownSafeText(strings.Join(platforms.CIMatrixVersions[name], ", ")))
	}
	for _, file := range sortedKeys(platforms.RuntimeVersionFiles) {
		_, _ = fmt.Fprintf(w, "- %s: %s\n", markdownSafeText(file), markdownSafeText(platforms.RuntimeVersionFiles[file]))
	}
	if len(platforms.CIMatrixOS) > 0 {
		_, _ = fmt.Fprintf(w, "- OS: %s (CI matrix)\n", markdownSafeText(strings.Join(platforms.CIMatrixOS, ", ")))
	}
}

func mdResources(w io.Writer, res *brief.ResourceInfo) {
	if res == nil || res.Empty() {
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "**Resources:**")
	mdResource(w, res.Readme)
	mdResource(w, res.Changelog)
	mdResource(w, res.Roadmap)
	if res.License != "" {
		label := res.License
		if res.LicenseType != "" {
			label += " (" + res.LicenseType + ")"
		}
		_, _ = fmt.Fprintf(w, "- %s\n", markdownSafeText(label))
	}
	mdResourceGroup(w, "Legal", res.Legal)
	mdResourceGroup(w, "Community", res.Community)
	mdResourceGroup(w, "Security", res.Security)
	mdResourceGroup(w, "Metadata", res.Metadata)
	mdResourceGroup(w, "Agents", res.Agents)
	mdTemplates(w, res.Templates)
}

func mdTemplates(w io.Writer, t *brief.TemplateInfo) {
	if t.Empty() {
		return
	}
	_, _ = fmt.Fprintln(w, "- Templates:")
	for _, p := range t.Issue {
		_, _ = fmt.Fprintf(w, "  - issue: %s\n", markdownSafeText(p))
	}
	for _, p := range t.PullRequest {
		_, _ = fmt.Fprintf(w, "  - pull request: %s\n", markdownSafeText(p))
	}
	if t.Config != "" {
		_, _ = fmt.Fprintf(w, "  - config: %s\n", markdownSafeText(t.Config))
	}
}

func mdResource(w io.Writer, path string) {
	if path != "" {
		_, _ = fmt.Fprintf(w, "- %s\n", markdownSafeText(path))
	}
}

func mdResourceGroup(w io.Writer, label string, group map[string]string) {
	if len(group) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "- %s:\n", label)
	for _, k := range sortedKeys(group) {
		_, _ = fmt.Fprintf(w, "  - %s\n", markdownSafeText(group[k]))
	}
}

func mdSkills(w io.Writer, skills []brief.Skill) {
	if len(skills) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "**Skills:**")
	for _, s := range skills {
		line := s.Name
		if s.Description != "" {
			line += " — " + s.Description
		}
		_, _ = fmt.Fprintf(w, "- %s %s\n", markdownSafeText(line), markdownCode(s.Path))
	}
}

func mdGit(w io.Writer, git *brief.GitInfo) {
	if git == nil {
		return
	}
	_, _ = fmt.Fprintln(w)
	if git.Branch != "" {
		_, _ = fmt.Fprintf(w, "**Git:** branch %s", markdownCode(git.Branch))
		if git.DefaultBranch != "" && git.DefaultBranch != git.Branch {
			_, _ = fmt.Fprintf(w, " (default: %s)", markdownCode(git.DefaultBranch))
		}
		if git.CommitCount > 0 {
			_, _ = fmt.Fprintf(w, " — %d commits", git.CommitCount)
		}
		_, _ = fmt.Fprintln(w)
	}
	for _, name := range sortedKeys(git.Remotes) {
		_, _ = fmt.Fprintf(w, "- %s: %s\n", markdownSafeText(name), markdownSafeText(git.Remotes[name]))
	}
}

func mdLines(w io.Writer, lines *brief.LineCount) {
	if lines == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "\n**Lines:** %d code, %d files (%s)\n",
		lines.TotalLines, lines.TotalFiles, markdownSafeText(lines.Source))
}

func mdEnrichment(w io.Writer, e *brief.EnrichmentInfo) {
	if e == nil {
		return
	}
	if e.Repo != nil && e.Repo.Scorecard > 0 {
		_, _ = fmt.Fprintf(w, "\n**Scorecard:** %.1f/10 (%s)\n", e.Repo.Scorecard, markdownSafeText(e.Repo.ScorecardDate))
	}
	if len(e.RuntimeEOL) > 0 {
		_, _ = fmt.Fprintln(w)
		for name, eol := range e.RuntimeEOL {
			_, _ = fmt.Fprintf(w, "**Runtime:** %s\n", markdownSafeText(enrichmentRuntimeLine(name, eol)))
		}
	}
	for _, pkg := range e.Packages {
		_, _ = fmt.Fprintf(w, "\n**Published:** %s (%s)\n", markdownSafeText(pkg.Name), markdownSafeText(pkg.Ecosystem))
		for _, line := range packageDetailLines(pkg) {
			_, _ = fmt.Fprintf(w, "- %s\n", markdownSafeText(line))
		}
	}
}

// MissingMarkdown writes the missing report in markdown format.
func MissingMarkdown(w io.Writer, r *brief.MissingReport) {
	if len(r.Missing) == 0 {
		_, _ = fmt.Fprintln(w, "No missing recommended tooling detected.")
		return
	}

	_, _ = fmt.Fprintf(w, "**Detected:** %s\n\n", markdownSafeText(strings.Join(r.Ecosystems, ", ")))
	_, _ = fmt.Fprintf(w, "## Missing recommended tooling\n\n")
	_, _ = fmt.Fprintln(w, "| Category | Suggested | Command | Docs |")
	_, _ = fmt.Fprintln(w, "|----------|-----------|---------|------|")

	for _, m := range r.Missing {
		suggested := ""
		if m.Suggested != "" {
			suggested = markdownSafeText(m.Suggested)
		}
		cmd := ""
		if m.SuggestedCmd != "" {
			cmd = markdownCode(m.SuggestedCmd)
		}
		docs := ""
		if m.Docs != "" {
			docs = markdownSafeText(m.Docs)
		}
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |\n", markdownSafeText(m.Label), suggested, cmd, docs)
	}
}

// ThreatMarkdown writes the threat report in markdown format.
func ThreatMarkdown(w io.Writer, r *brief.ThreatReport) {
	if len(r.Ecosystems) > 0 {
		_, _ = fmt.Fprintf(w, "**Detected:** %s\n\n", markdownSafeText(strings.Join(r.Ecosystems, ", ")))
	}

	if len(r.Threats) == 0 {
		_, _ = fmt.Fprintln(w, "No threat categories match the detected stack.")
		return
	}

	_, _ = fmt.Fprintln(w, "| Threat | CWE | OWASP | Introduced by |")
	_, _ = fmt.Fprintln(w, "|--------|-----|-------|---------------|")
	for _, t := range r.Threats {
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |\n",
			markdownSafeText(t.Title), markdownSafeText(t.CWE), markdownSafeText(t.OWASP),
			markdownSafeText(strings.Join(t.IntroducedBy, ", ")))
	}
}

// SinksMarkdown writes the sink report in markdown format.
func SinksMarkdown(w io.Writer, r *brief.SinkReport) {
	if len(r.Sinks) == 0 {
		_, _ = fmt.Fprintln(w, "No sink data available for detected tools.")
		return
	}

	_, _ = fmt.Fprintln(w, "| Tool | Symbol | Threat | CWE |")
	_, _ = fmt.Fprintln(w, "|------|--------|--------|-----|")
	for _, s := range r.Sinks {
		_, _ = fmt.Fprintf(w, "| %s | %s | %s | %s |\n",
			markdownSafeText(s.Tool), markdownCode(s.Symbol), markdownSafeText(s.Threat), markdownSafeText(s.CWE))
	}
}

// ArtifactMarkdown writes the artifact report in Markdown format.
func ArtifactMarkdown(w io.Writer, a *brief.Artifact) {
	text := markdownSafeText
	list := func(header string, values []string) {
		items := make([]string, len(values))
		for i, value := range values {
			items[i] = text(value)
		}
		mdTruncatedList(w, header, items)
	}
	field := func(label, value string) {
		if value != "" {
			_, _ = fmt.Fprintf(w, "**%s:** %s\n\n", label, text(value))
		}
	}
	_, _ = fmt.Fprintf(w, "# brief %s — %s\n\n", text(a.Version), text(a.Path))
	field("Format", a.Format)
	field("SHA256", a.SHA256)
	if a.Entries > 0 {
		_, _ = fmt.Fprintf(w, "**Entries:** %d files, %d native objects\n\n", a.Entries, len(a.NativeObjects))
	}

	for _, obj := range a.NativeObjects {
		_, _ = fmt.Fprintf(w, "## Object: %s\n\n", text(obj.Path))
		field("Format", obj.Format)
		field("Architecture", obj.Arch)
		field("SOName", obj.SOName)
		list("Producers", obj.Producer)
		list("Needed", obj.Needed)
		if obj.Go != nil {
			field("Go", obj.Go.Version)
			field("Go path", obj.Go.Path)
			field("Go main", obj.Go.Main)
			list("Go dependencies", obj.Go.Deps)
		}
		for _, hint := range obj.Static {
			label := hint.Library
			if hint.Version != "" {
				label += " " + hint.Version
			}
			field("Static (low confidence)", label)
			field("Matched text", hint.Match)
		}
	}
	_, _ = fmt.Fprintf(w, "---\n\n%.1fms\n", a.DurationMS)
}
