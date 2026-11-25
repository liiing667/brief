package detect

import (
	"slices"
	"sort"
	"strings"

	"github.com/git-pkgs/brief"
)

// ThreatModel resolves the threat surface implied by detected tools.
// Each tool's taxonomy tags are matched against the threat mappings in
// _threats.toml; matched threat IDs are unioned with any explicit
// [security].threats on the tool, then resolved against the registry.
func (e *Engine) ThreatModel(r *brief.Report) *brief.ThreatReport {
	tr := &brief.ThreatReport{
		Version: brief.Version,
		Path:    r.Path,
	}

	for eco := range e.detectedEcosystems {
		tr.Ecosystems = append(tr.Ecosystems, eco)
	}
	sort.Strings(tr.Ecosystems)

	// A tool can surface more than once (e.g. the same tool evidenced by a
	// manifest and again by a CI workflow). Collapse to one entry per real
	// tool so repeated hits never create duplicate stack entries or threats.
	detections := uniqueDetections(allDetections(r))

	contributes := e.resolveThreats(detections)

	// Build the stack from tools that actually contribute threats or sinks.
	// Preserve first-seen order; sorting happens after the loop.
	stackSeen := make(map[string]bool)
	for _, d := range detections {
		if !contributes.tools[d.Name] || stackSeen[d.Name] {
			continue
		}
		stackSeen[d.Name] = true
		tr.Stack = append(tr.Stack, brief.StackEntry{
			Name:     d.Name,
			Taxonomy: d.Taxonomy,
			Evidence: threatEvidence(d),
		})
	}
	sort.Slice(tr.Stack, func(i, j int) bool {
		return tr.Stack[i].Name < tr.Stack[j].Name
	})

	// Resolve threat IDs against the registry and sort.
	ids := make([]string, 0, len(contributes.threats))
	for id := range contributes.threats {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		def := e.KB.Threats[id]
		attribution := contributes.threats[id]

		introducers := make([]string, 0, len(attribution.tools))
		for name := range attribution.tools {
			introducers = append(introducers, name)
		}
		sort.Strings(introducers)

		// Keep every distinct mapping note, each attributed to the real tools
		// that produced it. The legacy Note field still carries the first note
		// so existing JSON consumers see an unchanged shape.
		notes := make([]brief.ThreatNote, 0, len(attribution.notes))
		for _, note := range sortedNoteKeys(attribution.notes) {
			tools := make([]string, 0, len(attribution.notes[note]))
			for name := range attribution.notes[note] {
				tools = append(tools, name)
			}
			sort.Strings(tools)
			notes = append(notes, brief.ThreatNote{Note: note, Tools: tools})
		}

		threat := brief.Threat{
			ID:           id,
			CWE:          def.CWE,
			OWASP:        def.OWASP,
			Title:        def.Title,
			IntroducedBy: introducers,
			Notes:        notes,
		}
		if len(notes) > 0 {
			threat.Note = notes[0].Note
		}
		tr.Threats = append(tr.Threats, threat)
	}

	return tr
}

// Sinks collects known dangerous functions from all detected tools.
// CWE is filled from the threat registry when the sink doesn't carry one.
func (e *Engine) Sinks(r *brief.Report) *brief.SinkReport {
	sr := &brief.SinkReport{
		Version: brief.Version,
		Path:    r.Path,
	}

	// One entry per real tool: duplicate detections of the same tool must
	// not duplicate its sinks.
	for _, d := range uniqueDetections(allDetections(r)) {
		tool := e.KB.ByName[d.Name]
		if tool == nil {
			continue
		}
		for _, s := range tool.Security.Sinks {
			cwe := s.CWE
			if cwe == "" {
				cwe = e.KB.Threats[s.Threat].CWE
			}
			sr.Sinks = append(sr.Sinks, brief.SinkEntry{
				Symbol: s.Symbol,
				Tool:   d.Name,
				Threat: s.Threat,
				CWE:    cwe,
				Note:   s.Note,
			})
		}
	}

	sort.Slice(sr.Sinks, func(i, j int) bool {
		if sr.Sinks[i].Tool != sr.Sinks[j].Tool {
			return sr.Sinks[i].Tool < sr.Sinks[j].Tool
		}
		return sr.Sinks[i].Symbol < sr.Sinks[j].Symbol
	})

	return sr
}

// allDetections flattens languages, package managers, and tools into one slice.
func allDetections(r *brief.Report) []brief.Detection {
	var all []brief.Detection
	all = append(all, r.Languages...)
	all = append(all, r.PackageManagers...)
	for _, cat := range sortedKeys(r.Tools) {
		all = append(all, r.Tools[cat]...)
	}
	return all
}

// threatAttribution accumulates, per threat ID, the real tools that
// introduced it and every distinct mapping note explaining why.
type threatAttribution struct {
	// tools is the set of tool names introducing the threat.
	tools map[string]bool
	// notes maps each distinct mapping note to the tools it came from.
	notes map[string]map[string]bool
}

// threatResolution records which tools contribute to the model and the
// per-threat attribution collected while resolving them.
type threatResolution struct {
	// contributing tools (threats or sinks), for stack filtering.
	tools   map[string]bool
	threats map[string]*threatAttribution
}

// resolveThreats iterates detections once per real tool, matches taxonomy
// tags against threat mappings, and unions explicit [security].threats.
// Repeated detections of the same tool and repeated mappings firing the same
// threat for the same tool are deduplicated; every distinct mapping note is
// retained with the tools it belongs to.
func (e *Engine) resolveThreats(detections []brief.Detection) *threatResolution {
	res := &threatResolution{
		tools:   make(map[string]bool),
		threats: make(map[string]*threatAttribution),
	}

	attribute := func(id, tool, note string) {
		attr := res.threats[id]
		if attr == nil {
			attr = &threatAttribution{
				tools: make(map[string]bool),
				notes: make(map[string]map[string]bool),
			}
			res.threats[id] = attr
		}
		attr.tools[tool] = true
		if note != "" {
			if attr.notes[note] == nil {
				attr.notes[note] = make(map[string]bool)
			}
			attr.notes[note][tool] = true
		}
	}

	for _, d := range detections {
		tool := e.KB.ByName[d.Name]
		if tool == nil {
			continue
		}

		tags := make(map[string]bool)
		for _, t := range tool.Taxonomy.Tags() {
			tags[t] = true
		}

		for _, m := range e.KB.ThreatMappings {
			if !matchesAll(tags, m.Match) {
				continue
			}
			res.tools[d.Name] = true
			for _, id := range m.Threats {
				attribute(id, d.Name, m.Note)
			}
		}

		for _, id := range tool.Security.Threats {
			res.tools[d.Name] = true
			attribute(id, d.Name, "")
		}

		if len(tool.Security.Sinks) > 0 {
			res.tools[d.Name] = true
		}
	}
	return res
}

// uniqueDetections collapses repeated detections of the same tool to one
// entry, keeping the first-seen detection and merging the project-local
// evidence (config files, lockfile) carried by later hits. Tools can be
// evidenced from more than one place (manifest plus CI workflow) but the
// duplicate detection must not produce duplicate threats or stack entries.
func uniqueDetections(detections []brief.Detection) []brief.Detection {
	seen := make(map[string]int)
	var unique []brief.Detection
	for _, d := range detections {
		if idx, ok := seen[d.Name]; ok {
			mergeEvidence(&unique[idx], d)
			continue
		}
		seen[d.Name] = len(unique)
		unique = append(unique, d)
	}
	return unique
}

// mergeEvidence folds the project-local evidence of src into dst without
// duplicating already-recorded signals.
func mergeEvidence(dst *brief.Detection, src brief.Detection) {
	for _, f := range src.ConfigFiles {
		if !slices.Contains(dst.ConfigFiles, f) {
			dst.ConfigFiles = append(dst.ConfigFiles, f)
		}
	}
	if src.Lockfile != "" && !slices.Contains(dst.ConfigFiles, src.Lockfile) && dst.Lockfile == "" {
		dst.Lockfile = src.Lockfile
	}
}

// threatEvidence lists the project-local signals that established a tool.
func threatEvidence(d brief.Detection) []string {
	var evidence []string
	for _, f := range d.ConfigFiles {
		if !slices.Contains(evidence, f) {
			evidence = append(evidence, f)
		}
	}
	if d.Lockfile != "" && !slices.Contains(evidence, d.Lockfile) {
		evidence = append(evidence, d.Lockfile)
	}
	return evidence
}

// sortedNoteKeys returns note strings sorted case-insensitively so output is
// deterministic regardless of map iteration order.
func sortedNoteKeys(notes map[string]map[string]bool) []string {
	keys := make([]string, 0, len(notes))
	for note := range notes {
		keys = append(keys, note)
	}
	sort.Slice(keys, func(i, j int) bool {
		if strings.EqualFold(keys[i], keys[j]) {
			return keys[i] < keys[j]
		}
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})
	return keys
}

// matchesAll reports whether the tag set contains every required tag.
// An empty required slice matches nothing (vacuous mappings shouldn't fire).
func matchesAll(have map[string]bool, required []string) bool {
	if len(required) == 0 {
		return false
	}
	for _, r := range required {
		if !have[r] {
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
