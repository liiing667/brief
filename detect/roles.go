package detect

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/git-pkgs/brief/kb"
	"github.com/git-pkgs/roles"
)

func (e *Engine) pathRoles(rel string) roles.Set {
	if labels, ok := e.fileRoles[rel]; ok {
		return labels
	}
	labels, err := roles.Match(e.localEvidencePath(rel))
	if err != nil {
		return 0
	}
	return labels
}

// localEvidencePath returns rel relative to the containing analysis root. An
// included submodule keeps its own path semantics even if the submodule itself
// sits below a conventional bundled directory such as vendor/.
func (e *Engine) localEvidencePath(rel string) string {
	local := filepath.ToSlash(e.pathAtAnalysisRoot(rel))
	if strings.HasSuffix(rel, "/") {
		local += "/"
	}
	return local
}

func (e *Engine) projectEvidence(rel string) bool {
	if e.pathRoles(rel).BundledOrDerived() {
		return false
	}
	// The bounded scan skips these directories entirely. Treat their contents
	// the same way when a caller asks about a specific path.
	return !skippedEvidencePath(e.localEvidencePath(rel))
}

// bundledEvidencePath reports whether rel belongs to content that the bounded
// scan never treats as project evidence: fixtures, vendored code, caches and
// build output. Changed-file filtering uses the same rule so a commit that only
// touches bundled content cannot make an unrelated detection relevant.
func bundledEvidencePath(rel string) bool {
	slash := filepath.ToSlash(rel)
	cleaned := filepath.ToSlash(filepath.Clean(rel))
	if strings.HasSuffix(slash, "/") && cleaned != "." && cleaned != "" {
		cleaned += "/"
	}
	if cleaned != "." && cleaned != "" {
		if labels, err := roles.Match(cleaned); err == nil && labels.BundledOrDerived() {
			return true
		}
	}
	return skippedEvidencePath(rel)
}

func skippedEvidencePath(rel string) bool {
	cleaned := filepath.ToSlash(filepath.Clean(rel))
	if cleaned == "." || cleaned == "" {
		return false
	}
	for _, part := range strings.Split(cleaned, "/") {
		if defaultSkipDirs[part] {
			return true
		}
	}
	return false
}

func (e *Engine) languageEvidence(rel string) bool {
	if !e.projectEvidence(rel) {
		return false
	}
	labels := e.pathRoles(rel)
	return !labels.Has(roles.Generated) && !labels.Has(roles.Example) &&
		!labels.Has(roles.Test) && !labels.Has(roles.Benchmark) &&
		!labels.Has(roles.Fuzz) && !labels.Has(roles.Documentation) &&
		!labels.Has(roles.Tooling)
}

func (e *Engine) sourceEvidence(rel string) bool {
	if !e.languageEvidence(rel) {
		return false
	}
	labels := e.pathRoles(rel)
	// Unclassified paths include root files and unconventional source directories.
	return (labels == 0 || labels.Has(roles.Source)) &&
		!labels.Has(roles.Packaging) && !labels.Has(roles.Configuration) &&
		!labels.Has(roles.Build) && !labels.Has(roles.CI) && !labels.Has(roles.Legal)
}

func (e *Engine) languageFileExists(pattern string) bool {
	e.filesChecked++
	e.loadProjectFiles()
	for _, rel := range e.projectFiles {
		if e.languageEvidence(rel) && e.matchesProjectPattern(pattern, rel) {
			return true
		}
	}
	return false
}

func (e *Engine) typeScriptDeclarationsOnly(tool *kb.ToolDef) *bool {
	e.loadProjectFiles()
	var hasDeclaration bool
	for _, rel := range e.projectFiles {
		if !slices.ContainsFunc(tool.Detect.Files, func(pattern string) bool {
			return e.matchesProjectPattern(pattern, rel)
		}) || !e.languageEvidence(rel) {
			continue
		}
		// A config can establish the language without being source evidence.
		if slices.ContainsFunc(tool.Config.Files, func(pattern string) bool {
			return e.matchesProjectPattern(pattern, rel) || kb.MatchPathPattern(pattern, filepath.Base(rel))
		}) {
			continue
		}
		ext := filepath.Ext(rel)
		if ext == ".tsx" || !strings.HasSuffix(rel, ".d"+ext) {
			return new(false)
		}
		hasDeclaration = true
	}
	if hasDeclaration {
		return new(true)
	}
	return nil
}
