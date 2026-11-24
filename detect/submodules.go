package detect

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/git-pkgs/brief/kb"
)

type submoduleInfo struct {
	Name        string
	Path        string
	Parent      string
	Initialized bool
	identity    submoduleIdentity
}

type submoduleIdentity struct {
	Parent string
	Name   string
	Path   string
}

func (id submoduleIdentity) key() string {
	return id.Parent + "\x00" + id.Name + "\x00" + id.Path
}

func (e *Engine) loadSubmodules() {
	if e.submodulesLoaded {
		return
	}
	e.submodulesLoaded = true
	if e.fsOnly {
		return
	}
	e.submoduleByIdentity = make(map[string]submoduleInfo)
	e.loadSubmodulesFrom(e.Root, "", make(map[string]bool))
	sort.Slice(e.submodules, func(i, j int) bool {
		if e.submodules[i].Path != e.submodules[j].Path {
			return e.submodules[i].Path < e.submodules[j].Path
		}
		if e.submodules[i].Parent != e.submodules[j].Parent {
			return e.submodules[i].Parent < e.submodules[j].Parent
		}
		return e.submodules[i].Name < e.submodules[j].Name
	})
	e.submoduleByPath = make(map[string]submoduleInfo, len(e.submodules))
	e.submoduleRoutes = make(map[string]bool)
	for _, submodule := range e.submodules {
		if existing, ok := e.submoduleByPath[submodule.Path]; !ok || preferSubmoduleRecord(submodule, existing) {
			e.submoduleByPath[submodule.Path] = submodule
		}
		if !submodule.Initialized {
			continue
		}
		for route := submodule.Path; route != "."; route = filepath.Dir(route) {
			e.submoduleRoutes[route] = true
		}
	}
}

func preferSubmoduleRecord(candidate, existing submoduleInfo) bool {
	if candidate.Initialized != existing.Initialized {
		return candidate.Initialized
	}
	if candidate.Parent != existing.Parent {
		return len(candidate.Parent) > len(existing.Parent)
	}
	return candidate.Name < existing.Name
}

func (e *Engine) loadSubmodulesFrom(root, parent string, seen map[string]bool) {
	if e.submoduleByIdentity == nil {
		e.submoduleByIdentity = make(map[string]submoduleInfo)
	}
	modulesFile := filepath.Join(root, ".gitmodules")
	info, err := os.Lstat(modulesFile)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	absRoot, err := filepath.Abs(root)
	if err != nil || seen[absRoot] {
		return
	}
	seen[absRoot] = true

	cmd := exec.Command("git", "config", "--null", "--file", ".gitmodules", "--get-regexp", `^submodule\..*\.path$`)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return
	}
	for record := range strings.SplitSeq(string(out), "\x00") {
		if record == "" {
			continue
		}
		if e.IncludeSubmodules && e.ScanLimit > 0 && e.submoduleEntries >= e.ScanLimit {
			e.scanTruncated = true
			return
		}
		e.submoduleEntries++
		configKey, configuredPath, ok := strings.Cut(record, "\n")
		if !ok {
			continue
		}
		name := submoduleConfigName(configKey)
		child, ok := cleanSubmodulePath(configuredPath)
		if !ok {
			continue
		}
		fullPath := filepath.Clean(filepath.Join(parent, child))
		if _, ok := rootRelativePath(fullPath); !ok {
			continue
		}
		identity := submoduleIdentity{Parent: parent, Name: name, Path: fullPath}
		if _, duplicate := e.submoduleByIdentity[identity.key()]; duplicate {
			continue
		}
		childRoot := filepath.Join(root, child)
		initialized := e.IncludeSubmodules && initializedSubmoduleDir(childRoot, root)
		info := submoduleInfo{
			Name:        name,
			Path:        fullPath,
			Parent:      parent,
			Initialized: initialized,
			identity:    identity,
		}
		e.submoduleByIdentity[identity.key()] = info
		e.submodules = append(e.submodules, info)
		if initialized && e.IncludeSubmodules &&
			(e.ScanDepth == 0 || pathDepth(fullPath) <= e.ScanDepth) {
			e.loadSubmodulesFrom(childRoot, fullPath, seen)
		}
	}
}

func submoduleConfigName(configKey string) string {
	name, ok := strings.CutPrefix(configKey, "submodule.")
	if !ok {
		return ""
	}
	name, ok = strings.CutSuffix(name, ".path")
	if !ok {
		return ""
	}
	return name
}

func cleanSubmodulePath(value string) (string, bool) {
	if strings.TrimSpace(value) == "" {
		return "", false
	}
	cleaned, ok := rootRelativePath(strings.TrimSpace(value))
	if !ok || cleaned == "." {
		return "", false
	}
	return cleaned, true
}

// rootRelativePath canonicalizes a path relative to the analysis root and
// rejects absolute paths and traversal above that root.
func rootRelativePath(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	cleaned := filepath.Clean(filepath.FromSlash(value))
	if cleaned == "." {
		return ".", true
	}
	if filepath.IsAbs(cleaned) || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", false
	}
	return cleaned, true
}

func initializedSubmoduleDir(root, parent string) bool {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	out, err := exec.Command("git", "-C", root, "rev-parse", "--show-superproject-working-tree").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return false
	}
	superproject, err := os.Stat(filepath.FromSlash(strings.TrimSpace(string(out))))
	if err != nil {
		return false
	}
	parentInfo, err := os.Stat(parent)
	return err == nil && os.SameFile(superproject, parentInfo)
}

func (e *Engine) submoduleForPath(rel string) (submoduleInfo, bool) {
	e.loadSubmodules()
	rel, ok := rootRelativePath(rel)
	if !ok {
		return submoduleInfo{}, false
	}
	submodule, ok := e.submoduleByPath[rel]
	return submodule, ok
}

func (e *Engine) initializedSubmoduleRoute(rel string) bool {
	e.loadSubmodules()
	rel, ok := rootRelativePath(rel)
	if !ok {
		return false
	}
	return e.submoduleRoutes[rel]
}

func (e *Engine) addIncludedSubmodule(rel string) {
	if e.includedSubmoduleSet == nil {
		e.includedSubmoduleSet = make(map[string]bool)
	}
	if e.includedSubmoduleSet[rel] {
		return
	}
	e.includedSubmoduleSet[rel] = true
	e.includedSubmodules = append(e.includedSubmodules, rel)
}

func (e *Engine) analysisRoots() []string {
	e.loadProjectFiles()
	roots := make([]string, 1, len(e.includedSubmodules)+1)
	copyRoots := append([]string(nil), e.includedSubmodules...)
	sort.Strings(copyRoots)
	return append(roots, copyRoots...)
}

func (e *Engine) analysisRootFor(rel string) string {
	cleaned, ok := rootRelativePath(rel)
	if !ok {
		return ""
	}
	for candidate := cleaned; candidate != "."; candidate = filepath.Dir(candidate) {
		if e.includedSubmoduleSet[candidate] {
			return candidate
		}
	}
	return ""
}

func (e *Engine) pathAtAnalysisRoot(rel string) string {
	root := e.analysisRootFor(rel)
	if root == "" {
		return filepath.Clean(rel)
	}
	local, err := filepath.Rel(root, rel)
	if err != nil {
		return filepath.Clean(rel)
	}
	return local
}

func (e *Engine) matchesProjectPattern(pattern, rel string) bool {
	slashRel := filepath.ToSlash(rel)
	if kb.MatchPathPattern(pattern, slashRel) {
		return true
	}
	local := e.pathAtAnalysisRoot(rel)
	return local != rel && kb.MatchPathPattern(pattern, filepath.ToSlash(local))
}

func (e *Engine) isAnalysisRootPath(root string) bool {
	if filepath.Clean(root) == filepath.Clean(e.Root) {
		return true
	}
	rel, err := filepath.Rel(e.Root, root)
	if err != nil {
		return false
	}
	submodule, ok := e.submoduleForPath(rel)
	return ok && submodule.Initialized
}

func (e *Engine) directSubmodulePaths(parent string) []string {
	e.loadSubmodules()
	var paths []string
	for _, submodule := range e.submodules {
		if submodule.Parent != parent {
			continue
		}
		rel, err := filepath.Rel(baseOrDot(parent), submodule.Path)
		if err == nil {
			paths = append(paths, filepath.ToSlash(rel))
		}
	}
	sort.Strings(paths)
	return paths
}

// ExpandSubmoduleChanges adds scanned files beneath changed submodule roots.
func (e *Engine) ExpandSubmoduleChanges(changedFiles []string) []string {
	e.loadProjectFiles()
	seen := make(map[string]bool, len(changedFiles))
	scoped := make([]string, 0, len(changedFiles))
	for _, file := range changedFiles {
		rel, ok := rootRelativePath(file)
		if !ok {
			continue
		}
		slashRel := filepath.ToSlash(rel)
		if seen[slashRel] {
			continue
		}
		seen[slashRel] = true
		scoped = append(scoped, slashRel)
	}

	expanded := append([]string(nil), scoped...)
	for _, changed := range scoped {
		root, ok := rootRelativePath(changed)
		if !ok {
			continue
		}
		if !e.includedSubmoduleSet[root] {
			continue
		}
		prefix := filepath.ToSlash(root) + "/"
		for _, file := range e.projectFiles {
			slashFile := filepath.ToSlash(file)
			if !strings.HasPrefix(slashFile, prefix) {
				continue
			}
			rel, ok := rootRelativePath(slashFile)
			if !ok {
				continue
			}
			slashFile = filepath.ToSlash(rel)
			if seen[slashFile] {
				continue
			}
			seen[slashFile] = true
			expanded = append(expanded, slashFile)
		}
	}
	return expanded
}
