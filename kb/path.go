package kb

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/roles"
)

// CanonicalPath returns the slash-separated, lexically clean form of a path.
func CanonicalPath(value string) string {
	if value == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(value))
}

// MatchPathPattern matches slash-separated paths and treats ** as zero or more
// complete path segments. A trailing slash denotes a directory and matches the
// directory plus every path beneath it.
func MatchPathPattern(pattern, name string) bool {
	pattern = canonicalPattern(pattern)
	name = CanonicalPath(name)
	return matchPathSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func canonicalPattern(value string) string {
	if value == "" {
		return ""
	}
	directory := strings.HasSuffix(filepath.ToSlash(value), "/")
	cleaned := CanonicalPath(value)
	if directory && cleaned != "." && cleaned != "/" {
		// ** already matches zero or more complete path segments, so this
		// covers both the directory itself and any descendant.
		cleaned += "/**"
	}
	return cleaned
}

// MatchesPath reports whether the tool has positive file or config evidence at
// filePath. Exclusion patterns are not evidence for the tool, and bundled or
// derived content (fixtures, vendored code, caches and build output) never is.
func (tool *ToolDef) MatchesPath(filePath string) bool {
	if tool == nil {
		return false
	}
	if bundledEvidencePath(filePath) {
		return false
	}
	patterns := make([]string, 0, len(tool.Detect.Files)+len(tool.Config.Files)+1)
	patterns = append(patterns, tool.Detect.Files...)
	patterns = append(patterns, tool.Config.Files...)
	if tool.Config.Lockfile != "" {
		patterns = append(patterns, tool.Config.Lockfile)
	}
	for target := range tool.Detect.FileContains {
		patterns = append(patterns, target)
	}
	for target := range tool.Detect.KeyExists {
		patterns = append(patterns, target)
	}
	canonical := CanonicalPath(filePath)
	for _, pattern := range patterns {
		if MatchPathPattern(pattern, canonical) {
			return true
		}
	}
	return false
}

// MatchesPath reports whether filePath matches this resource definition.
func (resource ResourceInfo) MatchesPath(filePath string) bool {
	if bundledEvidencePath(filePath) {
		return false
	}
	cleaned := strings.ToLower(CanonicalPath(filePath))
	dir, name := path.Split(cleaned)
	dir = strings.TrimSuffix(dir, "/")
	if !matchesAnyPath(resource.Patterns, name, true) {
		return false
	}
	if resource.Recursive || dir == "" || dir == "." {
		return true
	}
	for _, allowed := range resource.Dirs {
		if strings.EqualFold(path.Clean(filepath.ToSlash(allowed)), dir) {
			return true
		}
	}
	return false
}

func bundledEvidencePath(filePath string) bool {
	canonical := CanonicalPath(filePath)
	// Callers normally pass repository-relative paths, but tolerate absolute
	// paths so a leading volume or separator cannot hide a bundled directory.
	canonical = strings.TrimLeft(canonical, "/")
	if canonical == "" || canonical == "." || canonical == ".." ||
		strings.HasPrefix(canonical, "../") {
		return false
	}
	rolePath := canonical
	if strings.HasSuffix(filepath.ToSlash(filePath), "/") {
		rolePath += "/"
	}
	labels, err := roles.Match(rolePath)
	if err == nil && labels.BundledOrDerived() {
		return true
	}
	return matchesOutputDirectory(canonical)
}

// matchesOutputDirectory covers conventional build and temporary directories
// that are never project configuration, even when a role corpus predates them.
func matchesOutputDirectory(canonical string) bool {
	for _, part := range strings.Split(canonical, "/") {
		switch part {
		case "build", "dist", "target", "tmp", "temp", "cache", "coverage", "_build":
			return true
		}
	}
	return false
}

func matchesAnyPath(patterns []string, filePath string, foldCase bool) bool {
	if foldCase {
		filePath = strings.ToLower(CanonicalPath(filePath))
	}
	for _, pattern := range patterns {
		if foldCase {
			pattern = strings.ToLower(CanonicalPath(pattern))
		}
		if MatchPathPattern(pattern, filePath) {
			return true
		}
	}
	return false
}

func matchPathSegments(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	if pattern[0] == "**" {
		if matchPathSegments(pattern[1:], name) {
			return true
		}
		return len(name) > 0 && matchPathSegments(pattern, name[1:])
	}
	if len(name) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], name[0])
	return err == nil && matched && matchPathSegments(pattern[1:], name[1:])
}
