//go:build unix

package detect

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// hardLinkToProject links external into root as name, skipping the test when
// the filesystem does not support hard links.
func hardLinkToProject(t *testing.T, external, root, name string) {
	t.Helper()
	if err := os.Link(external, filepath.Join(root, name)); err != nil {
		t.Skipf("creating hard link: %v", err)
	}
}

func TestHardLinkedManifestRejected(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	hostManifest := filepath.Join(external, "host-package.json")
	writeProjectFile(t, external, "host-package.json",
		`{"name":"host-secret","dependencies":{"left-pad":"1.0.0"}}`)
	hardLinkToProject(t, hostManifest, root, "package.json")
	writeProjectFile(t, root, "main.go", "package main\n")

	engine := New(loadKB(t), root)
	r, err := engine.Run()
	if err != nil {
		t.Fatal(err)
	}

	if slices.Contains(engine.projectFiles, "package.json") {
		t.Error("hard-linked package.json entered the project file index")
	}
	if engine.exactFileExists("package.json") {
		t.Error("hard-linked package.json treated as an existing regular file")
	}
	data, err := engine.safeReadFile("package.json")
	if err == nil || !strings.Contains(err.Error(), "hard-linked") {
		t.Errorf("safeReadFile error = %v, want hard link rejection", err)
	}
	if data != nil {
		t.Errorf("safeReadFile returned %q for hard-linked file, want no data", data)
	}

	// The rejected file must not pollute the report.
	if slices.Contains(packageManagerNames(r), "npm") {
		t.Error("hard-linked package.json triggered npm detection")
	}
	for _, m := range r.Manifests {
		if m.Path == "package.json" {
			t.Errorf("hard-linked manifest leaked into report: %+v", m)
		}
	}
	for _, d := range r.Dependencies {
		if d.Name == "left-pad" {
			t.Errorf("host dependency leaked into report: %+v", d)
		}
	}
	// The genuine project file is still detected.
	if !slices.Contains(engine.projectFiles, "main.go") {
		t.Error("regular file main.go missing from the project file index")
	}
}

func TestHardLinkedLanguageFileExcluded(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	hostSource := filepath.Join(external, "host.py")
	writeProjectFile(t, external, "host.py", "print('host')\n")
	hardLinkToProject(t, hostSource, root, "host.py")
	writeProjectFile(t, root, "main.go", "package main\n")

	engine := New(loadKB(t), root)
	r, err := engine.Run()
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(engine.projectFiles, "host.py") {
		t.Error("hard-linked host.py entered the project file index")
	}
	for _, language := range r.Languages {
		if language.Name == "Python" {
			t.Error("hard-linked host.py counted toward language statistics")
		}
	}
}

func TestProjectBoundaryKeepsNormalFilesAndControlledSymlinks(t *testing.T) {
	root := t.TempDir()
	writeProjectFile(t, root, "real_go.mod", "module example.com/ok\n")
	writeProjectFile(t, root, "main.go", "package main\n")
	if err := os.Symlink("real_go.mod", filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("creating file symlink: %v", err)
	}

	engine := New(loadKB(t), root)
	assertSafeRead(t, engine, "go.mod", "module example.com/ok\n")
	assertSafeRead(t, engine, "main.go", "package main\n")

	engine.loadProjectFiles()
	if !slices.Contains(engine.projectFiles, "main.go") {
		t.Error("regular file main.go missing from the project file index")
	}
}
