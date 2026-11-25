package detect

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/git-pkgs/brief"
)

func TestNotebookParseBudgetIsObservableAndAtomic(t *testing.T) {
	source := strings.Repeat(`{"deep":`, notebookMaxDepth*2) + "0" + strings.Repeat("}", notebookMaxDepth*2)
	deep := `{"nbformat":4,"metadata":{"language_info":{"name":"python"}},"cells":[{"cell_type":"code","source":[` + source + `]}]}`
	fsys := fstest.MapFS{
		"deep.ipynb": {Data: []byte(deep)},
		"main.py":    {Data: []byte("print('stable')\n")},
	}

	engine := NewFS(loadKB(t), fsys)
	engine.NotebookStats = true
	report, err := engine.Run()
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Notebooks.Files) != 0 {
		t.Fatalf("budget failure published notebook statistics: %+v", report.Notebooks.Files)
	}
	if len(report.Notebooks.Budget.Failures) != 1 || report.Notebooks.Budget.Failures[0].Status != notebookDepthLimit {
		t.Fatalf("budget failure not observable: %+v", report.Notebooks.Budget)
	}
	if report.Notebooks.Budget.MaxDepth != notebookMaxDepth || report.Notebooks.Budget.MaxCellBytes != notebookCellBytes {
		t.Fatalf("budget limits not exposed: %+v", report.Notebooks.Budget)
	}
	if len(report.Languages) == 0 {
		t.Fatal("notebook budget failure hid other project source evidence")
	}
	for _, language := range report.Languages {
		if strings.EqualFold(language.Name, "Python") && language.Confidence == brief.ConfidenceHigh {
			t.Fatalf("failed notebook still established high-confidence language evidence: %+v", language)
		}
	}
}

func TestNotebookBudgetFailureDoesNotSurviveRepair(t *testing.T) {
	bigSource := strings.Repeat("x", notebookCellBytes+1)
	fsys := fstest.MapFS{
		"repaired.ipynb": {Data: []byte(`{"nbformat":4,"metadata":{"language_info":{"name":"python"}},"cells":[{"cell_type":"code","source":"` + bigSource + `"}]}`)},
	}
	engine := NewFS(loadKB(t), fsys)
	engine.NotebookStats = true

	report, err := engine.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Notebooks.Files) != 0 || len(report.Notebooks.Budget.Failures) != 1 {
		t.Fatalf("oversized cell was committed: %+v", report.Notebooks)
	}

	fsys["repaired.ipynb"].Data = []byte(`{"nbformat":4,"metadata":{"language_info":{"name":"python"}},"cells":[{"cell_type":"code","source":["print(1)\n"]}]}`)
	report, err = engine.Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Notebooks.Budget.Failures) != 0 || len(report.Notebooks.Files) != 1 || report.Notebooks.Files[0].Status != "ok" {
		t.Fatalf("repair did not produce a clean generation: %+v", report.Notebooks)
	}
}
