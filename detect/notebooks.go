package detect

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/brief"
	"github.com/git-pkgs/brief/kb"
)

var errNotebookFormat = errors.New("expected a version 3 or 4 notebook with code-cell sources")

const (
	notebookFileBytes      = 8 << 20
	notebookTotalBytes     = 32 << 20
	notebookFileCount      = 32
	notebookCellBytes      = 1 << 20
	notebookMaxCells       = 10_000
	notebookMaxDepth       = 64
	notebookFormat         = 4
	notebookLegacy         = 3
	notebookInvalid        = "invalid"
	notebookDepthLimit     = "depth_limit"
	notebookCellLimit      = "cell_byte_limit"
	notebookCellCountLimit = "cell_count_limit"
	notebookLanguageBytes  = 64
)

type notebookBudgetError struct {
	status   string
	limit    int64
	observed int64
}

func (e *notebookBudgetError) Error() string {
	return e.status
}

func notebookBudgetInfo() brief.NotebookBudget {
	return brief.NotebookBudget{
		MaxFiles:      notebookFileCount,
		MaxFileBytes:  notebookFileBytes,
		MaxTotalBytes: notebookTotalBytes,
		MaxCellBytes:  notebookCellBytes,
		MaxCells:      notebookMaxCells,
		MaxDepth:      notebookMaxDepth,
	}
}

type notebookCell struct {
	Type    string          `json:"cell_type"`
	Source  json.RawMessage `json:"source"`
	Input   json.RawMessage `json:"input"`
	Outputs json.RawMessage `json:"outputs"`
}

type notebookDocument struct {
	Format   int `json:"nbformat"`
	Metadata struct {
		Language   string `json:"language"`
		KernelSpec struct {
			Language string `json:"language"`
		} `json:"kernelspec"`
		LanguageInfo struct {
			Name string `json:"name"`
		} `json:"language_info"`
	} `json:"metadata"`
	Cells      []notebookCell `json:"cells"`
	Worksheets []struct {
		Cells []notebookCell `json:"cells"`
	} `json:"worksheets"`
}

func (e *Engine) detectNotebooks() *brief.NotebookInfo {
	e.loadProjectFiles()
	result := &brief.NotebookInfo{Files: []brief.NotebookFile{}, Budget: notebookBudgetInfo()}
	processed := 0
	for _, file := range e.indexedFiles {
		if !strings.EqualFold(filepath.Ext(file), ".ipynb") {
			continue
		}
		if processed >= notebookFileCount {
			result.SkippedFiles++
			continue
		}
		processed++
		stats, read, budgetErr := e.readNotebookBudget(file, notebookTotalBytes-result.ReadBytes)
		result.ReadBytes += read
		if budgetErr != nil {
			result.Budget.Failures = append(result.Budget.Failures, brief.NotebookBudgetFailure{
				Path:     stats.Path,
				Status:   budgetErr.status,
				Limit:    budgetErr.limit,
				Observed: budgetErr.observed,
			})
			continue
		}
		result.Files = append(result.Files, stats)
	}
	return result
}

func (e *Engine) readNotebook(file string, remaining int64) (brief.NotebookFile, int64) {
	stats, read, _ := e.readNotebookBudget(file, remaining)
	return stats, read
}

func (e *Engine) readNotebookBudget(file string, remaining int64) (brief.NotebookFile, int64, *notebookBudgetError) {
	stats := brief.NotebookFile{Path: filepath.ToSlash(file), Status: "unreadable"}
	f, err := e.projectFS().Open(filepath.ToSlash(file))
	if err != nil {
		return stats, 0, nil
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return stats, 0, nil
	}
	stats.FileBytes = info.Size()
	if info.Size() > notebookFileBytes {
		stats.Status = "size_limit"
		return stats, 0, &notebookBudgetError{status: "size_limit", limit: notebookFileBytes, observed: info.Size()}
	}
	remaining = max(0, remaining)
	if info.Size() > remaining {
		stats.Status = "byte_limit"
		return stats, 0, &notebookBudgetError{status: "byte_limit", limit: remaining, observed: info.Size()}
	}
	limit := min(int64(notebookFileBytes), remaining)
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	read := int64(len(data))
	if err != nil {
		return stats, read, nil
	}
	if read > limit {
		stats.Status = "size_limit"
		return stats, read, &notebookBudgetError{status: "size_limit", limit: limit, observed: int64(read)}
	}
	parsed, err := parseNotebook(data)
	if err != nil {
		var budgetErr *notebookBudgetError
		if errors.As(err, &budgetErr) {
			stats.Status = budgetErr.status
			return stats, read, budgetErr
		}
		stats.Status = notebookInvalid
		return stats, read, nil
	}
	parsed.Path, parsed.FileBytes, parsed.Status = stats.Path, stats.FileBytes, "ok"
	return parsed, read, nil
}

func parseNotebook(data []byte) (brief.NotebookFile, error) {
	if depth, exceeded := notebookDepthExceeded(data, notebookMaxDepth); exceeded {
		return brief.NotebookFile{}, &notebookBudgetError{status: notebookDepthLimit, limit: notebookMaxDepth, observed: int64(depth)}
	}
	var document notebookDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return brief.NotebookFile{}, err
	}
	cells, err := notebookCells(document)
	if err != nil {
		return brief.NotebookFile{}, err
	}
	result := brief.NotebookFile{}
	if len(cells) > notebookMaxCells {
		return brief.NotebookFile{}, &notebookBudgetError{status: notebookCellCountLimit, limit: notebookMaxCells, observed: int64(len(cells))}
	}
	for _, candidate := range []struct{ value, source string }{
		{document.Metadata.LanguageInfo.Name, "language_info"},
		{document.Metadata.KernelSpec.Language, "kernelspec"},
		{document.Metadata.Language, "metadata"},
	} {
		language := strings.TrimSpace(candidate.value)
		if language != "" && len(language) <= notebookLanguageBytes {
			result.Language, result.LanguageSource = language, candidate.source
			break
		}
	}
	for _, cell := range cells {
		if cell.Type != "code" {
			continue
		}
		source, err := notebookSource(cell.Source)
		if err != nil {
			return brief.NotebookFile{}, err
		}
		if len(source) > notebookCellBytes {
			return brief.NotebookFile{}, &notebookBudgetError{status: notebookCellLimit, limit: notebookCellBytes, observed: int64(len(source))}
		}
		result.CodeCells++
		result.CodeBytes += len(source)
		result.CodeLines += strings.Count(source, "\n")
		if source != "" && !strings.HasSuffix(source, "\n") {
			result.CodeLines++
		}
		result.OutputBytes += len(cell.Outputs)
	}
	return result, nil
}

func notebookCells(document notebookDocument) ([]notebookCell, error) {
	if document.Format == notebookFormat && document.Cells != nil {
		return document.Cells, nil
	}
	if document.Format != notebookLegacy || document.Worksheets == nil {
		return nil, errNotebookFormat
	}
	var cells []notebookCell
	for _, worksheet := range document.Worksheets {
		for _, cell := range worksheet.Cells {
			cell.Source = cell.Input
			cells = append(cells, cell)
		}
	}
	return cells, nil
}

func notebookSource(data json.RawMessage) (string, error) {
	var single string
	if len(data) > 0 && data[0] == '"' {
		err := json.Unmarshal(data, &single)
		return single, err
	}
	var lines []string
	if err := json.Unmarshal(data, &lines); err != nil {
		return "", err
	}
	if lines == nil {
		return "", errNotebookFormat
	}
	return strings.Join(lines, ""), nil
}

func notebookDepthExceeded(data []byte, maxDepth int) (int, bool) {
	depth := 0
	inString := false
	escaped := false
	for _, c := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}

		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return depth, true
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth, false
}

func (e *Engine) notebookLanguagePaths(language string) []string {
	if e.notebooks == nil || !e.NotebookStats {
		return nil
	}
	var paths []string
	for _, file := range e.notebooks.Files {
		if file.Status == "ok" && file.CodeCells > 0 && strings.EqualFold(file.Language, language) && e.languageEvidence(file.Path) {
			paths = append(paths, file.Path)
		}
	}
	return paths
}

func (e *Engine) notebookLanguageConfidence(tool *kb.ToolDef) brief.Confidence {
	if tool.Tool.Category == categoryLanguage && len(e.notebookLanguagePaths(tool.Tool.Name)) > 0 {
		return brief.ConfidenceHigh
	}
	return ""
}
