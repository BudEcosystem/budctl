package lint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// frontends may talk to a terminal. Everything else is library code: it takes
// an io.Writer or an Observer, and returns questions as data, so a TUI can be
// built on it later without touching business logic (ARCHITECTURE.md §4.1).
var frontends = []string{"cmd/", "internal/cli/", "internal/tui/"}

func TestNoTerminalIOOutsideFrontends(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && rel != "." || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		for _, f := range frontends {
			if strings.HasPrefix(rel, f) {
				return nil
			}
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(p, "github.com/charmbracelet/") || p == "golang.org/x/term" {
				t.Errorf("%s imports %s: terminal UI belongs in internal/cli or internal/tui", rel, p)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case pkg.Name == "os" && (sel.Sel.Name == "Stdout" || sel.Sel.Name == "Stdin"),
				pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Print"):
				t.Errorf("%s: %s.%s — library code writes to the io.Writer or Observer it is given", fset.Position(sel.Pos()), pkg.Name, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("lint did not run from the module root: %v", err)
	}
}
