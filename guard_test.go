package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func productionSyntax(t *testing.T) []*ast.File {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	return files
}
func sourceViolations(f *ast.File) []string {
	var violations []string
	randAlias := ""
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path == "math/rand" || path == "math/rand/v2" {
			violations = append(violations, "noncryptographic random")
		}
		if path == "crypto/rand" {
			randAlias = "rand"
			if imp.Name != nil {
				randAlias = imp.Name.Name
			}
			if randAlias == "." {
				violations = append(violations, "dot random import")
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok {
			for _, expr := range a.Lhs {
				sel, ok := expr.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				obj, ok := sel.X.(*ast.Ident)
				if ok && obj.Name == randAlias && sel.Sel.Name == "Reader" {
					violations = append(violations, "random Reader assignment")
				}
			}
		}
		return true
	})
	return violations
}
func TestNoNonCryptographicRandom(t *testing.T) {
	for _, f := range productionSyntax(t) {
		for _, v := range sourceViolations(f) {
			if strings.Contains(v, "noncryptographic") {
				t.Fatal(v)
			}
		}
	}
}
func TestRandomSourceWiring(t *testing.T) {
	found := false
	for _, f := range productionSyntax(t) {
		if v := sourceViolations(f); len(v) > 0 {
			t.Fatal(v)
		}
		alias := "rand"
		for _, imp := range f.Imports {
			if imp.Path.Value == `"crypto/rand"` && imp.Name != nil {
				alias = imp.Name.Name
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "newSearcher" {
				return true
			}
			if len(call.Args) != 2 {
				t.Fatal("changed search constructor")
			}
			sel, ok := call.Args[1].(*ast.SelectorExpr)
			if !ok {
				t.Fatal("production random source changed")
			}
			obj, ok := sel.X.(*ast.Ident)
			if !ok || obj.Name != alias || sel.Sel.Name != "Reader" {
				t.Fatal("production must use crypto/rand.Reader")
			}
			found = true
			return true
		})
	}
	if !found {
		t.Fatal("production search wiring not found")
	}
}
func TestGoModHasNoRequirements(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "require" {
			t.Fatal("default build must have no modules")
		}
	}
}
func TestDefaultBuildImportsOnlyStandardLibrary(t *testing.T) {
	for _, target := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"} {
		t.Run(target, func(t *testing.T) {
			parts := strings.Split(target, "/")
			cmd := exec.Command("go", "list", "-deps", "-json", ".")
			cmd.Env = append(os.Environ(), "GOOS="+parts[0], "GOARCH="+parts[1], "CGO_ENABLED=0")
			data, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(strings.NewReader(string(data)))
			for {
				var pkg struct {
					ImportPath string
					Standard   bool
					Module     *struct{ Main bool }
				}
				err := decoder.Decode(&pkg)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if !pkg.Standard && (pkg.Module == nil || !pkg.Module.Main) {
					t.Fatalf("third-party package %s", pkg.ImportPath)
				}
			}
		})
	}
}
func TestSourceGuardDetectsViolations(t *testing.T) {
	for _, src := range []string{
		`package main; import "math/rand"`,
		`package main; import r "crypto/rand";func f(){r.Reader=nil}`,
		`package main; import . "crypto/rand"`,
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "probe.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(sourceViolations(f)) == 0 {
			t.Fatal("guard failed to detect injected violation")
		}
	}
}

func byValueSecret(f *ast.File) bool {
	bad := false
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncType)
		if !ok {
			return true
		}
		for _, fields := range []*ast.FieldList{fn.Params, fn.Results} {
			if fields == nil {
				continue
			}
			for _, field := range fields.List {
				if id, ok := field.Type.(*ast.Ident); ok && (id.Name == "Identity" || id.Name == "searchOutcome") {
					bad = true
				}
			}
		}
		return true
	})
	return bad
}
func TestSecretsNotPassedByValue(t *testing.T) {
	for _, f := range productionSyntax(t) {
		if byValueSecret(f) {
			t.Fatal("secret aggregate passed by value")
		}
	}
	f, err := parser.ParseFile(token.NewFileSet(), "probe.go", `package main;func f(k Identity) searchOutcome {panic("probe")}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !byValueSecret(f) {
		t.Fatal("guard missed secret argument/result")
	}
}
