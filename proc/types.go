package proc

import (
	"debug/dwarf"
	"go/ast"
	"strings"
)

// Do not call this function directly it isn't able to deal correctly with package paths
func (dbp *Process) findType(name string) (dwarf.Type, error) {
	reader := dbp.DwarfReader()
	typentry, err := reader.SeekToTypeNamed(name)
	if err != nil {
		return nil, err
	}
	return dbp.dwarf.Type(typentry.Offset)
}

func (dbp *Process) pointerTo(typ dwarf.Type) dwarf.Type {
	return &dwarf.PtrType{dwarf.CommonType{int64(dbp.arch.PtrSize()), ""}, typ}
}

func (dbp *Process) findTypeExpr(expr ast.Expr) (dwarf.Type, error) {
	dbp.loadPackageMap()
	dbp.expandPackagesInType(expr)
	if snode, ok := expr.(*ast.StarExpr); ok {
		// Pointer types only appear in the dwarf informations when
		// a pointer to the type is used in the target program, here
		// we create a pointer type on the fly so that the user can
		// specify a pointer to any variable used in the target program
		ptyp, err := dbp.findType(exprToString(snode.X))
		if err != nil {
			return nil, err
		}
		return dbp.pointerTo(ptyp), nil
	}
	return dbp.findType(exprToString(expr))
}

func complexType(typename string) bool {
	dot := 0
	for _, ch := range typename {
		switch ch {
		case '*', '[', '<', '{', '(', ' ':
			return true
		case '.':
			dot++
			if dot > 1 {
				return true
			}
		}
	}
	return false
}

func (dbp *Process) loadPackageMap() error {
	if dbp.packageMap != nil {
		return nil
	}
	dbp.packageMap = map[string]string{}
	reader := dbp.DwarfReader()
	for entry, err := reader.Next(); entry != nil; entry, err = reader.Next() {
		if err != nil {
			return err
		}

		if entry.Tag != dwarf.TagTypedef && entry.Tag != dwarf.TagBaseType && entry.Tag != dwarf.TagClassType && entry.Tag != dwarf.TagStructType {
			continue
		}

		typename, ok := entry.Val(dwarf.AttrName).(string)
		if !ok || complexType(typename) {
			continue
		}

		dot := strings.Index(typename, ".")
		if dot < 0 {
			continue
		}
		path := typename[:dot]
		slash := strings.LastIndex(path, "/")
		if slash < 0 || slash+1 >= len(path) {
			continue
		}
		name := path[slash+1:]
		dbp.packageMap[name] = path
	}
	return nil
}

func (dbp *Process) expandPackagesInType(expr ast.Expr) {
	switch e := expr.(type) {
	case *ast.ArrayType:
		dbp.expandPackagesInType(e.Elt)
	case *ast.ChanType:
		dbp.expandPackagesInType(e.Value)
	case *ast.FuncType:
		for i := range e.Params.List {
			dbp.expandPackagesInType(e.Params.List[i].Type)
		}
		if e.Results != nil {
			for i := range e.Results.List {
				dbp.expandPackagesInType(e.Results.List[i].Type)
			}
		}
	case *ast.MapType:
		dbp.expandPackagesInType(e.Key)
		dbp.expandPackagesInType(e.Value)
	case *ast.ParenExpr:
		dbp.expandPackagesInType(e.X)
	case *ast.SelectorExpr:
		switch x := e.X.(type) {
		case *ast.Ident:
			if path, ok := dbp.packageMap[x.Name]; ok {
				x.Name = path
			}
		default:
			dbp.expandPackagesInType(e.X)
		}
	case *ast.StarExpr:
		dbp.expandPackagesInType(e.X)
	default:
		// nothing to do
	}
}
