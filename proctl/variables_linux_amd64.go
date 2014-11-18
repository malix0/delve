package proctl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/derekparker/delve/dwarf/op"
	"github.com/derekparker/delve/vendor/dwarf"
)

type Variable struct {
	Name  string
	Value string
	Type  string
}

type M struct {
	id        int
	procid    int
	g0        uintptr
	blocked   uint8
	spinning  uint8
	mallocing uint8
	gcing     uint8
	curg      uintptr
	lockedg   uintptr
	p         uintptr
	locks     uint32
}

type G struct {
	goid    uint64
	pc      uint64
	status  uint16
	file    string
	line    int
	fn      string
	lockedm uintptr
}

// Parses and returns select info on the internal M
// data structures used by the Go scheduler.
func (thread *ThreadContext) AllM() ([]*M, error) {
	data, err := thread.Process.Executable.DWARF()
	if err != nil {
		return nil, err
	}
	reader := data.Reader()

	procidoffset, err := offsetForMember("runtime.m", "procid", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	spinningoffset, err := offsetForMember("runtime.m", "spinning", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	alllinkoffset, err := offsetForMember("runtime.m", "alllink", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	locksoffset, err := offsetForMember("runtime.m", "locks", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	blockedoffset, err := offsetForMember("runtime.m", "blocked", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	idoffset, err := offsetForMember("runtime.m", "id", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	mallocingoffset, err := offsetForMember("runtime.m", "mallocing", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	gcingoffset, err := offsetForMember("runtime.m", "gcing", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	curgoffset, err := offsetForMember("runtime.m", "curg", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	lockedgoffset, err := offsetForMember("runtime.m", "lockedg", thread.Process, reader)
	if err != nil {
		return nil, err
	}
	reader.Seek(0)
	poffset, err := offsetForMember("runtime.m", "p", thread.Process, reader)
	if err != nil {
		return nil, err
	}

	reader.Seek(0)
	allmaddr, err := parseAllMPtr(thread.Process, reader)
	if err != nil {
		return nil, err
	}
	allmptr, err := thread.readMemory(uintptr(allmaddr), 8)
	if err != nil {
		return nil, err
	}
	m := binary.LittleEndian.Uint64(allmptr)
	if m == 0 {
		return nil, fmt.Errorf("allm contains no M pointers")
	}

	var allm []*M
	for {
		pbytes, err := thread.readMemory(uintptr(m+poffset), 8)
		if err != nil {
			return nil, err
		}
		p := binary.LittleEndian.Uint64(pbytes)

		curgbytes, err := thread.readMemory(uintptr(m+curgoffset), 8)
		if err != nil {
			return nil, err
		}
		curg := binary.LittleEndian.Uint64(curgbytes)

		lockedgbytes, err := thread.readMemory(uintptr(m+lockedgoffset), 8)
		if err != nil {
			return nil, err
		}
		lockedg := binary.LittleEndian.Uint64(lockedgbytes)

		g0bytes, err := thread.readMemory(uintptr(m), 8)
		if err != nil {
			return nil, err
		}
		g0 := binary.LittleEndian.Uint64(g0bytes)

		locksbytes, err := thread.readMemory(uintptr(m+locksoffset), 8)
		if err != nil {
			return nil, err
		}
		locks := binary.LittleEndian.Uint32(locksbytes)

		idbytes, err := thread.readMemory(uintptr(m+idoffset), 8)
		if err != nil {
			return nil, err
		}
		id := binary.LittleEndian.Uint64(idbytes)

		procidbytes, err := thread.readMemory(uintptr(m+procidoffset), 8)
		if err != nil {
			return nil, err
		}
		procid := binary.LittleEndian.Uint64(procidbytes)

		spinbytes, err := thread.readMemory(uintptr(m+spinningoffset), 1)
		if err != nil {
			return nil, err
		}

		blockbytes, err := thread.readMemory(uintptr(m+blockedoffset), 1)
		if err != nil {
			return nil, err
		}

		mallocingbytes, err := thread.readMemory(uintptr(m+mallocingoffset), 1)
		if err != nil {
			return nil, err
		}

		gcingbytes, err := thread.readMemory(uintptr(m+gcingoffset), 1)
		if err != nil {
			return nil, err
		}

		allm = append(allm, &M{
			id:        int(id),
			procid:    int(procid),
			blocked:   blockbytes[0],
			spinning:  spinbytes[0],
			curg:      uintptr(curg),
			p:         uintptr(p),
			g0:        uintptr(g0),
			lockedg:   uintptr(lockedg),
			mallocing: mallocingbytes[0],
			gcing:     gcingbytes[0],
			locks:     locks,
		})
		// Follow the linked list
		mptr, err := thread.readMemory(uintptr(m+alllinkoffset), 8)
		if err != nil {
			return nil, err
		}
		m = binary.LittleEndian.Uint64(mptr)
		if m == 0 {
			break
		}
	}

	return allm, nil
}

func offsetForMember(parent, member string, dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	reader.Seek(0)
	_, err := findDwarfEntry(parent, reader)
	if err != nil {
		return 0, err
	}
	entry, err := findDwarfEntry(member, reader)
	if err != nil {
		return 0, err
	}
	instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	addr, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(addr), nil
}

func parseAllMPtr(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("runtime.allm", reader)
	if err != nil {
		return 0, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	addr, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(addr), nil
}

func (dbp *DebuggedProcess) PrintGoroutinesInfo() error {
	data, err := dbp.Executable.DWARF()
	if err != nil {
		return err
	}
	reader := data.Reader()

	allglen, err := allglenval(dbp, reader)
	if err != nil {
		return err
	}
	reader.Seek(0)
	goidoffset, err := parsegoidoffset(dbp, reader)
	if err != nil {
		return err
	}
	reader.Seek(0)
	lockedmoffset, err := parselockedmoffset(dbp, reader)
	if err != nil {
		return err
	}
	reader.Seek(0)
	schedoffset, err := parseschedoffset(dbp, reader)
	if err != nil {
		return err
	}
	reader.Seek(0)
	allgentryaddr, err := allgentryptr(dbp, reader)
	if err != nil {
		return err
	}
	reader.Seek(0)
	statusoffset, err := parsestatusoffset(dbp, reader)
	if err != nil {
		return err
	}

	fmt.Printf("[%d goroutines]\n", allglen)
	faddr, err := dbp.CurrentThread.readMemory(uintptr(allgentryaddr), 8)
	allg := binary.LittleEndian.Uint64(faddr)

	for i := uint64(0); i < allglen; i++ {
		g, err := parseGoroutineInfo(dbp, allg+(i*8), goidoffset, schedoffset, statusoffset, lockedmoffset)
		if err != nil {
			return err
		}
		printGoroutineInfo(g)
	}

	return nil
}

func parseGoroutineInfo(dbp *DebuggedProcess, addr uint64, goidoffset, schedoffset, statusoffset, lockedmoffset uint64) (*G, error) {
	var fnstr string

	gaddrbytes, err := dbp.CurrentThread.readMemory(uintptr(addr), 8)
	if err != nil {
		return nil, fmt.Errorf("error derefing *G %s", err)
	}
	gaddr := binary.LittleEndian.Uint64(gaddrbytes)

	goidbytes, err := dbp.CurrentThread.readMemory(uintptr(gaddr+goidoffset), 8)
	if err != nil {
		return nil, fmt.Errorf("error reading goid %s", err)
	}
	lockedmbytes, err := dbp.CurrentThread.readMemory(uintptr(gaddr+lockedmoffset), 8)
	if err != nil {
		return nil, fmt.Errorf("error reading goid %s", err)
	}
	statusbytes, err := dbp.CurrentThread.readMemory(uintptr(gaddr+statusoffset), 8)
	if err != nil {
		return nil, fmt.Errorf("error reading status %s", err)
	}
	schedbytes, err := dbp.CurrentThread.readMemory(uintptr(gaddr+schedoffset+8), 8)
	if err != nil {
		return nil, fmt.Errorf("error reading goid %s", err)
	}
	gopc := binary.LittleEndian.Uint64(schedbytes)
	f, l, fn := dbp.GoSymTable.PCToLine(gopc)

	if fn != nil {
		fnstr = fn.Name
	}

	return &G{
		goid:    binary.LittleEndian.Uint64(goidbytes),
		pc:      gopc,
		status:  binary.LittleEndian.Uint16(statusbytes),
		file:    f,
		line:    l,
		fn:      fnstr,
		lockedm: uintptr(binary.LittleEndian.Uint64(lockedmbytes)),
	}, nil
}

func printGoroutineInfo(g *G) error {
	fmt.Printf("Goroutine %d (%d) %#v - (lockedm: %#v) %s:%d %s\n", g.goid, g.status, g.pc, g.lockedm, g.file, g.line, g.fn)
	return nil
}

func allglenval(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("runtime.allglen", reader)
	if err != nil {
		return 0, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	addr, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}
	val, err := dbp.CurrentThread.readMemory(uintptr(addr), 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(val), nil
}

func allgentryptr(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("runtime.allg", reader)
	if err != nil {
		return 0, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	addr, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(addr), nil
}

func parselockedmoffset(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("lockedm", reader)
	if err != nil {
		return 0, err
	}
	instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	offset, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(offset), nil
}

func parsestatusoffset(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("status", reader)
	if err != nil {
		return 0, err
	}
	instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	offset, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(offset), nil
}

func parsegoidoffset(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("goid", reader)
	if err != nil {
		return 0, err
	}
	instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	offset, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(offset), nil
}

func parseschedoffset(dbp *DebuggedProcess, reader *dwarf.Reader) (uint64, error) {
	entry, err := findDwarfEntry("sched", reader)
	if err != nil {
		return 0, err
	}
	instructions, ok := entry.Val(dwarf.AttrDataMemberLoc).([]byte)
	if !ok {
		return 0, fmt.Errorf("type assertion failed")
	}
	offset, err := op.ExecuteStackProgram(0, instructions)
	if err != nil {
		return 0, err
	}

	return uint64(offset), nil
}

// Returns the value of the named symbol.
func (thread *ThreadContext) EvalSymbol(name string) (*Variable, error) {
	data, err := thread.Process.Executable.DWARF()
	if err != nil {
		return nil, err
	}

	pc, err := thread.CurrentPC()
	if err != nil {
		return nil, err
	}
	fn := thread.Process.GoSymTable.PCToFunc(pc)
	if fn == nil {
		return nil, fmt.Errorf("could not func function scope")
	}
	reader := data.Reader()
	err = findFunction(fn.Name, reader)

	entry, err := findDwarfEntry(name, reader)
	if err != nil {
		return nil, err
	}

	offset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return nil, fmt.Errorf("type assertion failed")
	}

	t, err := data.Type(offset)
	if err != nil {
		return nil, err
	}

	instructions, ok := entry.Val(dwarf.AttrLocation).([]byte)
	if !ok {
		return nil, fmt.Errorf("type assertion failed")
	}

	val, err := thread.extractValue(instructions, 0, t)
	if err != nil {
		return nil, err
	}

	return &Variable{Name: name, Type: t.String(), Value: val}, nil
}

// findFunction is basically used to seek the dwarf.Reader to
// the function entry that represents our current scope. From there
// we can find the first child entry that matches the var name and
// use it to determine the value of the variable.
func findFunction(name string, reader *dwarf.Reader) error {
	for entry, err := reader.Next(); entry != nil; entry, err = reader.Next() {
		if err != nil {
			return err
		}

		if entry.Tag != dwarf.TagSubprogram {
			continue
		}

		n, ok := entry.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}

		if n == name {
			break
		}
	}

	return nil
}

func findDwarfEntry(name string, reader *dwarf.Reader) (*dwarf.Entry, error) {
	for entry, err := reader.Next(); entry != nil; entry, err = reader.Next() {
		if err != nil {
			return nil, err
		}

		if entry.Tag != dwarf.TagStructType && entry.Tag != dwarf.TagVariable && entry.Tag != dwarf.TagFormalParameter && entry.Tag != dwarf.TagMember {
			continue
		}

		n, ok := entry.Val(dwarf.AttrName).(string)
		if !ok || n != name {
			continue
		}
		return entry, nil
	}
	return nil, fmt.Errorf("could not find symbol value for %s", name)
}

// Extracts the value from the instructions given in the DW_AT_location entry.
// We execute the stack program described in the DW_OP_* instruction stream, and
// then grab the value from the other processes memory.
func (thread *ThreadContext) extractValue(instructions []byte, off int64, typ interface{}) (string, error) {
	regs, err := thread.Registers()
	if err != nil {
		return "", err
	}

	fde, err := thread.Process.FrameEntries.FDEForPC(regs.PC())
	if err != nil {
		return "", err
	}

	fctx := fde.EstablishFrame(regs.PC())
	cfaOffset := fctx.CFAOffset()

	offset := off
	if off == 0 {
		offset, err = op.ExecuteStackProgram(cfaOffset, instructions)
		if err != nil {
			return "", err
		}
		offset = int64(regs.Rsp) + offset
	}

	// If we have a user defined type, find the
	// underlying concrete type and use that.
	if tt, ok := typ.(*dwarf.TypedefType); ok {
		typ = tt.Type
	}

	offaddr := uintptr(offset)
	switch t := typ.(type) {
	case *dwarf.PtrType:
		addr, err := thread.readMemory(offaddr, 8)
		if err != nil {
			return "", err
		}
		adr := binary.LittleEndian.Uint64(addr)
		val, err := thread.extractValue(nil, int64(adr), t.Type)
		if err != nil {
			return "", err
		}

		retstr := fmt.Sprintf("*%s", val)
		return retstr, nil
	case *dwarf.StructType:
		switch t.StructName {
		case "string":
			return thread.readString(offaddr)
		case "[]int":
			return thread.readIntSlice(offaddr)
		default:
			// Recursively call extractValue to grab
			// the value of all the members of the struct.
			fields := make([]string, 0, len(t.Field))
			for _, field := range t.Field {
				val, err := thread.extractValue(nil, field.ByteOffset+offset, field.Type)
				if err != nil {
					return "", err
				}

				fields = append(fields, fmt.Sprintf("%s: %s", field.Name, val))
			}
			retstr := fmt.Sprintf("%s {%s}", t.StructName, strings.Join(fields, ", "))
			return retstr, nil
		}
	case *dwarf.ArrayType:
		return thread.readIntArray(offaddr, t)
	case *dwarf.IntType:
		return thread.readInt(offaddr, t.ByteSize)
	case *dwarf.FloatType:
		return thread.readFloat(offaddr, t.ByteSize)
	}

	return "", fmt.Errorf("could not find value for type %s", typ)
}

func (thread *ThreadContext) readString(addr uintptr) (string, error) {
	val, err := thread.readMemory(addr, 8)
	if err != nil {
		return "", err
	}

	// deref the pointer to the string
	addr = uintptr(binary.LittleEndian.Uint64(val))
	val, err = thread.readMemory(addr, 16)
	if err != nil {
		return "", err
	}

	i := bytes.IndexByte(val, 0x0)
	val = val[:i]
	return *(*string)(unsafe.Pointer(&val)), nil
}

func (thread *ThreadContext) readIntSlice(addr uintptr) (string, error) {
	var number uint64

	val, err := thread.readMemory(addr, uintptr(24))
	if err != nil {
		return "", err
	}

	a := binary.LittleEndian.Uint64(val[:8])
	l := binary.LittleEndian.Uint64(val[8:16])
	c := binary.LittleEndian.Uint64(val[16:24])

	val, err = thread.readMemory(uintptr(a), uintptr(8*l))
	if err != nil {
		return "", err
	}

	members := make([]uint64, 0, l)
	buf := bytes.NewBuffer(val)
	for {
		err := binary.Read(buf, binary.LittleEndian, &number)
		if err != nil {
			break
		}

		members = append(members, number)
	}

	return fmt.Sprintf("len: %d cap: %d %d", l, c, members), nil
}

func (thread *ThreadContext) readIntArray(addr uintptr, t *dwarf.ArrayType) (string, error) {
	var (
		number  uint64
		members = make([]uint64, 0, t.ByteSize)
	)

	val, err := thread.readMemory(addr, uintptr(t.ByteSize))
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(val)
	for {
		err := binary.Read(buf, binary.LittleEndian, &number)
		if err != nil {
			break
		}

		members = append(members, number)
	}

	return fmt.Sprintf("[%d]int %d", t.ByteSize/8, members), nil
}

func (thread *ThreadContext) readInt(addr uintptr, size int64) (string, error) {
	var n int

	val, err := thread.readMemory(addr, uintptr(size))
	if err != nil {
		return "", err
	}

	switch size {
	case 1:
		n = int(val[0])
	case 2:
		n = int(binary.LittleEndian.Uint16(val))
	case 4:
		n = int(binary.LittleEndian.Uint32(val))
	case 8:
		n = int(binary.LittleEndian.Uint64(val))
	}

	return strconv.Itoa(n), nil
}

func (thread *ThreadContext) readFloat(addr uintptr, size int64) (string, error) {
	val, err := thread.readMemory(addr, uintptr(size))
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(val)

	switch size {
	case 4:
		n := float32(0)
		binary.Read(buf, binary.LittleEndian, &n)
		return strconv.FormatFloat(float64(n), 'f', -1, int(size)*8), nil
	case 8:
		n := float64(0)
		binary.Read(buf, binary.LittleEndian, &n)
		return strconv.FormatFloat(n, 'f', -1, int(size)*8), nil
	}

	return "", fmt.Errorf("could not read float")
}

func (thread *ThreadContext) readMemory(addr uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)

	_, err := syscall.PtracePeekData(thread.Id, addr, buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
