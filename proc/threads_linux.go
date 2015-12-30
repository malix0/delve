package proc

import (
	"fmt"

	sys "golang.org/x/sys/unix"
)

// Not actually used, but necessary
// to be defined.
type OSSpecificDetails struct {
	registers sys.PtraceRegs
}

func (t *Thread) halt() (err error) {
	err = sys.Tgkill(t.dbp.Pid, t.Id, sys.SIGSTOP)
	if err != nil {
		err = fmt.Errorf("halt err %s on thread %d", err, t.Id)
		return
	}
	_, _, err = t.dbp.wait(t.Id, 0)
	if err != nil {
		err = fmt.Errorf("wait err %s on thread %d", err, t.Id)
		return
	}
	return
}

func (thread *Thread) stopped() bool {
	state := status(thread.Id, thread.dbp.os.comm)
	return state == STATUS_TRACE_STOP
}

func (t *Thread) resume() (err error) {
	t.running = true
	t.dbp.execPtraceFunc(func() { err = PtraceCont(t.Id, 0) })
	return
}

func (t *Thread) singleStep() (err error) {
	t.dbp.execPtraceFunc(func() { err = sys.PtraceSingleStep(t.Id) })
	if err != nil {
		return err
	}
	_, _, err = t.dbp.wait(t.Id, 0)
	return err
}

func (t *Thread) blocked() bool {
	pc, _ := t.PC()
	fn := t.dbp.goSymTable.PCToFunc(pc)
	if fn != nil && ((fn.Name == "runtime.futex") || (fn.Name == "runtime.usleep") || (fn.Name == "runtime.clone")) {
		return true
	}
	return false
}

func (thread *Thread) saveRegisters() (Registers, error) {
	var err error
	thread.dbp.execPtraceFunc(func() { err = sys.PtraceGetRegs(thread.Id, &thread.os.registers) })
	if err != nil {
		return nil, fmt.Errorf("could not save register contents")
	}
	return &Regs{&thread.os.registers}, nil
}

func (thread *Thread) restoreRegisters() (err error) {
	thread.dbp.execPtraceFunc(func() { err = sys.PtraceSetRegs(thread.Id, &thread.os.registers) })
	return
}

func (thread *Thread) writeMemory(addr uintptr, data []byte) (written int, err error) {
	if len(data) == 0 {
		return
	}
	thread.dbp.execPtraceFunc(func() { written, err = sys.PtracePokeData(thread.Id, addr, data) })
	return
}

func (thread *Thread) readMemory(addr uintptr, size int) (data []byte, err error) {
	if size == 0 {
		return
	}
	data = make([]byte, size)
	thread.dbp.execPtraceFunc(func() { _, err = sys.PtracePeekData(thread.Id, addr, data) })
	return
}
