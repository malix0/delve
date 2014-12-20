package proctl

import (
	"runtime"
	"syscall"
)

const (
	PT_ATTACH = byte(0)
	PT_DETACH = iota
	PT_STEP
	PT_CONT
	PT_GETREGS
	PT_SETREGS
	PT_PEEK
	PT_POKE
)

type ptrequst struct {
	req  byte
	tid  int
	addr uintptr
	data []byte
	regs *syscall.PtraceRegs
}

func handlePtraceRequest(reg chan *ptrequst, err chan error) {
	// We must ensure here that we are running on the same thread during
	// the execution of dbg. This is due to the fact that ptrace(2) expects
	// all commands after PTRACE_ATTACH to come from the same thread.
	runtime.LockOSThread()

	for msg := range reg {
		switch msg.req {
		case PT_ATTACH:
			err <- syscall.PtraceAttach(msg.tid)
		case PT_DETACH:
			err <- syscall.PtraceDetach(msg.tid)
		case PT_STEP:
		case PT_CONT:
			err <- syscall.PtraceCont(msg.tid, 0)
		case PT_GETREGS:
		case PT_SETREGS:
		case PT_PEEK:
		case PT_POKE:
		}
	}
}

func (dbp *DebuggedProcess) ptraceAttach(tid int) error {
	dbp.ptchan <- &ptrequst{req: PT_ATTACH, tid: tid}
	return <-dbp.pterrchan
}

func (dbp *DebuggedProcess) ptraceDetach(tid int) error {
	dbp.ptchan <- &ptrequst{req: PT_DETACH, tid: tid}
	return <-dbp.pterrchan
}

func (dbp *DebuggedProcess) ptraceCont(tid int) error {
	dbp.ptchan <- &ptrequst{req: PT_CONT, tid: tid}
	return <-dbp.pterrchan
}
