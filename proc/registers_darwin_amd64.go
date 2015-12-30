package proc

// #include "threads_darwin.h"
import "C"
import (
	"bytes"
	"fmt"
)

type Regs struct {
	rax     uint64
	rbx     uint64
	rcx     uint64
	rdx     uint64
	rdi     uint64
	rsi     uint64
	rbp     uint64
	rsp     uint64
	r8      uint64
	r9      uint64
	r10     uint64
	r11     uint64
	r12     uint64
	r13     uint64
	r14     uint64
	r15     uint64
	rip     uint64
	rflags  uint64
	cs      uint64
	fs      uint64
	gs      uint64
	gs_base uint64
}

func (r *Regs) String() string {
	var buf bytes.Buffer
	var regs = []struct {
		k string
		v uint64
	}{
		{"Rip", r.rip},
		{"Rsp", r.rsp},
		{"Rax", r.rax},
		{"Rbx", r.rbx},
		{"Rcx", r.rcx},
		{"Rdx", r.rdx},
		{"Rdi", r.rdi},
		{"Rsi", r.rsi},
		{"Rbp", r.rbp},
		{"R8", r.r8},
		{"R9", r.r9},
		{"R10", r.r10},
		{"R11", r.r11},
		{"R12", r.r12},
		{"R13", r.r13},
		{"R14", r.r14},
		{"R15", r.r15},
		{"Rflags", r.rflags},
		{"Cs", r.cs},
		{"Fs", r.fs},
		{"Gs", r.gs},
		{"Gs_base", r.gs_base},
	}
	for _, reg := range regs {
		fmt.Fprintf(&buf, "%8s = %0#16x\n", reg.k, reg.v)
	}
	return buf.String()
}

func (r *Regs) PC() uint64 {
	return r.rip
}

func (r *Regs) SP() uint64 {
	return r.rsp
}

func (r *Regs) CX() uint64 {
	return r.rcx
}

func (r *Regs) TLS() uint64 {
	return r.gs_base
}

func (r *Regs) SetPC(thread *Thread, pc uint64) error {
	kret := C.set_pc(thread.os.thread_act, C.uint64_t(pc))
	if kret != C.KERN_SUCCESS {
		return fmt.Errorf("could not set pc")
	}
	return nil
}

func registers(thread *Thread) (Registers, error) {
	var state C.x86_thread_state64_t
	var identity C.thread_identifier_info_data_t
	kret := C.get_registers(C.mach_port_name_t(thread.os.thread_act), &state)
	if kret != C.KERN_SUCCESS {
		return nil, fmt.Errorf("could not get registers")
	}
	kret = C.get_identity(C.mach_port_name_t(thread.os.thread_act), &identity)
	if kret != C.KERN_SUCCESS {
		return nil, fmt.Errorf("could not get thread identity informations")
	}
	/*
		thread_identifier_info::thread_handle contains the base of the
		thread-specific data area, which on x86 and x86_64 is the thread’s base
		address of the %gs segment. 10.9.2 xnu-2422.90.20/osfmk/kern/thread.c
		thread_info_internal() gets the value from
		machine_thread::cthread_self, which is the same value used to set the
		%gs base in xnu-2422.90.20/osfmk/i386/pcb_native.c
		act_machine_switch_pcb().
		--
		comment copied from chromium's crashpad
		https://chromium.googlesource.com/crashpad/crashpad/+/master/snapshot/mac/process_reader.cc
	*/
	regs := &Regs{
		rax:     uint64(state.__rax),
		rbx:     uint64(state.__rbx),
		rcx:     uint64(state.__rcx),
		rdx:     uint64(state.__rdx),
		rdi:     uint64(state.__rdi),
		rsi:     uint64(state.__rsi),
		rbp:     uint64(state.__rbp),
		rsp:     uint64(state.__rsp),
		r8:      uint64(state.__r8),
		r9:      uint64(state.__r9),
		r10:     uint64(state.__r10),
		r11:     uint64(state.__r11),
		r12:     uint64(state.__r12),
		r13:     uint64(state.__r13),
		r14:     uint64(state.__r14),
		r15:     uint64(state.__r15),
		rip:     uint64(state.__rip),
		rflags:  uint64(state.__rflags),
		cs:      uint64(state.__cs),
		fs:      uint64(state.__fs),
		gs:      uint64(state.__gs),
		gs_base: uint64(identity.thread_handle),
	}
	return regs, nil
}

func (thread *Thread) saveRegisters() (Registers, error) {
	kret := C.get_registers(C.mach_port_name_t(thread.os.thread_act), &thread.os.registers)
	if kret != C.KERN_SUCCESS {
		return nil, fmt.Errorf("could not save register contents")
	}
	return &Regs{rip: uint64(thread.os.registers.__rip), rsp: uint64(thread.os.registers.__rsp)}, nil
}

func (thread *Thread) restoreRegisters() error {
	kret := C.set_registers(C.mach_port_name_t(thread.os.thread_act), &thread.os.registers)
	if kret != C.KERN_SUCCESS {
		return fmt.Errorf("could not save register contents")
	}
	return nil
}
