package rpc

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	grpc "net/rpc"
	"net/rpc/jsonrpc"

	"github.com/derekparker/delve/service"
	"github.com/derekparker/delve/service/api"
	"github.com/derekparker/delve/service/debugger"
)

type RPCServer struct {
	// config is all the information necessary to start the debugger and server.
	config *service.Config
	// listener is used to serve HTTP.
	listener net.Listener
	// debugger is a debugger service.
	debugger *debugger.Debugger
}

// NewServer creates a new RPCServer.
func NewServer(config *service.Config, logEnabled bool) *RPCServer {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	if !logEnabled {
		log.SetOutput(ioutil.Discard)
	}

	return &RPCServer{
		config:   config,
		listener: config.Listener,
	}
}

// Stop detaches from the debugger and waits for it to stop.
func (s *RPCServer) Stop(kill bool) error {
	return s.debugger.Detach(kill)
}

// Run starts a debugger and exposes it with an HTTP server. The debugger
// itself can be stopped with the `detach` API. Run blocks until the HTTP
// server stops.
func (s *RPCServer) Run() error {
	var err error
	// Create and start the debugger
	if s.debugger, err = debugger.New(&debugger.Config{
		ProcessArgs: s.config.ProcessArgs,
		AttachPid:   s.config.AttachPid,
	}); err != nil {
		return err
	}

	go func() {
		c, err := s.listener.Accept()
		if err != nil {
			panic(err)
		}

		rpcs := grpc.NewServer()
		rpcs.Register(s)
		rpcs.ServeCodec(jsonrpc.NewServerCodec(c))
	}()
	return nil
}

func (s *RPCServer) ProcessPid(arg1 interface{}, pid *int) error {
	*pid = s.debugger.ProcessPid()
	return nil
}

func (s *RPCServer) Detach(kill bool, ret *int) error {
	return s.debugger.Detach(kill)
}

func (s *RPCServer) Restart(arg1 interface{}, arg2 *int) error {
	if s.config.AttachPid != 0 {
		return errors.New("cannot restart process Delve did not create")
	}
	return s.debugger.Restart()
}

func (s *RPCServer) State(arg interface{}, state *api.DebuggerState) error {
	st, err := s.debugger.State()
	if err != nil {
		return err
	}
	*state = *st
	return nil
}

func (s *RPCServer) Command(command *api.DebuggerCommand, state *api.DebuggerState) error {
	st, err := s.debugger.Command(command)
	if err != nil {
		return err
	}
	*state = *st
	return nil
}

func (s *RPCServer) GetBreakpoint(id int, breakpoint *api.Breakpoint) error {
	bp := s.debugger.FindBreakpoint(id)
	if bp == nil {
		return fmt.Errorf("no breakpoint with id %d", id)
	}
	*breakpoint = *bp
	return nil
}

type StacktraceGoroutineArgs struct {
	Id    int
	Depth int
	Full  bool
}

func (s *RPCServer) StacktraceGoroutine(args *StacktraceGoroutineArgs, locations *[]api.Stackframe) error {
	locs, err := s.debugger.Stacktrace(args.Id, args.Depth, args.Full)
	if err != nil {
		return err
	}
	*locations = locs
	return nil
}

func (s *RPCServer) ListBreakpoints(arg interface{}, breakpoints *[]*api.Breakpoint) error {
	*breakpoints = s.debugger.Breakpoints()
	return nil
}

func (s *RPCServer) CreateBreakpoint(bp, newBreakpoint *api.Breakpoint) error {
	createdbp, err := s.debugger.CreateBreakpoint(bp)
	if err != nil {
		return err
	}
	*newBreakpoint = *createdbp
	return nil
}

func (s *RPCServer) ClearBreakpoint(id int, breakpoint *api.Breakpoint) error {
	bp := s.debugger.FindBreakpoint(id)
	if bp == nil {
		return fmt.Errorf("no breakpoint with id %d", id)
	}
	deleted, err := s.debugger.ClearBreakpoint(bp)
	if err != nil {
		return err
	}
	*breakpoint = *deleted
	return nil
}

func (s *RPCServer) ListThreads(arg interface{}, threads *[]*api.Thread) error {
	*threads = s.debugger.Threads()
	return nil
}

func (s *RPCServer) GetThread(id int, thread *api.Thread) error {
	t := s.debugger.FindThread(id)
	if t == nil {
		return fmt.Errorf("no thread with id %d", id)
	}
	*thread = *t
	return nil
}

func (s *RPCServer) ListPackageVars(filter string, variables *[]api.Variable) error {
	state, err := s.debugger.State()
	if err != nil {
		return err
	}

	current := state.CurrentThread
	if current == nil {
		return fmt.Errorf("no current thread")
	}

	vars, err := s.debugger.PackageVariables(current.ID, filter)
	if err != nil {
		return err
	}
	*variables = vars
	return nil
}

type ThreadListArgs struct {
	Id     int
	Filter string
}

func (s *RPCServer) ListThreadPackageVars(args *ThreadListArgs, variables *[]api.Variable) error {
	if thread := s.debugger.FindThread(args.Id); thread == nil {
		return fmt.Errorf("no thread with id %d", args.Id)
	}

	vars, err := s.debugger.PackageVariables(args.Id, args.Filter)
	if err != nil {
		return err
	}
	*variables = vars
	return nil
}

func (s *RPCServer) ListRegisters(arg interface{}, registers *string) error {
	state, err := s.debugger.State()
	if err != nil {
		return err
	}

	regs, err := s.debugger.Registers(state.CurrentThread.ID)
	if err != nil {
		return err
	}
	*registers = regs
	return nil
}

func (s *RPCServer) ListLocalVars(scope api.EvalScope, variables *[]api.Variable) error {
	vars, err := s.debugger.LocalVariables(scope)
	if err != nil {
		return err
	}
	*variables = vars
	return nil
}

func (s *RPCServer) ListFunctionArgs(scope api.EvalScope, variables *[]api.Variable) error {
	vars, err := s.debugger.FunctionArguments(scope)
	if err != nil {
		return err
	}
	*variables = vars
	return nil
}

type EvalSymbolArgs struct {
	Scope  api.EvalScope
	Symbol string
}

func (s *RPCServer) EvalSymbol(args EvalSymbolArgs, variable *api.Variable) error {
	v, err := s.debugger.EvalVariableInScope(args.Scope, args.Symbol)
	if err != nil {
		return err
	}
	*variable = *v
	return nil
}

type SetSymbolArgs struct {
	Scope  api.EvalScope
	Symbol string
	Value  string
}

func (s *RPCServer) SetSymbol(args SetSymbolArgs, unused *int) error {
	*unused = 0
	return s.debugger.SetVariableInScope(args.Scope, args.Symbol, args.Value)
}

func (s *RPCServer) ListSources(filter string, sources *[]string) error {
	ss, err := s.debugger.Sources(filter)
	if err != nil {
		return err
	}
	*sources = ss
	return nil
}

func (s *RPCServer) ListFunctions(filter string, funcs *[]string) error {
	fns, err := s.debugger.Functions(filter)
	if err != nil {
		return err
	}
	*funcs = fns
	return nil
}

func (s *RPCServer) ListGoroutines(arg interface{}, goroutines *[]*api.Goroutine) error {
	gs, err := s.debugger.Goroutines()
	if err != nil {
		return err
	}
	*goroutines = gs
	return nil
}

func (c *RPCServer) AttachedToExistingProcess(arg interface{}, answer *bool) error {
	if c.config.AttachPid != 0 {
		*answer = true
	}
	return nil
}

type FindLocationArgs struct {
	Scope api.EvalScope
	Loc   string
}

func (c *RPCServer) FindLocation(args FindLocationArgs, answer *[]api.Location) error {
	var err error
	*answer, err = c.debugger.FindLocation(args.Scope, args.Loc)
	return err
}
