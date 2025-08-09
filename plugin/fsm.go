package plugin

import (
	"context"

	"github.com/hashicorp/go-hclog"
	"github.com/qmuntal/stateless"
)

const (
	StateIdle = iota
	StateAuthenticating
	StateAuthenticatingFailed
	StateAuthenticatingSuccess
	StateAuthenticated
	StateFailed
)

type Event int

const (
	EventAuthenticate Event = iota
	EventAuthenticated
	EventFailed
)

func NewFSM(logger hclog.Logger) *stateless.StateMachine {
	fsm := stateless.NewStateMachine(StateIdle)

	fsm.Configure(StateIdle).Permit(EventAuthenticate, StateAuthenticating)
	fsm.Configure(StateAuthenticating).Permit(EventAuthenticate, StateAuthenticatingSuccess)
	fsm.Configure(StateAuthenticating).Permit(EventFailed, StateAuthenticatingFailed)
	fsm.Configure(StateAuthenticatingSuccess).Permit(EventAuthenticated, StateAuthenticated)
	fsm.Configure(StateAuthenticatingFailed).Permit(EventFailed, StateFailed)

	fsm.OnTransitioned(func(ctx context.Context, e stateless.Transition) {
		logger.Info("FSM transitioned", "from", e.Source, "to", e.Destination)
	})

	logger.Info("Initial FSM state", "state", fsm.MustState())

	fsm.Fire(EventAuthenticate)
	fsm.Fire(EventAuthenticated)
	fsm.Fire(EventFailed)

	logger.Info("FSM state after failed", "state", fsm.MustState())

	fsm.Fire(EventAuthenticated)

	logger.Info("FSM state after authenticated", "state", fsm.MustState())

	return fsm
}
