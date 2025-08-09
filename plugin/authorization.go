package plugin

import (
    "context"

    "github.com/casbin/casbin/v2"
    "github.com/hashicorp/go-hclog"
)

// Authorizer wraps Casbin enforcer with simple helpers
type Authorizer struct {
    logger   hclog.Logger
    enforcer *casbin.Enforcer
}

func NewAuthorizer(logger hclog.Logger, modelPath, policyPath string) (*Authorizer, error) {
    e, err := casbin.NewEnforcer(modelPath, policyPath)
    if err != nil {
        return nil, err
    }
    return &Authorizer{logger: logger, enforcer: e}, nil
}

// AuthorizeConnect checks if user can connect to database
func (a *Authorizer) AuthorizeConnect(ctx context.Context, username, database string) (bool, string) {
    if a == nil || a.enforcer == nil || modelPathOrPolicyEmpty(a.enforcer) {
        return true, "no authorizer configured"
    }
    ok, err := a.enforcer.Enforce(username, database, "connect")
    if err != nil {
        a.logger.Error("authorization error", "error", err)
        return false, "authorization error"
    }
    if !ok {
        return false, "not permitted"
    }
    return true, ""
}

func modelPathOrPolicyEmpty(e *casbin.Enforcer) bool {
    return e == nil || e.GetModel() == nil
}
