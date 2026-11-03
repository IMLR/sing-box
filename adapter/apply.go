package adapter

// ApplyResult reports what applying a configuration to a running instance
// changed. When RestartRequired is not empty nothing was applied: the new
// configuration differs in a part that can only be rebuilt by a reload.
type ApplyResult struct {
	Outbounds       ApplyOutbounds `json:"outbounds"`
	RouteRules      bool           `json:"route_rules"`
	RuleSetsAdded   []string       `json:"rule_sets_added,omitempty"`
	RuleSetsRemoved []string       `json:"rule_sets_removed,omitempty"`
	Final           string         `json:"final,omitempty"`
	RestartRequired []string       `json:"restart_required,omitempty"`
}

type ApplyOutbounds struct {
	Added     []string `json:"added,omitempty"`
	Updated   []string `json:"updated,omitempty"`
	Removed   []string `json:"removed,omitempty"`
	Regrouped []string `json:"regrouped,omitempty"`
}

// Changed reports whether the apply touched anything at all.
func (r *ApplyResult) Changed() bool {
	o := r.Outbounds
	return len(o.Added)+len(o.Updated)+len(o.Removed)+len(o.Regrouped)+
		len(r.RuleSetsAdded)+len(r.RuleSetsRemoved) > 0 || r.RouteRules || r.Final != ""
}

// OutboundGroupMembers is implemented by groups whose members can be replaced
// while they run. It also rebinds every member to the outbound currently
// registered under its tag, which a group needs after a member was recreated.
type OutboundGroupMembers interface {
	UpdateMembers(tags []string, defaultTag string) error
}

// ConfigApplier applies the configuration files the process was started with
// to the running instance without restarting it.
type ConfigApplier interface {
	ApplyConfig() (*ApplyResult, error)
}
