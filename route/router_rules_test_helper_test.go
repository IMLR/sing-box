package route

import "github.com/sagernet/sing-box/adapter"

// setRules installs rules the way an applied configuration does, for tests
// that build a Router by hand.
func (r *Router) setRules(rules []adapter.Rule) {
	r.ruleSnapshot.Store(&routeRules{rules: rules, byUUID: make(map[string]adapter.Rule)})
}
