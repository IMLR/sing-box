package box

import (
	"errors"
	"reflect"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

// Apply brings a running instance to the given configuration without
// restarting it, for everything that can change in place: outbounds (nodes
// and groups), route rules, rule-set definitions and route.final.
//
// Only what changed is touched. A node whose options changed is recreated
// under its tag and every group holding it is rebound to the new instance; a
// group whose member list changed is updated in place and keeps its selection.
// Connections through untouched outbounds carry on.
//
// If any other part differs (inbounds, DNS, log, experimental, ...), nothing
// is applied and the result lists why a reload is needed.
func (s *Box) Apply(options option.Options) (*adapter.ApplyResult, error) {
	s.applyAccess.Lock()
	defer s.applyAccess.Unlock()
	result := &adapter.ApplyResult{}
	result.RestartRequired = restartReasons(s.options, options)
	if len(result.RestartRequired) > 0 {
		return result, nil
	}
	plan, err := planOutbounds(s.options.Outbounds, options.Outbounds, s.outbound)
	if err != nil {
		return nil, err
	}
	if plan.restart != "" {
		result.RestartRequired = []string{plan.restart}
		return result, nil
	}

	// Recreated selectors keep what was selected.
	previousSelection := make(map[string]string)
	for _, tag := range plan.recreate {
		if current, loaded := s.outbound.Outbound(tag); loaded {
			if group, isGroup := current.(adapter.OutboundGroup); isGroup {
				previousSelection[tag] = group.Now()
			}
		}
	}
	for _, outboundOptions := range plan.create {
		err = s.createOutbound(outboundOptions)
		if err != nil {
			return result, err
		}
	}
	for tag, selected := range previousSelection {
		current, _ := s.outbound.Outbound(tag)
		if selector, isSelector := current.(interface{ SelectOutbound(string) bool }); isSelector {
			selector.SelectOutbound(selected)
		}
	}
	for _, tag := range plan.regroup {
		current, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return result, E.New("outbound not found: ", tag)
		}
		members, defaultTag, _ := groupMembers(plan.next[tag])
		err = current.(adapter.OutboundGroupMembers).UpdateMembers(members, defaultTag)
		if err != nil {
			return result, E.Cause(err, "update members of ", tag)
		}
	}
	s.outbound.RebuildDependencies()
	result.Outbounds.Added = plan.added
	result.Outbounds.Updated = plan.updated
	result.Outbounds.Regrouped = plan.regroup

	nextRoute := common.PtrValueOrDefault(options.Route)
	currentRoute := common.PtrValueOrDefault(s.options.Route)
	if nextRoute.Final != currentRoute.Final {
		err = s.outbound.SetDefault(nextRoute.Final)
		if err != nil {
			return result, err
		}
		result.Final = nextRoute.Final
	}
	rulesChanged := !reflect.DeepEqual(nextRoute.Rules, currentRoute.Rules)
	ruleSetsChanged := !reflect.DeepEqual(nextRoute.RuleSet, currentRoute.RuleSet)
	if rulesChanged || ruleSetsChanged {
		added, removed, routeErr := s.router.ApplyRoute(nextRoute.Rules, nextRoute.RuleSet)
		if errors.Is(routeErr, route.ErrRestartRequired) {
			result.RestartRequired = []string{routeErr.Error()}
			return result, nil
		}
		if routeErr != nil {
			return result, routeErr
		}
		result.RouteRules = rulesChanged
		result.RuleSetsAdded, result.RuleSetsRemoved = added, removed
	}

	// Removed last: until the new rules are in place, old rules may still
	// route to these.
	for _, tag := range plan.remove {
		err = s.outbound.Remove(tag)
		if err != nil {
			return result, E.Cause(err, "remove outbound ", tag)
		}
	}
	result.Outbounds.Removed = plan.remove
	s.options = options
	return result, nil
}

func (s *Box) createOutbound(outboundOptions option.Outbound) error {
	tag := outboundOptions.Tag
	outboundCtx := adapter.WithContext(s.ctx, &adapter.InboundContext{Outbound: tag})
	err := s.outbound.Create(
		outboundCtx,
		s.router,
		s.logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", tag, "]")),
		tag,
		outboundOptions.Type,
		outboundOptions.Options,
	)
	if err != nil {
		return E.Cause(err, "create outbound ", tag)
	}
	return nil
}

type outboundPlan struct {
	next     map[string]option.Outbound
	create   []option.Outbound // nodes first, then groups after the groups they hold
	recreate []string          // existing tags among create
	regroup  []string
	remove   []string // groups before the nodes they hold
	added    []string
	updated  []string
	restart  string
}

func planOutbounds(current, next []option.Outbound, manager adapter.OutboundManager) (*outboundPlan, error) {
	currentByTag := make(map[string]option.Outbound, len(current))
	for _, it := range current {
		currentByTag[it.Tag] = it
	}
	plan := &outboundPlan{next: make(map[string]option.Outbound, len(next))}
	for i, it := range next {
		if it.Tag == "" {
			return &outboundPlan{restart: F.ToString("outbound[", i, "] has no tag")}, nil
		}
		if _, duplicate := plan.next[it.Tag]; duplicate {
			return nil, E.New("duplicate outbound tag: ", it.Tag)
		}
		plan.next[it.Tag] = it
	}

	recreate := make(map[string]bool)
	regroup := make(map[string]bool)
	for _, it := range next {
		previous, existed := currentByTag[it.Tag]
		switch {
		case !existed:
			plan.added = append(plan.added, it.Tag)
		case previous.Type != it.Type:
			recreate[it.Tag] = true
		case reflect.DeepEqual(previous.Options, it.Options):
		case sameExceptMembers(previous, it) && supportsMembers(manager, it.Tag):
			regroup[it.Tag] = true
		default:
			recreate[it.Tag] = true
		}
	}
	for _, it := range current {
		if _, kept := plan.next[it.Tag]; !kept {
			plan.remove = append(plan.remove, it.Tag)
		}
	}

	// A group still holding the old instance of a recreated or removed member
	// has to be rebound, and recreating it means its own holders follow.
	gone := make(map[string]bool)
	for tag := range recreate {
		gone[tag] = true
	}
	for _, tag := range plan.remove {
		gone[tag] = true
	}
	for changed := true; changed; {
		changed = false
		for _, it := range next {
			members, _, isGroup := groupMembers(it)
			if !isGroup || recreate[it.Tag] || regroup[it.Tag] || !holdsAny(members, gone) {
				continue
			}
			if _, existed := currentByTag[it.Tag]; !existed {
				continue
			}
			if supportsMembers(manager, it.Tag) {
				regroup[it.Tag] = true
			} else {
				recreate[it.Tag] = true
				gone[it.Tag] = true
				changed = true
			}
		}
	}

	var groups []option.Outbound
	for _, it := range next {
		_, existed := currentByTag[it.Tag]
		if existed && !recreate[it.Tag] {
			continue
		}
		if existed {
			plan.updated = append(plan.updated, it.Tag)
			plan.recreate = append(plan.recreate, it.Tag)
		}
		if _, _, isGroup := groupMembers(it); isGroup {
			groups = append(groups, it)
		} else {
			plan.create = append(plan.create, it)
		}
	}
	ordered, err := orderGroups(groups)
	if err != nil {
		return nil, err
	}
	plan.create = append(plan.create, ordered...)
	for _, it := range next {
		if regroup[it.Tag] {
			plan.regroup = append(plan.regroup, it.Tag)
		}
	}
	plan.remove = orderRemoval(plan.remove, currentByTag)
	return plan, nil
}

// orderGroups puts every group after the groups it holds that are created in
// the same apply, since a group resolves its members when it starts.
func orderGroups(groups []option.Outbound) ([]option.Outbound, error) {
	pending := make(map[string]bool, len(groups))
	for _, it := range groups {
		pending[it.Tag] = true
	}
	ordered := make([]option.Outbound, 0, len(groups))
	for len(ordered) < len(groups) {
		progressed := false
		for _, it := range groups {
			if !pending[it.Tag] {
				continue
			}
			members, _, _ := groupMembers(it)
			if holdsAny(members, pending) {
				continue
			}
			ordered = append(ordered, it)
			delete(pending, it.Tag)
			progressed = true
		}
		if !progressed {
			var cycle []string
			for tag := range pending {
				cycle = append(cycle, tag)
			}
			return nil, E.New("circular outbound groups: ", strings.Join(cycle, ", "))
		}
	}
	return ordered, nil
}

// orderRemoval removes groups before what they hold.
func orderRemoval(tags []string, byTag map[string]option.Outbound) []string {
	var groups, nodes []string
	for _, tag := range tags {
		if _, _, isGroup := groupMembers(byTag[tag]); isGroup {
			groups = append(groups, tag)
		} else {
			nodes = append(nodes, tag)
		}
	}
	return append(groups, nodes...)
}

func groupMembers(it option.Outbound) (members []string, defaultTag string, isGroup bool) {
	switch options := it.Options.(type) {
	case *option.SelectorOutboundOptions:
		return options.Outbounds, options.Default, true
	case *option.URLTestOutboundOptions:
		return options.Outbounds, "", true
	case *option.LoadBalanceOutboundOptions:
		return options.Outbounds, "", true
	}
	return nil, "", false
}

// sameExceptMembers reports a group change limited to its member list and,
// for a selector, its default.
func sameExceptMembers(previous, next option.Outbound) bool {
	switch a := previous.Options.(type) {
	case *option.SelectorOutboundOptions:
		b, ok := next.Options.(*option.SelectorOutboundOptions)
		if !ok {
			return false
		}
		x, y := *a, *b
		x.Outbounds, y.Outbounds, x.Default, y.Default = nil, nil, "", ""
		return reflect.DeepEqual(x, y)
	case *option.URLTestOutboundOptions:
		b, ok := next.Options.(*option.URLTestOutboundOptions)
		if !ok {
			return false
		}
		x, y := *a, *b
		x.Outbounds, y.Outbounds = nil, nil
		return reflect.DeepEqual(x, y)
	}
	return false
}

func supportsMembers(manager adapter.OutboundManager, tag string) bool {
	current, loaded := manager.Outbound(tag)
	if !loaded {
		return false
	}
	_, supported := current.(adapter.OutboundGroupMembers)
	return supported
}

func holdsAny(members []string, tags map[string]bool) bool {
	for _, member := range members {
		if tags[member] {
			return true
		}
	}
	return false
}

// restartReasons lists the parts of the configuration that differ and cannot
// be changed in a running instance.
func restartReasons(current, next option.Options) []string {
	var reasons []string
	differs := func(name string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			reasons = append(reasons, name+" changed")
		}
	}
	differs("log", current.Log, next.Log)
	differs("dns", current.DNS, next.DNS)
	differs("ntp", current.NTP, next.NTP)
	differs("certificate", current.Certificate, next.Certificate)
	differs("certificate_providers", current.CertificateProviders, next.CertificateProviders)
	differs("http_clients", current.HTTPClients, next.HTTPClients)
	differs("network_namespaces", current.NetworkNamespaces, next.NetworkNamespaces)
	differs("endpoints", current.Endpoints, next.Endpoints)
	differs("inbounds", current.Inbounds, next.Inbounds)
	differs("providers", current.Providers, next.Providers)
	differs("services", current.Services, next.Services)
	differs("experimental", current.Experimental, next.Experimental)
	currentRoute := common.PtrValueOrDefault(current.Route)
	nextRoute := common.PtrValueOrDefault(next.Route)
	currentRest, nextRest := currentRoute, nextRoute
	currentRest.Rules, currentRest.RuleSet, currentRest.Final = nil, nil, ""
	nextRest.Rules, nextRest.RuleSet, nextRest.Final = nil, nil, ""
	differs("route options other than rules, rule_set and final", currentRest, nextRest)

	// Rule sets read by DNS rules or by a TUN inbound are wired in at start.
	pinned := pinnedRuleSets(current)
	currentSets := ruleSetsByTag(currentRoute.RuleSet)
	nextSets := ruleSetsByTag(nextRoute.RuleSet)
	for tag := range pinned {
		if !reflect.DeepEqual(currentSets[tag], nextSets[tag]) {
			reasons = append(reasons, "rule-set "+tag+" is used by DNS or TUN and changed")
		}
	}
	return reasons
}

func ruleSetsByTag(ruleSets []option.RuleSet) map[string]option.RuleSet {
	byTag := make(map[string]option.RuleSet)
	for _, it := range ruleSets {
		for _, tag := range it.Tag {
			byTag[tag] = it
		}
	}
	return byTag
}

func pinnedRuleSets(options option.Options) map[string]bool {
	tags := make(map[string]bool)
	var walk func([]option.DNSRule)
	walk = func(rules []option.DNSRule) {
		for _, rule := range rules {
			switch rule.Type {
			case C.RuleTypeDefault:
				for _, tag := range rule.DefaultOptions.RuleSet {
					tags[tag] = true
				}
			case C.RuleTypeLogical:
				walk(rule.LogicalOptions.Rules)
			}
		}
	}
	walk(common.PtrValueOrDefault(options.DNS).Rules)
	for _, inbound := range options.Inbounds {
		if tun, isTun := inbound.Options.(*option.TunInboundOptions); isTun {
			for _, tag := range tun.RouteAddressSet {
				tags[tag] = true
			}
			for _, tag := range tun.RouteExcludeAddressSet {
				tags[tag] = true
			}
		}
	}
	return tags
}
