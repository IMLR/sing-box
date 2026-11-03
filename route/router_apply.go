package route

import (
	"errors"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

// ErrRestartRequired marks a change the running router cannot take in place.
var ErrRestartRequired = errors.New("restart required")

// ruleRetireDelay is how long replaced rules stay open after a swap. A match
// in progress keeps iterating the slice it started with, and closing a rule
// releases the rule sets it holds, so the old rules outlive any match that
// could still be using them.
var ruleRetireDelay = 30 * time.Second

// routeRules is one generation of route rules. Matching reads the current
// generation once and iterates it; applying a configuration swaps in a new
// generation as a whole, so a match never sees a half-replaced list.
type routeRules struct {
	rules  []adapter.Rule
	byUUID map[string]adapter.Rule
}

func (r *Router) loadRules() []adapter.Rule {
	snapshot := r.ruleSnapshot.Load()
	if snapshot == nil {
		return nil
	}
	return snapshot.rules
}

func (r *Router) newRouteRules(options []option.Rule) (*routeRules, error) {
	snapshot := &routeRules{
		rules:  make([]adapter.Rule, 0, len(options)),
		byUUID: make(map[string]adapter.Rule, len(options)),
	}
	for i, ruleOptions := range options {
		err := R.ValidateNoNestedRuleActions(ruleOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		rule, err := R.NewRule(r.ctx, r.logger, ruleOptions, false)
		if err != nil {
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		snapshot.rules = append(snapshot.rules, rule)
		snapshot.byUUID[rule.UUID()] = rule
	}
	return snapshot, nil
}

type refCounter interface {
	RefCount() int32
}

// ApplyRoute replaces the route rules and rule-set definitions of a running
// router. Rule sets whose definition did not change are kept, so their content
// and file watches carry on; added or changed ones are started before any rule
// refers to them. The new rules are built and started completely before they
// replace the old ones in one swap. On any failure the router is left as it
// was.
func (r *Router) ApplyRoute(rules []option.Rule, ruleSets []option.RuleSet) (added []string, removed []string, err error) {
	if !r.needFindProcess && hasRule(rules, isProcessRule) {
		return nil, nil, E.Extend(ErrRestartRequired, "process rules need a process searcher, which only starts with the router")
	}
	if !r.needFindNeighbor && hasRule(rules, isNeighborRule) {
		return nil, nil, E.Extend(ErrRestartRequired, "neighbor rules need a neighbor resolver, which only starts with the router")
	}

	newOptions := make(map[string]option.RuleSet)
	var order []string
	for _, definition := range ruleSets {
		for _, tag := range definition.Tag {
			if _, exists := newOptions[tag]; exists {
				return nil, nil, E.New("duplicate rule-set tag: ", tag)
			}
			newOptions[tag] = definition
			order = append(order, tag)
		}
	}
	referenced := ruleSetReferences(rules)

	// Build what is new or changed. A kept set that nothing held since start
	// had its rules released, so it is rebuilt too if the new rules use it.
	r.ruleSetAccess.RLock()
	created := make(map[string]adapter.RuleSet)
	var createErr error
	for _, tag := range order {
		definition := newOptions[tag]
		current, exists := r.ruleSetMap[tag]
		if exists && reflect.DeepEqual(r.ruleSetOptions[tag], definition) {
			counter, counts := current.(refCounter)
			if !referenced[tag] || !counts || counter.RefCount() > 0 {
				continue
			}
		}
		ruleSet, newErr := R.NewRuleSet(r.ctx, r.logger, tag, definition)
		if newErr != nil {
			createErr = E.Cause(newErr, "parse rule-set ", tag)
			break
		}
		created[tag] = ruleSet
	}
	r.ruleSetAccess.RUnlock()
	closeCreated := func() {
		for _, ruleSet := range created {
			_ = ruleSet.Close()
		}
	}
	if createErr != nil {
		closeCreated()
		return nil, nil, createErr
	}
	if len(created) > 0 {
		startContext := adapter.NewHTTPStartContext()
		for tag, ruleSet := range created {
			startErr := ruleSet.StartContext(r.ctx, startContext)
			if startErr != nil {
				startContext.Close()
				closeCreated()
				return nil, nil, E.Cause(startErr, "initialize rule-set ", tag)
			}
			if ruleSet.Metadata().ContainsProcessRule && r.processSearcher == nil {
				startContext.Close()
				closeCreated()
				return nil, nil, E.Extend(ErrRestartRequired, "rule-set ", tag, " has process rules but no process searcher is running")
			}
		}
		startContext.Close()
	}

	// Install the sets, remembering what they displaced for a rollback.
	r.ruleSetAccess.Lock()
	previousMap, previousSets, previousOptions := r.ruleSetMap, r.ruleSets, r.ruleSetOptions
	nextMap := make(map[string]adapter.RuleSet, len(order))
	nextSets := make([]adapter.RuleSet, 0, len(order))
	for _, tag := range order {
		ruleSet, isCreated := created[tag]
		if !isCreated {
			ruleSet = previousMap[tag]
		}
		nextMap[tag] = ruleSet
		nextSets = append(nextSets, ruleSet)
	}
	r.ruleSetMap, r.ruleSets, r.ruleSetOptions = nextMap, nextSets, newOptions
	r.ruleSetAccess.Unlock()
	rollbackSets := func() {
		r.ruleSetAccess.Lock()
		r.ruleSetMap, r.ruleSets, r.ruleSetOptions = previousMap, previousSets, previousOptions
		r.ruleSetAccess.Unlock()
		closeCreated()
	}

	snapshot, err := r.newRouteRules(rules)
	if err != nil {
		rollbackSets()
		return nil, nil, err
	}
	for i, rule := range snapshot.rules {
		startErr := rule.Start()
		if startErr != nil {
			for _, started := range snapshot.rules[:i] {
				_ = started.Close()
			}
			rollbackSets()
			return nil, nil, E.Cause(startErr, "initialize rule[", i, "]")
		}
	}
	retired := r.ruleSnapshot.Swap(snapshot)

	var displaced []adapter.RuleSet
	for tag, ruleSet := range previousMap {
		if nextMap[tag] != ruleSet {
			displaced = append(displaced, ruleSet)
		}
		if _, kept := newOptions[tag]; !kept {
			removed = append(removed, tag)
		}
	}
	for _, tag := range order {
		if _, existed := previousMap[tag]; !existed {
			added = append(added, tag)
		}
	}
	for _, ruleSet := range created {
		ruleSet.Cleanup()
	}
	r.restartRuleSetUpdater(created, displaced)
	go r.retireRules(retired, displaced)
	return added, removed, nil
}

// retireRules closes a replaced rule generation once no match can still be
// using it, then the rule sets it was the last holder of.
func (r *Router) retireRules(retired *routeRules, displaced []adapter.RuleSet) {
	timer := time.NewTimer(ruleRetireDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-r.closing:
	}
	if retired != nil {
		for _, rule := range retired.rules {
			_ = rule.Close()
		}
	}
	for _, ruleSet := range displaced {
		_ = ruleSet.Close()
	}
	for _, ruleSet := range r.RuleSets() {
		ruleSet.Cleanup()
	}
}

func (r *Router) restartRuleSetUpdater(created map[string]adapter.RuleSet, displaced []adapter.RuleSet) {
	isRemote := func(it adapter.RuleSet) bool { return it.Type() == C.RuleSetTypeRemote }
	changed := common.Any(displaced, isRemote)
	for _, ruleSet := range created {
		changed = changed || isRemote(ruleSet)
	}
	if !changed {
		return
	}
	if r.ruleSetUpdater != nil {
		_ = r.ruleSetUpdater.Close()
	}
	r.ruleSetUpdater = R.NewRuleSetUpdater(r.ctx, r.RuleSets())
	if r.ruleSetUpdater != nil {
		r.ruleSetUpdater.Start()
	}
}

// ruleSetReferences collects the rule-set tags the rules refer to, through
// logical rules as well.
func ruleSetReferences(rules []option.Rule) map[string]bool {
	tags := make(map[string]bool)
	var walk func([]option.Rule)
	walk = func(rules []option.Rule) {
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
	walk(rules)
	return tags
}
