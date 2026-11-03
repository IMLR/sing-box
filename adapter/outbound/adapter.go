package outbound

import (
	"github.com/sagernet/sing-box/option"
)

type Adapter struct {
	outboundType string
	outboundTag  string
	network      []string
	dependencies []string
}

func NewAdapter(outboundType string, outboundTag string, network []string, dependencies []string) Adapter {
	return Adapter{
		outboundType: outboundType,
		outboundTag:  outboundTag,
		network:      network,
		dependencies: dependencies,
	}
}

func NewAdapterWithDialerOptions(outboundType string, outboundTag string, network []string, dialOptions option.DialerOptions) Adapter {
	var dependencies []string
	if dialOptions.Detour != "" {
		dependencies = []string{dialOptions.Detour}
	}
	return NewAdapter(outboundType, outboundTag, network, dependencies)
}

func (a *Adapter) Type() string {
	return a.outboundType
}

func (a *Adapter) Tag() string {
	return a.outboundTag
}

func (a *Adapter) Network() []string {
	return a.network
}

func (a *Adapter) Dependencies() []string {
	return a.dependencies
}

// SetDependencies replaces the dependency list of a group whose members were
// updated in place, so the manager's dependency bookkeeping follows it.
func (a *Adapter) SetDependencies(dependencies []string) {
	a.dependencies = dependencies
}
