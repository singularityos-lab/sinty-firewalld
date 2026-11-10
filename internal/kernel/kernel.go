// Package kernel turns a firewall state into the nftables ruleset through
// libsinty-system-core.
package kernel

import (
	"github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"

	"github.com/singularityos-lab/sinty-firewalld/internal/state"
)

type Nftables struct{}

func (Nftables) Apply(s state.State) error {
	var ports []sintysystem.FirewallPort
	for _, r := range s.Active() {
		ports = append(ports, sintysystem.FirewallPort{Spec: r.Ports, Comment: r.Label})
	}
	return sintysystem.FirewallApply(s.Enabled, s.Profile == state.Public, ports)
}
