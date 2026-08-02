//go:build !(with_gvisor && windows)

package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
)

// newWinrtTunFromConfig returns nil on non-Windows/non-gVisor builds.
// WinRT VPN is only available on Windows with the gVisor stack.
func newWinrtTunFromConfig(name string, mtu uint32) tun.Tun {
	return nil
}
