package sing_tun

import (
	"sync/atomic"
)

// winrtState holds the C++ side callback for injecting inbound packets.
// Set via SetWinrtInjectFn from cgo before the tun listener starts.
var winrtInjectFn atomic.Pointer[func(data []byte) error]

// SetWinrtInjectFn sets the C++ callback for injecting inbound packets
// into the OS via VpnChannel buffer API.
// This is called from Go c-shared export (netstack_register).
func SetWinrtInjectFn(fn func(data []byte) error) {
	winrtInjectFn.Store(&fn)
}

// getWinrtInjectFn returns the current inject function, or nil if not set.
func getWinrtInjectFn() func(data []byte) error {
	fn := winrtInjectFn.Load()
	if fn == nil {
		return nil
	}
	return *fn
}

// winrtOutChan holds the channel for receiving outbound packets from Encapsulate.
// Set when the winrtTun is created.
var winrtOutChan atomic.Pointer[chan []byte]

// SetWinrtOutChan sets the channel for receiving outbound packets from Encapsulate.
func SetWinrtOutChan(ch chan []byte) {
	winrtOutChan.Store(&ch)
}

// PushWinrtPacket pushes an outbound IP packet from Encapsulate into the tun.
// Called from Go c-shared export (netstack_send).
// Returns false if the channel is not set or full (packet dropped).
func PushWinrtPacket(data []byte) bool {
	ch := winrtOutChan.Load()
	if ch == nil || *ch == nil {
		return false
	}
	select {
	case *ch <- data:
		return true
	default:
		return false // channel full, drop packet
	}
}
