//go:build with_gvisor && windows

package sing_tun

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	tun "github.com/metacubex/sing-tun"
)

// Compile-time interface checks
var _ tun.GVisorTun = (*winrtTun)(nil)
var _ tun.Tun = (*winrtTun)(nil)
var _ stack.LinkEndpoint = (*winrtEndpoint)(nil)

// winrtTun implements tun.GVisorTun for WinRT VPN.
//
// In the WinRT VPN model:
// - Outbound IP packets arrive via IVpnPlugIn::Encapsulate (push model).
//   We feed them into outChan, and the gVisor dispatchLoop reads from outChan.
// - Inbound IP packets are produced by the proxy engine's goroutines.
//   Write() calls the C++ inject callback, which uses VpnChannel buffer API.
type winrtTun struct {
	mtu    uint32
	name   string
	closed atomic.Bool

	// outChan carries outbound IP packets from Encapsulate to the gVisor dispatch loop.
	// Each element is a heap-allocated byte slice owned by the consumer.
	outChan chan []byte

	// injectFn is called by Write() to push inbound packets into the OS via VpnChannel.
	// This is set from C++ via cgo (netstack_register callback).
	injectFn func(data []byte) error

	closeOnce sync.Once
}

// newWinrtTun creates a WinRT VPN-backed tun.Tun.
// injectFn: called for each inbound packet (proxy engine → VpnChannel → OS).
// outBufSize: capacity of the outbound packet channel.
func newWinrtTun(name string, mtu uint32, injectFn func(data []byte) error, outBufSize int) *winrtTun {
	if mtu == 0 {
		mtu = 9000
	}
	if outBufSize == 0 {
		outBufSize = 256
	}
	return &winrtTun{
		mtu:      mtu,
		name:     name,
		outChan:  make(chan []byte, outBufSize),
		injectFn: injectFn,
	}
}

// --- tun.Tun interface (Read/Write/Close) ---

// Read blocks until an outbound packet is available from Encapsulate.
// This is called by the System stack's generic tunLoop fallback.
func (t *winrtTun) Read(p []byte) (n int, err error) {
	pkt, ok := <-t.outChan
	if !ok {
		return 0, io.ErrClosedPipe
	}
	n = copy(p, pkt)
	return
}

// Write pushes an inbound packet to the OS via the C++ inject callback.
func (t *winrtTun) Write(p []byte) (n int, err error) {
	if t.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if t.injectFn == nil {
		return 0, errors.New("winrt: inject function not set")
	}
	err = t.injectFn(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *winrtTun) Close() error {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		close(t.outChan)
	})
	return nil
}

// --- tun.GVisorTun interface (WritePacket + NewEndpoint) ---

// WritePacket is the gVisor path for outbound packets.
// It concatenates the packet buffer slices and writes them.
func (t *winrtTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	return t.write(pkt.AsSlices())
}

func (t *winrtTun) write(packetElementList [][]byte) (int, error) {
	if t.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if t.injectFn == nil {
		return 0, errors.New("winrt: inject function not set")
	}
	var totalLen int
	for _, elem := range packetElementList {
		totalLen += len(elem)
	}
	// Flatten into a single buffer for the inject callback
	buf := make([]byte, 0, totalLen)
	for _, elem := range packetElementList {
		buf = append(buf, elem...)
	}
	if err := t.injectFn(buf); err != nil {
		return 0, err
	}
	return totalLen, nil
}

// NewEndpoint creates a gVisor LinkEndpoint backed by this tun.
func (t *winrtTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return &winrtEndpoint{tun: t}, stack.NICOptions{}, nil
}

// --- ReadFunc helper (matches NativeTun.ReadFunc signature) ---

// ReadFunc reads one packet and calls block with the packet data.
func (t *winrtTun) ReadFunc(block func(b []byte)) error {
	pkt, ok := <-t.outChan
	if !ok {
		return io.ErrClosedPipe
	}
	block(pkt)
	return nil
}

// --- winrtEndpoint: stack.LinkEndpoint implementation ---

type winrtEndpoint struct {
	tun        *winrtTun
	mu         sync.RWMutex // mu guards dispatcher
	dispatcher stack.NetworkDispatcher
}

func (e *winrtEndpoint) MTU() uint32 {
	return e.tun.mtu
}

func (e *winrtEndpoint) SetMTU(mtu uint32) {
}

func (e *winrtEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *winrtEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *winrtEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
}

func (e *winrtEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (e *winrtEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if dispatcher == nil && e.dispatcher != nil {
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		go e.dispatchLoop()
	}
}

func (e *winrtEndpoint) dispatchLoop() {
	for {
		var packetBuffer buffer.Buffer
		err := e.tun.ReadFunc(func(b []byte) {
			packetBuffer = buffer.MakeWithData(b)
		})
		if err != nil {
			break
		}
		ihl, ok := packetBuffer.PullUp(0, 1)
		if !ok {
			packetBuffer.Release()
			continue
		}
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(ihl.AsSlice()) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		default:
			packetBuffer.Release()
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           packetBuffer,
			IsForwardedPacket: true,
		})
		e.mu.RLock()
		dispatcher := e.dispatcher
		e.mu.RUnlock()
		if dispatcher == nil {
			pkt.DecRef()
			return
		}
		dispatcher.DeliverNetworkPacket(networkProtocol, pkt)
		pkt.DecRef()
	}
}

func (e *winrtEndpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

func (e *winrtEndpoint) Wait() {
}

func (e *winrtEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *winrtEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (e *winrtEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (e *winrtEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, packet := range packetBufferList.AsSlice() {
		_, err := e.tun.write(packet.AsSlices())
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

func (e *winrtEndpoint) Close() {
}

func (e *winrtEndpoint) SetOnCloseAction(f func()) {
}

// newWinrtTunFromConfig creates a winrtTun using the package-level inject function.
// Returns nil if the inject function has not been set (WinRT VPN not active).
func newWinrtTunFromConfig(name string, mtu uint32) tun.Tun {
	fn := getWinrtInjectFn()
	if fn == nil {
		return nil
	}
	t := newWinrtTun(name, mtu, fn, 256)
	SetWinrtOutChan(t.outChan)
	return t
}
