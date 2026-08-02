//go:build windows

// Package winrt provides the Go c-shared DLL entry points for the
// WinRT VPN integration. This is compiled with:
//
//	go build -buildmode=c-shared -tags with_gvisor -o golib.dll .
//
// The resulting golib.dll is loaded by the C++/WinRT VPN Plugin DLL
// (VpnPlugin.dll) inside the Windows VPN broker process.
package main

/*
#include <stdint.h>
#include <stdlib.h>

// Callback type: C++ injects an inbound packet into the OS via VpnChannel.
// The Go side calls this for each packet produced by the proxy engine.
typedef void (*netstack_on_receive_cb)(const uint8_t* data, uint64_t size, void* context);

// Bridge: Go calls this to invoke the C++ callback.
// cgo disallows calling C function pointers directly, so we wrap it.
static void call_on_receive(netstack_on_receive_cb fn, const uint8_t* data, uint64_t size, void* context) {
    if (fn) fn(data, size, context);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/metacubex/mihomo/component/geodata"
	C2 "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/log"
	_ "go.uber.org/automaxprocs"
)

var (
	configBytes []byte
	options    []hub.Option
	running    bool
)

//export netstack_version
func netstack_version() *C.char {
	return C.CString(fmt.Sprintf("mihomo %s %s/%s %s", C2.Version, runtime.GOOS, runtime.GOARCH, runtime.Version()))
}

//export netstack_start
//
// Start mihomo with the given config path and home directory.
// This parses the config, starts the proxy engine, and enables the
// WinRT VPN tun adapter (via SetWinrtInjectFn).
//
// configPath: path to the YAML config file (or empty for default)
// homeDir: mihomo home directory (geodata, cache, etc.)
// extCtl: external controller address (e.g. "127.0.0.1:9090" or "" to disable)
// secret: API secret (or "")
//
// Returns 0 on success, -1 on error.
func netstack_start(configPath *C.char, homeDir *C.char, extCtl *C.char, secret *C.char) C.int {
	cfgPath := C.GoString(configPath)
	home := C.GoString(homeDir)
	ctl := C.GoString(extCtl)
	sec := C.GoString(secret)

	if home != "" {
		if !filepath.IsAbs(home) {
			cwd, _ := os.Getwd()
			home = filepath.Join(cwd, home)
		}
		C2.SetHomeDir(home)
	}

	if cfgPath == "" {
		cfgPath = filepath.Join(C2.Path.HomeDir(), C2.Path.Config())
	}
	C2.SetConfig(cfgPath)

	if err := initHomeDir(); err != nil {
		log.Errorln("init home dir: %s", err.Error())
		return -1
	}

	opts := []hub.Option{}
	if ctl != "" {
		opts = append(opts, hub.WithExternalController(ctl))
	}
	if sec != "" {
		opts = append(opts, hub.WithSecret(sec))
	}

	// Embed mode: disable restart/upgrade (we can't restart inside broker process)
	route.SetEmbedMode(true)

	// Parse and apply config
	if err := hub.Parse(nil, opts...); err != nil {
		log.Errorln("parse config: %s", err.Error())
		return -1
	}

	running = true
	log.Infoln("[WinRT] mihomo started, config=%s home=%s", cfgPath, home)
	return 0
}

//export netstack_register
//
// Register the C++ callback for injecting inbound packets into the OS
// via VpnChannel buffer API. This enables the WinRT VPN tun adapter.
//
// onReceive: C++ function called for each inbound packet.
// context: opaque pointer passed back to the callback (VpnChannel ABI).
//
// Returns 0 on success, -1 if mihomo is not started.
func netstack_register(onReceive C.netstack_on_receive_cb, context unsafe.Pointer) C.int {
	if !running {
		log.Errorln("[WinRT] netstack_register called before netstack_start")
		return -1
	}

	injectFn := func(data []byte) error {
		if onReceive == nil {
			return errors.New("inject callback is nil")
		}
		if len(data) == 0 {
			return nil
		}
		// Keep data alive during the call — Go's GC won't move it
		// because we hold a pointer for the duration of the C call.
		C.call_on_receive(onReceive, (*C.uint8_t)(unsafe.Pointer(&data[0])), C.uint64_t(len(data)), context)
		return nil
	}

	sing_tun.SetWinrtInjectFn(injectFn)
	log.Infoln("[WinRT] inject callback registered")
	return 0
}

//export netstack_send
//
// Push an outbound IP packet from Encapsulate into the gVisor stack.
// Called by C++ IVpnPlugIn::Encapsulate for each packet from the OS.
//
// data: pointer to raw IP packet
// size: packet size in bytes
//
// Returns 0 on success, -1 if dropped (channel full or not initialized).
func netstack_send(data unsafe.Pointer, size C.uint64_t) C.int {
	if size == 0 || data == nil {
		return -1
	}
	// Copy into Go-managed memory (the gVisor stack owns it after this)
	buf := C.GoBytes(data, C.int(size))
	if sing_tun.PushWinrtPacket(buf) {
		return 0
	}
	return -1 // dropped
}

//export netstack_release
//
// Release the inject callback. Called by C++ on IVpnPlugIn::Disconnect.
func netstack_release() {
	sing_tun.SetWinrtInjectFn(nil)
	log.Infoln("[WinRT] inject callback released")
}

//export netstack_stop
//
// Stop mihomo engine. Call this before unloading the DLL.
func netstack_stop() {
	sing_tun.SetWinrtInjectFn(nil)
	executor.Shutdown()
	running = false
	log.Infoln("[WinRT] mihomo stopped")
}

func initHomeDir() error {
	homeDir := C2.Path.HomeDir()
	if homeDir == "" {
		homeDir, _ = os.UserConfigDir()
	}
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		return fmt.Errorf("create home dir: %w", err)
	}
	// Init geodata path
	geodata.SetGeodataMode(false)
	return nil
}

func main() {}
