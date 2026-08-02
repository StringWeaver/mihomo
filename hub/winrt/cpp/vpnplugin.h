#pragma once

#include <unknwn.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Networking.h>

#include <cstdint>
#include <atomic>
#include <mutex>
#include <cstring>

// Forward declarations of Go exported functions
extern "C" {
    int32_t netstack_start(const char* configPath, const char* homeDir, const char* extCtl, const char* secret);
    int32_t netstack_register(void (*onReceive)(const uint8_t*, uint64_t, void*), void* context);
    int32_t netstack_send(const void* data, uint64_t size);
    void netstack_release();
    void netstack_stop();
    const char* netstack_version();
}

// VpnPlugin implements IVpnPlugIn for WinRT VPN.
class VpnPlugin : public winrt::implements<VpnPlugin, winrt::Windows::Networking::Vpn::IVpnPlugIn>
{
public:
    void Connect(winrt::Windows::Networking::Vpn::VpnChannel const& channel);
    void Disconnect(winrt::Windows::Networking::Vpn::VpnChannel const& channel);
    void Encapsulate(winrt::Windows::Networking::Vpn::VpnChannel const& channel,
                     winrt::Windows::Networking::Vpn::VpnPacketBufferList const& packets,
                     winrt::Windows::Networking::Vpn::VpnPacketBufferList const& encapsulatedPackets);
    void Decapsulate(winrt::Windows::Networking::Vpn::VpnChannel const& channel,
                     winrt::Windows::Networking::Vpn::VpnPacketBuffer const& encapBuffer,
                     winrt::Windows::Networking::Vpn::VpnPacketBufferList const& decapsulatedPackets,
                     winrt::Windows::Networking::Vpn::VpnPacketBufferList const& controlPacketsToSend);
    void GetKeepAlivePayload(winrt::Windows::Networking::Vpn::VpnChannel const& channel,
                             winrt::Windows::Networking::Vpn::VpnPacketBuffer& keepAlivePacket);

private:
    void* m_channelAbi = nullptr;
    std::mutex m_connectMutex;
    std::atomic<bool> m_connected{false};

    void ConnectCore(winrt::Windows::Networking::Vpn::VpnChannel const& channel);
};

// C-style callback invoked by Go (via cgo) for inbound packets.
extern "C" void on_receive_callback(const uint8_t* data, uint64_t size, void* context);
