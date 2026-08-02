// VpnPlugin.cpp - IVpnPlugIn implementation for WinRT VPN

#include "vpnplugin.h"
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

#include <string>

using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Networking;
using namespace Windows::Networking::Sockets;
using namespace Windows::Networking::Vpn;
using namespace Windows::Storage::Streams;

// ============================================================
// Helper: convert wide string to UTF-8
// ============================================================
static std::string to_utf8(std::wstring_view wide)
{
    if (wide.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.data(),
        static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.data(),
        static_cast<int>(wide.size()), out.data(), len, nullptr, nullptr);
    return out;
}

// ============================================================
// Connect
// ============================================================
void VpnPlugin::Connect(VpnChannel const& channel)
{
    std::lock_guard lock(m_connectMutex);
    try {
        ConnectCore(channel);
        m_connected.store(true);
    }
    catch (const hresult_error&) {}
}

void VpnPlugin::ConnectCore(VpnChannel const& channel)
{
    // 1. Fake Socket: self-connected UDP to satisfy transport check
    const auto localhost = HostName{ L"127.0.0.1" };
    DatagramSocket transport{};
    channel.AssociateTransport(transport, nullptr);
    transport.BindEndpointAsync(localhost, L"").get();
    transport.ConnectAsync(localhost, transport.Information().LocalPort()).get();

    // 2. Route assignment: two /1 routes to cover entire IPv4/IPv6
    VpnRouteAssignment routeScope{};
    routeScope.ExcludeLocalSubnets(true);
    routeScope.Ipv4InclusionRoutes(std::vector{
        VpnRoute(HostName{ L"0.0.0.0" }, 1),
        VpnRoute(HostName{ L"128.0.0.0" }, 1),
    });
    routeScope.Ipv6InclusionRoutes(std::vector{
        VpnRoute(HostName{ L"::" }, 1),
        VpnRoute(HostName{ L"8000::" }, 1),
    });

    // 3. VpnInterfaceId (16 bytes = GUID)
    uint8_t ifaceGuid[16] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90 };
    VpnInterfaceId interfaceId{ ifaceGuid };

    // 4. Domain name assignment (empty = no DNS override via VPN namespace)
    VpnDomainNameAssignment domainAssignment{};

    // 5. Start the channel with main transport
    auto ipv4List = winrt::single_threaded_vector<HostName>({ HostName{ L"10.10.0.1" } });
    auto ipv6List = winrt::single_threaded_vector<HostName>({});
    IInspectable transportAsInspectable = transport.as<IInspectable>();
    channel.StartWithMainTransport(
        ipv4List.GetView(),        // assignedClientIPv4list
        ipv6List.GetView(),        // assignedClientIPv6list
        interfaceId,               // vpnInterfaceId
        routeScope,                // assignedRoutes
        domainAssignment,          // assignedDomainName
        9000,                      // mtuSize
        9000,                      // maxFrameSize
        false,                     // Reserved
        transportAsInspectable     // mainOuterTunnelTransport
    );

    // 6. Detach VpnChannel ABI for Go callbacks (copy first, then detach)
    VpnChannel channelCopy = channel;
    m_channelAbi = winrt::detach_abi(channelCopy);

    // 7. Register inject callback FIRST (must be before netstack_load
    //    so newWinrtTunFromConfig detects the inject fn and skips wintun)
    netstack_register(on_receive_callback, m_channelAbi);

    // 8. Resolve paths from APPX LocalFolder (no hardcoded paths)
    //    UWP apps use ApplicationData.Current.LocalFolder for writable storage.
    //    config.yaml and geodata are placed here by the UWP App.
    auto localFolder = ApplicationData::Current().LocalFolder().Path();
    auto homeDirStr = to_utf8(localFolder);
    auto configPathStr = homeDirStr + "\\config.yaml";

    // 9. Initialize mihomo home directory (equivalent to CMFA coreInit)
    netstack_init(
        homeDirStr.c_str(),
        "127.0.0.1:9090",
        ""
    );

    // 10. Load config (equivalent to CMFA load)
    //     This triggers hub.Parse -> sing_tun.New -> newWinrtTunFromConfig
    //     -> detects inject fn is set -> creates winrtTun (no wintun)
    netstack_load(configPathStr.c_str());
}

// ============================================================
// Disconnect
// ============================================================
void VpnPlugin::Disconnect(VpnChannel const& channel)
{
    std::lock_guard lock(m_connectMutex);
    m_connected.store(false);

    netstack_release();

    try { channel.Stop(); }
    catch (...) {}

    if (m_channelAbi) {
        IInspectable obj{};
        winrt::attach_abi(obj, m_channelAbi);
        m_channelAbi = nullptr;
    }
}

// ============================================================
// Encapsulate: OS outbound -> Go proxy
// ============================================================
void VpnPlugin::Encapsulate(VpnChannel const&, VpnPacketBufferList const& packets,
                             VpnPacketBufferList const&)
{
    auto packetCount = packets.Size();
    while (packetCount-- > 0) {
        const auto packet = packets.RemoveAtBegin();
        const auto buffer = packet.Buffer();
        const auto data = buffer.data();
        const auto len = static_cast<uint64_t>(buffer.Length());
        netstack_send(data, len);
        packets.Append(packet);
    }
}

// ============================================================
// Decapsulate: bypassed
// ============================================================
void VpnPlugin::Decapsulate(VpnChannel const&, VpnPacketBuffer const&,
                             VpnPacketBufferList const&, VpnPacketBufferList const&)
{
}

// ============================================================
// GetKeepAlivePayload
// ============================================================
void VpnPlugin::GetKeepAlivePayload(VpnChannel const&, VpnPacketBuffer&)
{
    // Leave empty -- system uses its own keep-alive if needed
}

// ============================================================
// on_receive_callback: Go -> OS (inbound injection)
// ============================================================
extern "C" void on_receive_callback(const uint8_t* data, uint64_t size, void* context)
{
    if (!data || size == 0 || !context)
        return;

    VpnChannel channel{ nullptr };
    winrt::attach_abi(channel, context);

    try {
        const auto outBuffer = channel.GetVpnReceivePacketBuffer();
        const auto outBuf = outBuffer.Buffer();
        const auto capacity = static_cast<uint64_t>(outBuf.Capacity());
        if (size <= capacity) {
            std::memcpy(outBuf.data(), data, static_cast<size_t>(size));
            outBuf.Length(static_cast<uint32_t>(size));
            channel.AppendVpnReceivePacketBuffer(outBuffer);
            channel.FlushVpnReceivePacketBuffers();
        }
    }
    catch (...) {}

    winrt::detach_abi(channel);
}
