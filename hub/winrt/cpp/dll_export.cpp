// dll_export.cpp - DLL activation factory for WinRT VPN Plugin

#include "vpnplugin.h"
#include <unknwn.h>
#include <winstring.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>

using namespace winrt;
using namespace Windows::Foundation;

// DllGetActivationFactory: Windows calls this to create our plugin
HRESULT STDMETHODCALLTYPE DllGetActivationFactory(HSTRING classId, IActivationFactory** factory)
{
    *factory = nullptr;

    uint32_t len = 0;
    const wchar_t* rawStr = WindowsGetStringRawBuffer(classId, &len);
    std::wstring_view className(rawStr, len);

    if (className == L"VpnProxy.VpnPlugin") {
        IActivationFactory iaf = get_activation_factory<VpnPlugin>().as<IActivationFactory>();
        *factory = reinterpret_cast<IActivationFactory*>(winrt::detach_abi(iaf));
        return S_OK;
    }

    return E_NOINTERFACE;
}
