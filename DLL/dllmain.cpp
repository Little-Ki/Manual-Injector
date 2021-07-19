#include "pch.h"
#include <string>
#include <format>
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        auto str = std::format("Module base: {}", reinterpret_cast<PVOID>(hModule));
        MessageBoxA(0, str.c_str(), "Injected", MB_OK);
    }
    return TRUE;
}

