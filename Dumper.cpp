#include <Windows.h>

#include "DumperDefs.h"
#include "Patch.h"

uint32 WoWBase = 0;


int __stdcall DllMain (HMODULE Module, unsigned long Reason, void*)
{
    if (Reason != DLL_PROCESS_ATTACH)
        return 0;

    WoWBase = (uint32)GetModuleHandle(nullptr);

    void* hacksThread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(Inject), nullptr, 0, nullptr);
    if (hacksThread == nullptr)
    {
        MessageBox(nullptr, "Unable to create threads.", "Error", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    return 1;
}