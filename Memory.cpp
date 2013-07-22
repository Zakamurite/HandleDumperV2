#include "Memory.h"
#include <stdlib.h>
#include <exception>
#include <Windows.h>

// Protect memory and return the old protection
inline Protection Protect(uint32 Address, uint32 Size, Protection NewProtection)
{
    unsigned long OldProtection = 0;
    if (VirtualProtect((LPVOID)Address, Size, NewProtection, &OldProtection) == 0)
        throw std::exception("Unable to change memory protection: VirtualProtect failed.");

    return Protection(OldProtection);
}

// Write an array of bytes into memory
void Write(uint32 Address, const uint8* Bytes, uint32 Size)
{
    Protection OldProtection = Protect(Address, Size, Protection::ReadWrite);

    memcpy((LPVOID)Address, Bytes, Size);
    if (*reinterpret_cast<unsigned char*>((LPVOID)Address) != Bytes[0])
        throw std::exception("Memory write failed.");

    Protect(Address, Size, OldProtection);
    FlushInstructionCache(GetCurrentProcess(), (LPVOID)Address, Size);
    return;
}