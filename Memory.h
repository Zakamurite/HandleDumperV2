#ifndef _MEMORY_H
#define _MEMORY_H

#include "DumperDefs.h"

enum Protection : uint32
{
    NoAccess            = 0x1,
    Read                = 0x2,
    ReadWrite           = 0x4,
    WriteCopy           = 0x8,
    Execute             = 0x10,
    ExecuteRead         = 0x20,
    ExecuteReadWrite    = 0x40,
    ExecuteWriteCopy    = 0x80
};

inline Protection Protect (uint32 Address, uint32 Size, Protection NewProtection);

template <typename Type> Type& ReadCopy(uint32 Address)
{
    Type Object;
    Protection OldProtection = Protect(Address, sizeof(Object), Protection::WriteCopy);
    memcpy(&Object, (void*)Address, sizeof(Object));
    Protect(Address, sizeof(Object), OldProtection);
    return Object;
}

void Write(uint32 Address, const uint8* Bytes, uint32 Size);

#endif