#include "Patch.h"
#include <Windows.h>
#include "Dumper.h"
#include "WowPointers.h"
#include "Memory.h"
#include <fstream>

bool AuthCheck(uint32 opcode)
{
    return (opcode & 0xB3FD) == 320;
}

bool SpecialCheck(uint32 opcode)
{
    return (opcode & 0x92E8) == 4256;
}

bool NormalCheck(uint32 opcode)
{
    return (opcode & 0x90CC) == 4;
}

uint32 HandlerAddress;
uint32 opcode, _this;
bool doOnce;

void HandlePacket()
{
    if (doOnce)
        return;

    std::ofstream fs("packets.log", std::ios::out);

    for (uint32 i = 0; i < 0xFFFF; ++i)
    {
        if (AuthCheck(i) || SpecialCheck(i) || !NormalCheck(i))
            continue;

        opcode = i;

        uint32 condensed = opcode & 3 | ((opcode & 0x30 | ((opcode & 0xF00 | (opcode >> 1) & 0x3000) >> 2)) >> 2);
        uint32 jamOffs;
        if ((opcode & 0x90CC) == 4 && (jamOffs = *(uint32*)(_this + 4 * condensed + 1376)) != 0)
            if (uint32 handler = jamOffs - ((opcode | (opcode << 16)) ^ 0x62A3A31D))
                fs << std::hex << "Opcode: " << opcode << " jamOffs: " << jamOffs << " handler: " << handler << " handler2: " << *(uint32*)(_this + 4 * condensed + 9568) << std::endl;
    }

    fs.close();

    doOnce = true;
}

void __declspec(naked) PacketHook()
{
    __asm
    {
        pushad
        mov opcode, esi
        mov _this, edi
    }

    HandlePacket();

    __asm
    {
        popad
        cmp ecx, 10A0h
        jmp HandlerAddress
    }
}

void HookHandler()
{
    uint8 JumpHook[] = {0xE9, 0x0, 0x0, 0x0, 0x0, 0x90};
    *reinterpret_cast<unsigned int*>(&JumpHook[1]) = reinterpret_cast<unsigned int>(PacketHook) - (WoWBase + NetClient__ProcessMessage + 0x2A + 0x5);
    Write(WoWBase + NetClient__ProcessMessage + 0x2A, JumpHook, 5);
    HandlerAddress = WoWBase + NetClient__ProcessMessage + 0x30;

    doOnce = false;
}

void Inject()
{
    HookHandler();
}
