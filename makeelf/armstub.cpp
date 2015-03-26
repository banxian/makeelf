//
//  armstub.cpp
//  ndkutil
//
//  Created by banxian on 1/29/14.
//  Copyright (c) 2014 banxian. All rights reserved.
//

#include "armstub.h"
#ifdef _WIN32
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#endif

using namespace ELFIO;

bool fillbcblcblxarm(unsigned char* opptr, int delta, bool forceblx, bool* overflowed)
{
    unsigned w1 = *(unsigned*)opptr;
    unsigned absdist = delta;
    if (delta < 0) {
        absdist = 0 - delta;
    }
    if ((w1 & 0xFE000000u) == 0xFA000000u) {
        // BLX <label>
        //imm32 = SignExtend(imm24:H:'0', 32);
        if (overflowed) {
            *overflowed = absdist >= 0x04000000;
        }
        if (absdist >= 0x04000000) {
            printf("Distance %s%X is over 26bit in ARMv6 BLX fill\n", delta < 0?"-":"", absdist);
        }
        unsigned imm32 = delta;
        unsigned H = ((imm32 & 2) == 2);
        unsigned imm24 = imm32 >> 2 & 0x00FFFFFF;
        w1 = w1 & 0xFE000000 | imm24 | H << 24;
        *(unsigned*)opptr = w1;
        if (absdist < 0x04000000) {
            return true;
        }
    } else if ((w1 & 0x0F000000) == 0x0B000000 || (w1 & 0x0F000000u) == 0x0A000000u) {
        if (forceblx) {
            printf("Need BLX but B<c> BL<c> found\n");
        }
        if (overflowed) {
            *overflowed = absdist >= 0x04000000;
        }
        if (absdist >= 0x04000000) {
            printf("Distance %s%X is over 26bit in ARMv6 BL fill\n", delta < 0?"-":"", absdist);
        }
        // 28, R_ARM_CALL
        //BL      _Z11mh4gexptestv      = BL<c> <label>
        // 29, R_ARM_JMP24
        //B       _ZN2nn2fs7UnmountEPKc = B<c> <label>
        //BLMI    _Z7hardlogPKcz        = BL<c> <label> 
        unsigned imm32 = delta;
        unsigned imm24 = imm32 >> 2 & 0x00FFFFFF;
        w1 = w1 & 0xFF000000 | imm24;
        *(unsigned*)opptr = w1;
        if (absdist < 0x04000000) {
            return true;
        }
    } 

    return false;
}

bool fillblblxthumb1(unsigned char* opptr, int distance, bool forceblx, bool* overflowed)
{
    unsigned short hw1 = *(unsigned short*)opptr, hw2 = *(unsigned short*)(opptr + 2);
    unsigned absdist = distance;
    if (distance < 0) {
        absdist = 0 - distance;
    }

    if (((hw1 & 0xF800) == 0xF000) && ((hw2 & 0xF800) == 0xF800)) {
        // BL to thumb
        if (forceblx) {
            printf("Need BLX but BL<c> found\n");
        }
        if (overflowed) {
            *overflowed = (absdist & 0xFFC00000u) != 0;
        }
        if ((absdist & 0xFFC00000u) != 0) {
            printf("Distance %s%X is over 22bit in ARMv6 BL fill\n", distance < 0?"-":"", absdist);
        }
        unsigned char s = distance < 0;

        hw1 = (hw1 & 0xF800) | s << 10 | (distance >> 12 & 0x3FF);
        hw2 = (hw2 & 0xF800) | (distance >> 1 & 0x7FF);

        *(unsigned short*)opptr = hw1;
        *(unsigned short*)(opptr + 2) = hw2;
        if ((absdist & 0xFFC00000u) == 0) {
            return true;
        }
    } else if (((hw1 & 0xF800) == 0xF000) && ((hw2 & 0xF801) == 0xE800)) {
        // BLX to ARM
        if (overflowed) {
            *overflowed = (absdist & 0xFFC00000u) != 0;
        }
        if ((absdist & 0xFFC00000u) != 0) {
            printf("Distance %s%X is over 22bit in ARMv6 BLX fill\n", distance < 0?"-":"", absdist);
        }

        unsigned char s = distance < 0;

        hw1 = (hw1 & 0xF800) | s << 10 | (distance >> 12 & 0x3FF);
        hw2 = (hw2 & 0xF800) | (distance >> 1 & 0x7FE);

        *(unsigned short*)opptr = hw1;
        *(unsigned short*)(opptr + 2) = hw2;
        if ((absdist & 0xFFC00000u) == 0) {
            return true;
        }
    }

    return false;
}

bool fillb11b8thumb1(unsigned char* opptr, int distance, bool* overflowed)
{
    unsigned short hw = *(unsigned short*)opptr;
    unsigned absdist = ((distance < 0)?0 - distance:distance);
    if ((hw & 0xF000) == 0xD000) {
        //B<c> imm8
        if (overflowed) {
            *overflowed = absdist >= 0x200;
        }
        if (absdist >= 0x200) {
            printf("Distance %s%X is over 9bit in ARMv6 B<c> fill\n", distance < 0?"-":"", absdist);
        }
        hw = (hw & 0xFF00) | (distance >> 1 & 0xFF);
        *(unsigned short*)opptr = hw;
        if (absdist < 0x200) {
            return true;
        }
    } else if ((hw & 0xF800) == 0xE000) {
        //B<itc> imm11
        if (overflowed) {
            *overflowed = absdist >= 0x1000;
        }
        if (absdist >= 0x1000) {
            printf("Distance %s%X is over 12bit in ARMv6 B<c> fill\n", distance < 0?"-":"", absdist);
        }
        hw = (hw & 0xF800) | (distance >> 1 & 0x7FF);
        *(unsigned short*)opptr = hw;
        if (absdist < 0x1000) {
            return true;
        }
    }
    return false;
}

// T3
void fixupbranch32(int delta, bool arm, unsigned char* addr)
{
    // make sure addr[0] = 0
    unsigned short hw1 = *(unsigned short*)addr, hw2 = *(unsigned short*)(addr + 2);

    // extract distance
    //unsigned char s = (hw1 & binary(0000010000000000) ) != 0;
    //unsigned char i1 = (((hw2 & binary(0010000000000000) ) != 0) ^ s) == 0;
    //unsigned char i2 = (((hw2 & binary(0000100000000000) ) != 0) ^ s) == 0;
    //signed long offset = i1 << 23 | i2 << 22 | (hw1 & binary(0000001111111111) ) << 12 | (hw2 & binary(0000011111111111) ) << 1 | 0;
    unsigned char s = (hw1 & 0x400) != 0;
    unsigned char i1 = (((hw2 & 0x2000) != 0) ^ s) == 0;
    unsigned char i2 = (((hw2 & 0x800) != 0) ^ s) == 0;
    signed long offset = i1 << 23 | i2 << 22 | (hw1 & 0x3FF) << 12 | (hw2 & 0x7FF) << 1 | 0;

    if (s) {
        // cheat: 0xFF000000 & distance
        offset = 0 - (0x1000000 - offset);
    }

    //printf("offset: %s0x%08X\n", offset<0?"-":"", abs(offset));

    offset += delta;
    // store distance
    s = offset < 0;
    //i1 = (offset & binary(100000000000000000000000) ) != 0;
    //i2 = (offset & binary(010000000000000000000000) ) != 0;
    i1 = (offset & 0x800000) != 0;
    i2 = (offset & 0x400000) != 0;

    unsigned char j1 = ((i1 == 0) ^ s) != 0;
    unsigned char j2 = ((i2 == 0) ^ s) != 0;

    //hw1 = (hw1 & binary(1111100000000000) ) | s << 10 | (offset >> 12 & binary(0000001111111111) );
    //hw2 = (hw2 & binary(1101000000000000) ) | j1 << 13 | j2 << 11 | (offset >> 1 & binary(0000011111111111) );
    hw1 = (hw1 & 0xF800) | s << 10 | (offset >> 12 & 0x3FF);
    hw2 = (hw2 & 0xD000) | j1 << 13 | j2 << 11 | (offset >> 1 & 0x7FF);

    *(unsigned short*)addr = hw1;
    *(unsigned short*)(addr + 2) = hw2;
}

void fixupmov32(int delta, unsigned char* addrlo, unsigned char* addrhi)
{
    // make sure addr[0] = 0
    unsigned short hw1 = *(unsigned short*)addrlo, hw2 = *(unsigned short*)(addrlo + 2);

    // 4444 i333 8888 8888
    // extract imm16 lo
    //unsigned char i = (hw1 & binary(010000000000) ) != 0;
    //unsigned short imm16 = (hw1 & binary(1111) ) << 12 | i << 11 | (hw2 & binary(0111000000000000) ) >> 12 << 8 | (hw2 & binary(11111111) );
    unsigned char i = (hw1 & 0x400) != 0;
    unsigned short imm16 = (hw1 & 0xF) << 12 | i << 11 | (hw2 & 0x7000) >> 12 << 8 | (hw2 & 0xFF);


    unsigned imm32 = imm16; // imm32

    // extract imm16 hi
    hw1 = *(unsigned short*)addrhi;
    hw2 = *(unsigned short*)(addrhi + 2);


    //i = (hw1 & binary(010000000000) ) != 0;
    //imm16 = (hw1 & binary(1111) ) << 12 | i << 11 | (hw2 & binary(0111000000000000) ) >> 12 << 8 | (hw2 & binary(11111111) );
    i = (hw1 & 0x400) != 0;
    imm16 = (hw1 & 0xF) << 12 | i << 11 | (hw2 & 0x7000) >> 12 << 8 | (hw2 & 0xFF);


    imm32 |= (imm16 << 16);


    imm32 += delta;

    // take imm16 from imm32 hi
    imm16 = (imm32 >> 16) & 0xFFFF;

    // ---- -i-- ---- 4444 -333 ---- 8888 8888
    // 4444 i333 8888 8888
    // recalc hi
    //hw1 = (hw1 & binary(1111101111110000) ) | (imm16 & binary(100000000000) ) >> 11 << 10 | (imm16 & binary(1111000000000000) ) >> 12;
    //hw2 = (hw2 & binary(1000111100000000) ) | (imm16 & binary(011100000000) ) >> 8 << 12 | (imm16 & binary(11111111) );
    hw1 = (hw1 & 0xFBF0) | (imm16 & 0x800) >> 11 << 10 | (imm16 & 0xF000) >> 12;
    hw2 = (hw2 & 0x8F00) | (imm16 & 0x700) >> 8 << 12 | (imm16 & 0xFF);

    *(unsigned short*)addrhi = hw1;
    *(unsigned short*)(addrhi + 2) = hw2;

    // get hw1/hw2 from lo
    hw1 = *(unsigned short*)addrlo;
    hw2 = *(unsigned short*)(addrlo + 2);

    imm16 = imm32 & 0xFFFF; // truncate

    // recalc lo
    //hw1 = (hw1 & binary(1111101111110000) ) | (imm16 & binary(100000000000) ) >> 11 << 10 | (imm16 & binary(1111000000000000) ) >> 12;
    //hw2 = (hw2 & binary(1000111100000000) ) | (imm16 & binary(011100000000) ) >> 8 << 12 | (imm16 & binary(11111111) );
    hw1 = (hw1 & 0xFBF0) | (imm16 & 0x800) >> 11 << 10 | (imm16 & 0xF000) >> 12;
    hw2 = (hw2 & 0x8F00) | (imm16 & 0x700) >> 8 << 12 | (imm16 & 0xFF);

    *(unsigned short*)addrlo = hw1;
    *(unsigned short*)(addrlo + 2) = hw2;
}

int extract_branchlabel_t2_distance(unsigned short hw1) {
    unsigned short imm11 = hw1 & 0x07FF;
    if (imm11 & 0x0400) {
        // neg
        // 7FF
        return (0 - (0x800 - imm11)) << 1;
    }
    return imm11 << 1;
}

// B.W T4, BL T1
int extract_branchlabel_t4_distance(unsigned w1) {
    unsigned short hw1 = w1, hw2 = w1 >> 16;

    // extract distance
    //unsigned char s = (hw1 & binary(0000010000000000) ) != 0;
    //unsigned char i1 = (((hw2 & binary(0010000000000000) ) != 0) ^ s) == 0;
    //unsigned char i2 = (((hw2 & binary(0000100000000000) ) != 0) ^ s) == 0;
    //signed long offset = i1 << 23 | i2 << 22 | (hw1 & binary(0000001111111111) ) << 12 | (hw2 & binary(0000011111111111) ) << 1 | 0;
    unsigned char s = (hw1 & 0x400) != 0;
    unsigned char i1 = (((hw2 & 0x2000) != 0) ^ s) == 0;
    unsigned char i2 = (((hw2 & 0x800) != 0) ^ s) == 0;
    signed long offset = i1 << 23 | i2 << 22 | (hw1 & 0x3FF) << 12 | (hw2 & 0x7FF) << 1 | 0;

    if (s) {
        // cheat: 0xFF000000 & distance
        offset = 0 - (0x1000000 - offset);
    }

    return offset;
}

int extract_cbnzlabel_t1_distance(unsigned short hw1) {
    unsigned imm5 = (hw1 & 0x00F8) >> 3;
    unsigned char i = (hw1 & 0x0200) != 0;

    return ((i << 5) | imm5) << 1;
}

int extract_branchlabel_t2_target(unsigned short hw1, unsigned hw1pc) {
    short distance = extract_branchlabel_t2_distance(hw1);
    return distance + hw1pc + 4; // +4/+8
}

int extract_branchlabel_t4_target(unsigned w1, unsigned w1pc) {
    int distance = extract_branchlabel_t4_distance(w1); // multi 2?!
    return distance + w1pc + 4; // +4/+8
}

int extract_cbnzlabel_t1_target(unsigned short hw1, unsigned hw1pc) {
    short distance = extract_cbnzlabel_t1_distance(hw1);
    return distance + hw1pc + 4; // +4/+8
}

bool build_branchlabel_t2(unsigned short* hw1, unsigned caller, unsigned callee)
{
    unsigned distance = callee - (caller + 4);
    if (int(distance) > 0xFFF || int(distance) < - 0xFFF) {
        return false;
    }
    unsigned short imm11;
    imm11 = distance >> 1 & 0x7FF;
    *hw1 = 0xE000u & imm11;
}

// Encoding T4
// B<c>.W <label> Outside or last in IT block
bool build_branchlabelW_t4(unsigned* w1, unsigned caller, unsigned callee)
{
    int distance = callee - (caller + 4);
    if (distance > 0xFFFFFF || distance < - 0xFFFFFF) {
        return false;
    }
    // S = 0, J1/J2 = 1
    unsigned bwt3 = 0xB800F000;
    fixupbranch32(distance, false, (unsigned char*)&bwt3);
    *w1 = bwt3;
}

bool build_branchlinklabel_t1(unsigned* w1, unsigned caller, unsigned callee)
{
    int distance = callee - (caller + 4);
    if (distance > 0xFFFFFF || distance < - 0xFFFFFF) {
        return false;
    }
    unsigned bwt3 = 0xF800F000;
    fixupbranch32(distance, false, (unsigned char*)&bwt3);
    *w1 = bwt3;
}

int extract_branchlabel_bcblcblxarm_distance( unsigned w1 )
{
    if ((w1 & 0xFE000000u) == 0xFA000000u) {
        // BLX <label>
        //imm32 = SignExtend(imm24:H:'0', 32);
        unsigned imm24 = w1 & 0x00FFFFFF;
        char H = (w1 & 0x01000000) != 0;
        unsigned imm26 = (imm24 << 2 | H << 1);
        if (imm24 & 0x00800000) {
            return 0 - (0x03FFFFFF + 1 - (imm26));
        } else {
            return imm26;
        }
    } else if ((w1 & 0x0F000000) == 0x0B000000 || (w1 & 0x0F000000u) == 0x0A000000u) {
        // 28, R_ARM_CALL
        //BL      _Z11mh4gexptestv      = BL<c> <label>
        // 29, R_ARM_JMP24
        //B       _ZN2nn2fs7UnmountEPKc = B<c> <label>
        //BLMI    _Z7hardlogPKcz        = BL<c> <label> 
        unsigned imm24 = w1 & 0x00FFFFFF;
        unsigned imm26 = (imm24 << 2);
        if (imm24 & 0x00800000) {
            return 0 - (0x03FFFFFF + 1 - (imm26));
        } else {
            return imm26;
        }
    }
    return 0;
}

int extract_branchlabel_bcblcblxarm_target( unsigned w1, unsigned w1pc )
{
    int distance = extract_branchlabel_bcblcblxarm_distance(w1); // multi 2?!
    return distance + w1pc + 8; // +4/+8
}

int extract_ldr_literal_arm_distance( unsigned w1 )
{
    //Encoding A1 ARMv4*, ARMv5T*, ARMv6*, ARMv7
    //LDR<c> <Rt>, <label>
    //LDR<c> <Rt>, [PC, #-0]
    //t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    unsigned imm12 = w1 & 0x00000FFF;
    char U = (w1 & 0x00800000) != 0;
    if (U) {
        return imm12;
    } else {
        return 0 - imm12;
    }
}

unsigned extract_ldr_literal_arm_target( unsigned w1, unsigned w1pc )
{
    int distance = extract_ldr_literal_arm_distance(w1);
    return distance + w1pc + 8;
}
