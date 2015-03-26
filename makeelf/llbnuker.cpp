#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "AddonFuncUnt.h"
#include "armstub.h"
#include "llbnuker.h"

typedef unsigned (*fn_fileoffset_to_va)(const void* header, unsigned offset, void*context);

int findpatternoffset(const void *base, size_t begin, size_t end, const void *needle, size_t nlen);


int findpatternoffset(const void *base, size_t begin, size_t end, const void *needle, size_t nlen)
{
    // TODO: parse mach-o
    unsigned ret = (unsigned)memmem((char*)base + begin, end - begin, needle, nlen);
    if (ret) {
        ret -= (unsigned)base;
        //ret += 0x1000;
    }
    return ret;
}

unsigned find_movwtaddr0pc_to_data_thumb(unsigned base, const unsigned char* head, const unsigned char* tail, unsigned dataaddr, fn_fileoffset_to_va fo2rva, void* context, bool reverse)
{
    int step = reverse?-2:2; // thumb
    for (const unsigned char* curr = (reverse?tail:head); curr != (reverse?head:tail); curr += step) {
        // TODO: other than R0
        if (*(unsigned short*)curr == 0x4478) {
            unsigned pc = fo2rva((const void*)base, unsigned(curr) + 4 - base, context);
            unsigned imm32 = dataaddr - pc;
            // 40 F2 00 00 C0 F2 00 00
            unsigned long long op = 0x0000F2C00000F240ull; // mov32 r0, #0

            unsigned char* addrlo = (unsigned char*)&op;
            unsigned char* addrhi = addrlo + 4;

            fixupmov32(imm32, addrlo, addrhi);

            // TODO: find two 4byte instead 8byte
            if (*(unsigned long long*)(curr - 8) == op) {
                // hitted
                unsigned movwt = unsigned(curr) - 8 - base/* + 0x1000*/;
                return movwt;
            }
            // temporary for 5.1.1 asr
            // -10 = low, -4 = hi
            if (*(unsigned*)(curr - 10) == (op & 0xFFFFFFFF) && *(unsigned*)(curr - 4) == (op >> 32)) {
                // hitted
                unsigned movwt = unsigned(curr) - 10 - base/* + 0x1000*/;
                return movwt;
            }
        }
    }
    return 0;
}

unsigned find_ldr_to_offset_thumb(unsigned base, const unsigned char* head, const unsigned char* tail, unsigned offsetaddr, fn_fileoffset_to_va fo2rva, void* context, bool reverse)
{
    // LDR{<c>}{<q>} <Rt>, [PC, #+/-<imm>]
    // LDR.N
    // 01001ttt[imm8imm8]
    // LDR.W
    // 1111 1000 U101 1111 tttt [imm12imm12im]
    int step = reverse?-2:2; // thumb
    for (const unsigned char* curr = (reverse?tail:head); curr != (reverse?head:tail); curr += step) {
        if ((*(unsigned short*)curr & 0xF800u) == 0x4800) {
            unsigned pc = fo2rva((const void*)base, unsigned(curr) + 4 - base, context);
            unsigned char imm8 = *(unsigned short*)curr; // truncate
            unsigned delta = imm8 << 2;
            // Align(PC, 4)
            if ((pc & 0xFFFFFFFCu) + delta == offsetaddr) {
                return unsigned(curr) - base; // delta
            }
        }
        // DF F8 24 0D
        // 0000 1101 0010 0100 1111 1000 1101 1111
        if ((*(unsigned*)curr & 0x0000FF7Fu) == 0x0000F85Fu) {
            unsigned pc = fo2rva((const void*)base, unsigned(curr) + 4 - base, context);
            bool U = (*(unsigned*)curr & 0x00000080) != 0;
            unsigned short imm12 = (*(unsigned*)curr & 0x0FFF0000) >> 16;
            int delta = U?imm12:-imm12;
            if ((pc & 0xFFFFFFFCu) + delta == offsetaddr) {
                return unsigned(curr) - base; // delta
            }
        }
    }

    return 0;
}

unsigned find_ldr_to_data_thumb(unsigned base, const unsigned char* head, const unsigned char* tail, unsigned dataaddr, fn_fileoffset_to_va fo2rva, void* context, bool reverse)
{
    int step = reverse?-2:2; // thumb
    for (const unsigned char* curr = (reverse?tail:head); curr != (reverse?head:tail); curr += step) {
        if (*(unsigned*)curr == dataaddr) {
            //ROM:5FF19D48 7E AE F3 5F             p_debugenabled  DCD aDebugEnabled       ; DATA XREF: UpdateDeviceTree:loc_5FF19020r
            //ROM:5FF19D48                                                                 ; "debug-enabled"
            unsigned offsetaddr = fo2rva((const void*)base, unsigned(curr) - base, context);
            return find_ldr_to_offset_thumb(base, head, tail, offsetaddr, fo2rva, context, reverse);
        }
    }
    return 0;
}

unsigned codebin_fileoffset_to_va(const void* header, unsigned offset, void* context) 
{
    // TODO: loop
    exhdr_CodeSetInfo* exheader = (exhdr_CodeSetInfo*)header;
    return offset + exheader->text.address;
}

unsigned codebin_va_to_fileoffset(const void* header, unsigned va, void* context) 
{
    exhdr_CodeSetInfo* exheader = (exhdr_CodeSetInfo*)header;
    return va - exheader->text.address;
}

bool LocateZIForSection(void* textcontent, int textlen, const void* header, unsigned* zibegin, unsigned* ziend, bool* matched) {
    // Homebrew
    //.text:00100000 _start
    //.text:00100000                 BL      __libc_init_array
    // ...
    //.text:001089B8 __libc_init_array                       ; CODE XREF: _startp
    //.text:001089B8                 STMFD   SP!, {R4-R6,LR}
    //.text:001089BC                 LDR     R5, =gpuDOut
    //.text:001089C0                 LDR     R6, =gpuDOut

    // Retail Games
    //STUP_ENTRY:00100000 _start                                  ; DATA XREF: nn::fs::CTR::MPCore::detail::ContentRomFsArchive::AllocateBuffer(void)+90o
    //STUP_ENTRY:00100000                                         ; STUP_ENTRY:off_108F94o ...
    //STUP_ENTRY:00100000                 BL              nninitRegion
    // ...
    //STUP_ENTRY:00100024 nninitRegion                            ; CODE XREF: __dso_handlep
    //STUP_ENTRY:00100024                 LDR             R0, =Image$$ZI$$ZI$$Base
    //STUP_ENTRY:00100028                 LDR             R1, =Image$$ZI$$ZI$$Limit
    unsigned blinitop = *(unsigned*)textcontent;
    exhdr_CodeSetInfo* exheader = (exhdr_CodeSetInfo*)header;
    // Encoding A1 ARMv4*, ARMv5T*, ARMv6*, ARMv7
    // BL<c> <label>
    if ((blinitop & 0x0F000000) == 0x0B000000) {
        // okay
        unsigned initva = extract_branchlabel_bcblcblxarm_target(blinitop, exheader->text.address);
        // zibegin = dataaddr+datasize
        // ziend = zibegin+bsssize
        unsigned initoff = codebin_va_to_fileoffset(exheader, initva, NULL);
        unsigned ldrbaseop = *(unsigned*)(unsigned(textcontent) + initoff);
        unsigned ldrlimitop = *(unsigned*)(unsigned(textcontent) + initoff + 4);
        // E = <AL>
        if ((ldrbaseop & 0xFF7F0000) == 0xE51F0000 && (ldrlimitop & 0xFF7F0000) == 0xE51F0000) {
            unsigned offbaseva = extract_ldr_literal_arm_target(ldrbaseop, initva);
            unsigned offlimitva = extract_ldr_literal_arm_target(ldrlimitop, initva + 4);

            unsigned offbaseoff = codebin_va_to_fileoffset(exheader, offbaseva, NULL);
            unsigned offlimitoff = codebin_va_to_fileoffset(exheader, offlimitva, NULL);

            unsigned zibase = *(unsigned*)(unsigned(textcontent) + offbaseoff);
            unsigned zilimit = *(unsigned*)(unsigned(textcontent) + offlimitoff);

            *matched = (zibase == *zibegin && zilimit == *ziend);
            if (*matched == false) {
                *zibegin = zibase;
                *ziend = zilimit;
            }
            return true;
        } else {
            *matched = false;
            return false;
        }

        return true;
    }

    *matched = false;
    return false;
}