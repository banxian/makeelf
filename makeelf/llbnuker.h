#ifndef _LLB_NUKER_H
#define _LLB_NUKER_H

#include "ntypedefs.h"

unsigned LocateRWEndForHeap(void* llbcontent, int llblen);
unsigned ibxx_fileoffset_to_va(const void* header, unsigned offset, void* context);
unsigned ibxx_va_to_fileoffset(const void* header, unsigned va, void* context);
bool LocateZIForSection(void* textcontent, int textlen, const void* header, unsigned* zibegin, unsigned* ziend, bool* matched);
unsigned codebin_fileoffset_to_va(const void* header, unsigned offset, void* context);
unsigned codebin_va_to_fileoffset(const void* header, unsigned va, void* context);
#endif