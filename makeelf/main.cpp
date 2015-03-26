#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <map>
#include <sys/stat.h>
#include "AddonFuncUnt.h"
#include "utilunix.h"
#include "elfio/elfio.hpp"
#include "armstub.h"
#include "ntypedefs.h"
#include "llbnuker.h"
#ifdef _WIN32
#include "targetver.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#define strcasecmp _stricmp
#endif


using namespace ELFIO;

typedef std::vector< unsigned char > ByteArray;
struct VirtualSection {
    unsigned addr;
    std::string name;
    ByteArray content;
};

enum SymbolTypeEnum {
    stARM,
    stThumb,
    stData,
    stUnkown
};

enum SymbolSectionEnum {
    ssText,
    ssConst,
    ssData,
    ssBss,
    ssUnkown
};

struct SymbolItem {
    SymbolTypeEnum type;
    unsigned addr;
    unsigned size; // 0?
    bool global;
    bool local;
    bool weak;
    bool undef;
    SymbolSectionEnum sect;
    Elf_Half sectindex;
    std::string name;
};

typedef std::map < std::string, SymbolItem > SymbolMap;


SymbolMap loadmapfromtxt(const wchar_t* path);
void printfreespace(exhdr_CodeSetInfo* exheader);
void printexclamatorymark();


int wmain(int argc, const wchar_t* argv[])
{
    const wchar_t* exheaderpath = NULL;
    const wchar_t* symbolspath = NULL;
    const wchar_t* outputpath = NULL; // .axf
    const wchar_t* inputpath = NULL; // exefs
    const wchar_t* objectpath = NULL;
    bool verbose = false;
    for (int i = 1; i < argc; i++) {
        if (beginwith(argv[i], L"--exheader=")) {
            exheaderpath = &(argv[i][sizeof "--exheader=" - 1]);
        } else if (beginwith(argv[i], L"--symbols=")) {
            symbolspath = &(argv[i][sizeof "--symbols=" - 1]);
        } else if (wcscmp(argv[i], L"-o") == 0) {
            outputpath = argv[++i];
        } else if (wcscmp(argv[i], L"-i") == 0) {
            inputpath = argv[++i];
        } else if (wcscmp(argv[i], L"-v") == 0) {
            verbose = true;
        } else {
            // both input
            objectpath = argv[i];
        }
    }
    if (exheaderpath == NULL || inputpath == NULL || outputpath == NULL) {
        printf("Usage: makeelf --exheader=exheader.bin [--symbols=idaexp.txt] -i {exefs.bin|code.bin} -o mh4g.elf\n");
    }

    exhdr_CodeSetInfo* exheader = 0;
    int exheadersize = readallcontent(exheaderpath, (void**)&exheader);

    if (exheadersize == 0) {
        printexclamatorymark();
        printf("Can't read exheader for codebin\n");
        return 5;
    }

    // TODO: merge symbols to debug sections
    SymbolMap exefssymbols = loadmapfromtxt(symbolspath); // from symbols.txt

    // TODO: extract from exefs instead codebin
    void* code = 0;
    int codesize = readallcontent(inputpath, &code);

    if (codesize == 0) {
        printexclamatorymark();
        printf("Can't read input codebin\n");
        return 5;
    }

    unsigned zibegin = exheader->data.address + exheader->data.codeSize;
    unsigned ziend = zibegin + exheader->bssSize;
    bool matched;

    bool retail = LocateZIForSection(code, codesize, exheader, &zibegin, &ziend, &matched);

    if (retail) {
        printf("Retail Game Detected.\nUse CTR style section names.\n");
    } else {
        printf("Maybe Homebrew.\nUsing devkit section names.\n");
    }

    if (retail && matched == false) {
        printf("Prefer ZI begin and end from code instead exheader.\n");
    }
    if (verbose) {
        printf("ZI Base: 0x%08X, ZI Limit: 0x%08X\n", zibegin, ziend);
    }

    elfio writer;

    // You can't proceed without this function call!
    writer.create(ELFCLASS32, ELFDATA2LSB);

    writer.set_os_abi(ELFOSABI_NONE);
    writer.set_type(ET_EXEC);
    writer.set_machine(EM_ARM);

    unsigned textoff = codebin_va_to_fileoffset(exheader, exheader->text.address, NULL);
    unsigned rodataoff = codebin_va_to_fileoffset(exheader, exheader->rodata.address, NULL);
    unsigned dataoff = codebin_va_to_fileoffset(exheader, exheader->data.address, NULL);

    unsigned zibeginoff = codebin_va_to_fileoffset(exheader, zibegin, NULL);
    unsigned ziendoff = codebin_va_to_fileoffset(exheader, ziend, NULL);

    VirtualSection textsect, constsect, datasect, bsssect;
    if (retail) {
        textsect.name = "STUP_ENTRY";
        constsect.name = "RO";
        datasect.name = "RW";
        bsssect.name = "ZI";
    } else {
        textsect.name = ".text";
        constsect.name = ".rodata";
        datasect.name = ".data";
        bsssect.name = ".bss";
    }

    textsect.content.insert(textsect.content.end(), (char*)code + textoff, (char*)code + textoff + exheader->text.codeSize);
    constsect.content.insert(constsect.content.end(), (char*)code + rodataoff, (char*)code + rodataoff + exheader->rodata.codeSize);
    datasect.content.insert(datasect.content.end(), (char*)code + dataoff, (char*)code + dataoff + exheader->data.codeSize);
    //bsssect.content.insert(bsssect.content.end(), (char*)code + zibeginoff, (char*)code + ziendoff);

    // Create code section
    section* text_sec = writer.sections.add(textsect.name);
    text_sec->set_type(SHT_PROGBITS);
    text_sec->set_flags(SHF_ALLOC | SHF_EXECINSTR);
    text_sec->set_addr_align(4);
    text_sec->set_data((const char*)textsect.content.data(), textsect.content.size());

    // Create a loadable segment
    segment* text_seg = writer.segments.add();
    text_seg->set_type(PT_LOAD);
    text_seg->set_virtual_address(exheader->text.address);
    text_seg->set_physical_address(exheader->text.address);
    text_seg->set_flags(PF_X | PF_R);
    text_seg->set_align(4);

    // Add code section into program segment
    text_seg->add_section_index(text_sec->get_index(), text_sec->get_addr_align());

    // const
    section* const_sec = writer.sections.add(constsect.name);
    const_sec->set_type(SHT_PROGBITS);
    const_sec->set_flags(SHF_ALLOC);
    const_sec->set_addr_align(4);
    const_sec->set_data((const char*)constsect.content.data(), constsect.content.size());

    // Create a read only segment
    segment* const_seg = writer.segments.add();
    const_seg->set_type(PT_LOAD);
    const_seg->set_virtual_address(exheader->rodata.address);
    const_seg->set_physical_address(exheader->rodata.address);
    const_seg->set_flags(PF_R);
    const_seg->set_align(4096);

    // Add const section into program segment
    const_seg->add_section_index(const_sec->get_index(), const_sec->get_addr_align());

    // Create data section*
    section* data_sec = writer.sections.add(datasect.name);
    data_sec->set_type(SHT_PROGBITS);
    data_sec->set_flags(SHF_ALLOC | SHF_WRITE);
    data_sec->set_addr_align(8);
    data_sec->set_data((const char*)datasect.content.data(), datasect.content.size());

    // Create a read/write segment
    segment* data_seg = writer.segments.add();
    data_seg->set_type(PT_LOAD);
    data_seg->set_virtual_address(exheader->data.address);
    data_seg->set_physical_address(exheader->data.address);
    data_seg->set_flags(PF_W | PF_R);
    data_seg->set_align(4096);

    // Add data section into program segment
    data_seg->add_section_index(data_sec->get_index(), data_sec->get_addr_align());

    // Create bss section
    section* bss_sec = writer.sections.add(bsssect.name);
    bss_sec->set_type(SHT_NOBITS);
    bss_sec->set_flags(SHF_ALLOC | SHF_WRITE);
    bss_sec->set_addr_align(8);
    bss_sec->set_size(ziend - zibegin);

    if (retail == false) {
        // Create a extra read/write segment
        segment* bss_seg = writer.segments.add();
        bss_seg->set_type(PT_LOAD);
        bss_seg->set_virtual_address(zibegin);
        bss_seg->set_physical_address(zibegin);
        bss_seg->set_flags(PF_W | PF_R);
        bss_seg->set_align(4096);

        // Add bss section into program segment
        bss_seg->add_section_index(bss_sec->get_index(), bss_sec->get_addr_align());
    } else {
        // using exists segment like rvct4nintendo does
        data_seg->add_section_index(bss_sec->get_index(), bss_sec->get_addr_align());
    }

    // Setup entry point
    writer.set_entry(exheader->data.address);   // _start

    // Create ELF file
    bool saveok = writer.save(outputpath);

    if (verbose) {
        printf("Save output file %s\n", (saveok ? "done." : "failed!"));
    }

    free(code);
    free(exheader);

    return saveok ? 0 : -1;
}

SymbolMap loadmapfromtxt(const wchar_t* path)
{
    SymbolMap result;
    if (path == NULL) {
        return result;
    }
    FILE* file = _wfopen(path, L"r");
    if (file == NULL) {
        return result;
    }
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        size_t length = strlen(line);
        while (line[length - 1] == '\n' || line[length - 1] == '\r') {
            line[length - 1] = 0;
            length--;
        }
        SymbolItem item;
        item.size = 0;
        item.undef = false;
        char name[500];
        sscanf(line, "%08X, %d, %s", &item.addr, &item.type, name);
        result.insert(make_pair(std::string(name), item));
    }
    fclose(file);
    return result;
}

void trimstr(char* str)
{
    // Left
    char* curpos = str;
    while (*curpos) {
        char c1 = *curpos;
        // [ ][ ]a
        if (c1 != ' ' && c1 != '\t') {
            memmove(str, curpos, strlen(curpos) + 1);
            break;
        }
        curpos++;
    }
    // Right
    curpos = str + strlen(str) - 1;
    while (*curpos) {
        char c1 = *curpos;
        // b[ ][ ]
        if (c1 != ' ' && c1 != '\t') {
            *(curpos + 1) = 0;
            break;
        }
        curpos--;
    }
}

void printfreespace(exhdr_CodeSetInfo* exheader)
{
    if (exheader->text.codeSize > exheader->text.numMaxPages * 0x1000) {
        printf("text section overflowed 0x%X bytes!\n", exheader->text.codeSize - exheader->text.numMaxPages * 0x1000);
    } else {
        printf("text section have 0x%X bytes gap left\n", exheader->text.numMaxPages * 0x1000 - exheader->text.codeSize);
    }
    if (exheader->rodata.codeSize > exheader->rodata.numMaxPages * 0x1000) {
        printf("rodata section overflowed 0x%X bytes!\n", exheader->rodata.codeSize - exheader->rodata.numMaxPages * 0x1000);
    } else {
        printf("rodata section have 0x%X bytes gap left\n", exheader->rodata.numMaxPages * 0x1000 - exheader->rodata.codeSize);
    }
}

void printexclamatorymark()
{
    printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
}