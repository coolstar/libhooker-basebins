#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <string.h>

#if __LP64__
#define LHnlist nlist_64
#else
#define LHnlist nlist
#endif

#define guardRetFalse(x) if (x){return false;}

bool linksSymbol(const void *hdr,
                             uintptr_t slide,
                             const char *symbolName){
#if __LP64__
    const struct mach_header_64 *machHeader = hdr;
    guardRetFalse(machHeader->magic != MH_MAGIC_64);
#else
    const struct mach_header *machHeader = hdr;
    guardRetFalse(machHeader->magic != MH_MAGIC);
#endif
    
    uint32_t ncmds = machHeader->ncmds;
    struct load_command *loadCmd = (void *)(machHeader + 1);
    struct symtab_command *symtabCmd = NULL;
    for (uint32_t i = 0; i < ncmds; i++){
        if (loadCmd->cmd == LC_SYMTAB){
            symtabCmd = (struct symtab_command *)loadCmd;
            break;
        }
        loadCmd = (void *)loadCmd + loadCmd->cmdsize;
    }
    
    guardRetFalse(symtabCmd == NULL);
    
    struct LHnlist *symbols = NULL;
    const char *strings = NULL;
    loadCmd = (void *)(machHeader + 1);
    for (uint32_t i = 0; i < ncmds; i++){
#if __LP64__
        if (loadCmd->cmd == LC_SEGMENT_64){
            struct segment_command_64 *seg = (void *)loadCmd;
#else
        if (loadCmd->cmd == LC_SEGMENT){
            struct segment_command *seg = (void *)loadCmd;
#endif
            if (symtabCmd->symoff - seg->fileoff < seg->filesize)
                symbols = (void *)seg->vmaddr + symtabCmd->symoff - seg->fileoff;
            if (symtabCmd->stroff - seg->fileoff < seg->filesize)
                strings = (void *)seg->vmaddr + symtabCmd->stroff - seg->fileoff;
            if (slide == -1 && !strcmp(seg->segname, "__TEXT")){
                slide = (uintptr_t)hdr - seg->vmaddr + seg->fileoff;
            }
            if (symbols && strings)
                break;
        }
        loadCmd = (void *)loadCmd + loadCmd->cmdsize;
    }
    
    guardRetFalse(symbols == NULL || strings == NULL);
    
    symbols = (void *)symbols + slide;
    strings = (void *)strings + slide;
        
    for (uint32_t i = 0; i < symtabCmd->nsyms; i++){
        const struct LHnlist *symbol = &symbols[i];
        const char *name = (symbol->n_un.n_strx != 0) ? strings + symbol->n_un.n_strx : "";
        if (!strcmp(name, symbolName)){
            return true;
        }
    }
    return false;
}