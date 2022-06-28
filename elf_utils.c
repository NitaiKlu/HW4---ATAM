#include "elf_utis.h"

#define MAGIC_LENGTH 4
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define STB_GLOBAL 1



int isExecutable(Elf64_Ehdr *hdr)
{
    return hdr->e_type == ET_EXEC;
}

int LoadHdr(int fd, Elf64_Ehdr *hdr)
{
    if (hdr == NULL)
        return 0;
    if (read(fd, hdr, sizeof(*hdr)) != sizeof(*hdr))
        return 0;
    if (memcmp("\x7f\x45\x4c\x46", hdr, MAGIC_LENGTH))
    {
        free(hdr);
        return 0;
    }

    return 1;
}

char *GetSectionAsString(int fd, Elf64_Shdr *Shdr)
{
    lseek(fd, Shdr->sh_offset, SEEK_SET);
    char *s = (char *)malloc(Shdr->sh_size);
    int n = read(fd, s, Shdr->sh_size);
    if (n != Shdr->sh_size)
    {
        // Could not read section
        free(s);
        return NULL;
    }
    return s;
}

int GetSectionHeader(int fd, Elf64_Ehdr *hdr, char *section_names, char *shdr_name,
                     Elf64_Shdr *shdr_to_fill)
{
    Elf64_Shdr *current_shdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    lseek(fd, hdr->e_shoff, SEEK_SET);
    int found = 0;
    for (int i = 0; i < hdr->e_shnum; i++)
    {
        if (read(fd, current_shdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr))
            break; // Could not read section header
        if (!strcmp(section_names + current_shdr->sh_name, shdr_name))
        {
            memcpy(shdr_to_fill, current_shdr, sizeof(Elf64_Shdr));
            found = 1;
            break;
        }
    }
    free(current_shdr);
    return found;
}

// returns the index of the symbol in the symtab or -1 if not found
int GetSymbol(int fd, Elf64_Shdr *symtab, char *func_name, char *symbol_names, Elf64_Sym *symbol_to_fill)
{
    // Go to symbol table
    lseek(fd, symtab->sh_offset, SEEK_SET);
    // Look for func's symbol
    int num_symbols = symtab->sh_size / symtab->sh_entsize;
    for (int i = 0; i < num_symbols; i++)
    {
        int n = read(fd, symbol_to_fill, symtab->sh_entsize);
        if (n != symtab->sh_entsize)
        {
            // Could not read symbol en
            return -1;
        }
        char *temp = symbol_names + symbol_to_fill->st_name;
        if (!strcmp(temp, func_name))
        {
            return i;
        }
    }
    // The symbol is not in the symtab
    return -1;
}

Elf64_Addr getRelaAddr(int fd, Elf64_Shdr *reloc_shdr, int dyn_index)
{
    /*
    if ((reloc_section = GetSectionAsString(fd, reloc_shdr)) == NULL)
    {
        FINISH(ELF_OPEN_FAIL);
    }
    Elf64_Rela *relocations = (Elf64_Rela *)reloc_section;
    *func_addr = relocations[dyn_index].r_offset;
    */

    Elf64_Rela rela_entry;
    // Go to rela table
    lseek(fd, reloc_shdr->sh_offset, SEEK_SET);
    // Look for func's symbol
    int num_symbols = reloc_shdr->sh_size / reloc_shdr->sh_entsize;
    for (int i = 0; i < num_symbols; i++)
    {
        int n = read(fd, (void *)&rela_entry, reloc_shdr->sh_entsize);
        if (n != reloc_shdr->sh_entsize)
        {
            // Could not read rela entry
            return -1;
        }
        int index = ELF64_R_SYM(rela_entry.r_info);
        if (index == dyn_index)
        {
            return rela_entry.r_offset;
        }
    }
    // The symbol is not in the symtab
    return -1;
}

int LoadShdrsNames(int fd, Elf64_Ehdr *hdr, char **shdrs_names)
{
    Elf64_Shdr *shdrs_strtab = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    // Go to section header table
    lseek(fd, hdr->e_shoff, SEEK_SET);
    // Get section header string table section header
    lseek(fd, hdr->e_shstrndx * sizeof(Elf64_Shdr), SEEK_CUR);
    if (read(fd, shdrs_strtab, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr))
    {
        free(shdrs_strtab);
        return 0; // could not load section header string table
    }
    if ((*shdrs_names = GetSectionAsString(fd, shdrs_strtab)) == NULL)
    {
        free(shdrs_strtab);
        return 0;
    }
    free(shdrs_strtab);
    return 1;
}

// returns the index of the symbol in the symtab or -1 if not found
// fills the symbol_to_fill with the symbol found
int FindSymbol(int fd, Elf64_Ehdr *hdr, char *func_name,
               Elf64_Sym *symbol_to_fill, int is_dynamic, char *shdrs_names)
{
    int num_symbols;
    char *symbol_names;
    Elf64_Shdr *symtab, *strtab;

    symtab = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    strtab = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));

    char *symtab_name = is_dynamic ? ".dynsym" : ".symtab";
    char *strtab_name = is_dynamic ? ".dynstr" : ".strtab";

    // Get symtab and strtab headers
    if (!GetSectionHeader(fd, hdr, shdrs_names, symtab_name, symtab) ||
        !GetSectionHeader(fd, hdr, shdrs_names, strtab_name, strtab))
    {
        // Could not find symtab or strtab
        free(symtab);
        free(strtab);
        return -1;
    }

    if ((symbol_names = GetSectionAsString(fd, strtab)) == NULL)
    {
        free(symtab);
        free(strtab);
        return -1;
    }
    int res = GetSymbol(fd, symtab, func_name, symbol_names, symbol_to_fill);
    free(symtab);
    free(strtab);
    return res;
}

int isGlobal(int fd, Elf64_Sym *symbol_en)
{
    return ELF64_ST_BIND(symbol_en->st_info) == STB_GLOBAL;
}

#define FINISH(status)             \
    do                             \
    {                              \
        if (fd != -1)              \
            close(fd);             \
        if (hdr != NULL)           \
            free(hdr);             \
        if (symbol != NULL)        \
            free(symbol);          \
        if (shdrs_names != NULL)   \
            free(shdrs_names);     \
        if (reloc_shdr != NULL)    \
            free(reloc_shdr);      \
        if (reloc_section != NULL) \
            free(reloc_section);   \
    } while (0);                   \
    return status;

elf_res getFuncAddr(char *prog_name, char *func_name, Elf64_Addr *func_addr)
{
    Elf64_Ehdr *hdr = NULL;
    Elf64_Sym *symbol = NULL;
    Elf64_Shdr *reloc_shdr = NULL;
    char *shdrs_names = NULL, *reloc_section = NULL;

    int fd = open(prog_name, O_RDONLY);
    if (fd == -1)
    {
        FINISH(ELF_OPEN_FAIL);
    }

    hdr = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
    if (!LoadHdr(fd, hdr))
    {
        FINISH(ELF_OPEN_FAIL);
    }

    if (!LoadShdrsNames(fd, hdr, &shdrs_names))
    {
        FINISH(ELF_OPEN_FAIL);
    }

    if (!isExecutable(hdr))
    {
        FINISH(ELF_NOT_EXECUTABLE);
    }
    symbol = (Elf64_Sym *)malloc(sizeof(Elf64_Sym));
    if (FindSymbol(fd, hdr, func_name, symbol, 0, shdrs_names) < 0)
    {
        FINISH(ELF_NOT_FOUND);
    }
    if (!isGlobal(fd, symbol))
    {
        FINISH(ELF_UND);
    }
    // FIND ADDRESS:
    if (symbol->st_shndx != SHN_UNDEF)
    {
        *func_addr = symbol->st_value;
        FINISH(ELF_STATIC);
    }
    else
    {
        int dyn_index = FindSymbol(fd, hdr, func_name, symbol, 1, shdrs_names);
        if (dyn_index < 0)
        {
            FINISH(ELF_NOT_FOUND);
        }

        reloc_shdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
        if (!GetSectionHeader(fd, hdr, shdrs_names, ".rela.plt", reloc_shdr))
        {
            // Lotan will hundle;
            printf("Could not find .rela\n");
        }
        *func_addr = getRelaAddr(fd, reloc_shdr, dyn_index);
        FINISH(ELF_DYNAMIC);
    }
}
