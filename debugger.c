#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>
#include "reg.h"
#include <elf.h>
#include <string.h>
#include <sys/wait.h>
#define NUM_OF_ARGS 2
#define MAX_SIZE 200

pid_t run_target(const char *program_name, char **argv)
{
    pid_t child;
    child = fork();

    if (child > 0)
        return child;
    else if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("TraceMe failed.");
            exit(1);
        }
        execv(program_name, argv + 2);
    }
    else
    {
        perror("fork failed.");
        exit(1);
    }
}

int readSectionHeader(FILE *file, Elf64_Ehdr *hdr, char *SectNames, char *shdr_name,
                      Elf64_Shdr *sect_hdr) // to change/////////////////////////////
{
    int fd = fileno(file);
    Elf64_Shdr *header = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    lseek(fd, hdr->e_shoff, SEEK_SET);
    // int found = 0;  // remove this guy
    for (int i = 0; i < hdr->e_shnum; i++)
    {
        if (read(fd, header, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr))
        {
            free(header);
            return 0;
        }
        if (!strcmp(SectNames + header->sh_name, shdr_name))
        {
            memcpy(sect_hdr, header, sizeof(Elf64_Shdr));
            free(header);
            return 1;
        }
    }
    free(header);
    return 0; // was 'found', check again guy
}

char *getString(FILE *file, Elf64_Shdr *header)
{
    int fd = fileno(file);
    lseek(fd, header->sh_offset, SEEK_SET);
    char *str = (char *)malloc(header->sh_size);
    if (read(fd, str, header->sh_size) != header->sh_size)
    {
        free(str);
        return NULL;
    }
    return str;
}

int getHeaders(FILE *file, Elf64_Ehdr *hdr, char **names)
{
    int fd = fileno(file);
    Elf64_Shdr *strTabHdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    // Go to section header table
    lseek(fd, hdr->e_shoff, SEEK_SET);
    // Get section header string table section header
    lseek(fd, hdr->e_shstrndx * sizeof(Elf64_Shdr), SEEK_CUR);
    if (read(fd, strTabHdr, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr))
    {
        free(strTabHdr);
        return 0; // could not load section header string table
    }
    if ((*names = getString(file, strTabHdr)) == NULL)
    {
        free(strTabHdr);
        return 0;
    }
    free(strTabHdr);
    return 1;
}

int findSymbol(FILE *file, const char *function, Elf64_Shdr *dynsym, Elf64_Sym *symbol, char *string_section)
{
    int fd = fileno(file);
    lseek(fd, dynsym->sh_offset, SEEK_SET);
    symbol = (Elf64_Sym *)malloc(sizeof(Elf64_Sym *));
    int num_of_symbols = dynsym->sh_size / dynsym->sh_entsize;
    for (int i = 0; i < num_of_symbols; i++)
    {
        int n = read(fd, symbol, dynsym->sh_entsize);
        if (n != dynsym->sh_entsize)
            return -1;
        char *temp = string_section + symbol->st_name;
        if (!strcmp(temp, function))
        {
            return i;
        }
    }
}

Elf64_Addr check_data(const char *program_name, const char *function, Elf64_Addr *address)
{
    FILE *ElfFile;
    char *SectNames = NULL;
    Elf64_Sym elfSym;
    Elf64_Ehdr *elfHdr = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
    Elf64_Shdr *sectHdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr *dynShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr *relaShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr *symTabShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr *targetShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr *strTabShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr *dynStrShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Sym sym;
    Elf64_Sym dynSym;
    uint32_t idx;
    int wait_status;

    // read ELF header, first thing in the file
    ElfFile = fopen("/home/student/Documents/atam/hw4/out", "rw");
    int fd = fileno(ElfFile);
    if (ElfFile == NULL)
    {
        perror("[E] Error opening file:");
        exit(1);
    }
    if (read(fd, elfHdr, sizeof(*elfHdr)) != sizeof(*elfHdr))
        exit(1);
    if (memcmp("\x7f\x45\x4c\x46", elfHdr, 4))
    {
        free(elfHdr);
        exit(1);
    }

    // stage 1 - executable
    if (elfHdr->e_type != ET_EXEC)
    {
        /* non-executable */
        printf("PRF:: %s not an executable! :(\n", program_name);
        exit(1);
    }

    getHeaders(ElfFile, elfHdr, &SectNames);

    // stage 2 - looking for function
    if (!readSectionHeader(ElfFile, elfHdr, SectNames, ".symtab", symTabShdr))
    {
        printf("PRF:: %s not found!\n", function);
        exit(1);
    }
    // I THINK we should malloc every struct that use fread ?!
    readSectionHeader(ElfFile, elfHdr, SectNames, ".dynsym", dynShdr);
    readSectionHeader(ElfFile, elfHdr, SectNames, ".strtab", strTabShdr);
    readSectionHeader(ElfFile, elfHdr, SectNames, ".dynstr", dynStrShdr);
    readSectionHeader(ElfFile, elfHdr, SectNames, ".rela.plt", relaShdr);

    char *strings = NULL;
    strings = getString(ElfFile, strTabShdr);
    Elf64_Sym function_sym;
    int flag = 0;
    int index_of_symbol;
    int num_of_symbols = symTabShdr->sh_size / symTabShdr->sh_entsize;
    lseek(fd, symTabShdr->sh_offset, SEEK_SET);
    for (int idx = 0; idx < num_of_symbols; idx++)
    {
        read(fd, &sym, symTabShdr->sh_entsize);

        if (strcmp(strings + sym.st_name, function) == 0)
        {
            flag = 1;
            index_of_symbol = idx;
            function_sym = sym;
            if (ELF64_ST_BIND(sym.st_info) == STB_GLOBAL)
            {
                break;
            }
        }
    }
    if (!flag)
    {
        printf("PRF:: %s not found!\n", function);
        exit(1);
    }

    // stage 3 - global symbol or not
    if (ELF64_ST_BIND(function_sym.st_info) != STB_GLOBAL)
    {
        printf("PRF:: %s is not a global symbol! :(\n", function);
        exit(1);
    }

    int index_in_dynsym = -1;
    // stage 4 - check if the function is defined in a section
    if (function_sym.st_shndx == SHN_UNDEF)
    {
        // dynamically alocated.
        // stage 5 - find the ptr location
        char *dyn_str = NULL;
        dyn_str = getString(ElfFile, dynStrShdr);
        Elf64_Sym *dyn_sym_func = NULL;
        int dyn_index = findSymbol(ElfFile, function, dynShdr, dyn_sym_func, dyn_str);
        // free(dyn_sym_func); // guy
        if (dyn_index < 0)
        {
            printf("PRF:: %s not found!\n", function);
            exit(1);
        }

        Elf64_Rela rela;
        lseek(fd, relaShdr->sh_offset, SEEK_SET);
        // Look for func's symbol in rela plt
        int num_of_symbols = relaShdr->sh_size / relaShdr->sh_entsize;
        for (int i = 0; i < num_of_symbols; i++)
        {
            int n = read(fd, (void *)&rela, relaShdr->sh_entsize);
            if (n != relaShdr->sh_entsize)
                return -1;
            int index = ELF64_R_SYM(rela.r_info);
            if (index == dyn_index)
            {
                *address = rela.r_offset;
            }
        }
        // The symbol is not in the symtab
        free(ElfFile); // guy
        free(symTabShdr); // guy
        return 1;
    }
    else
    {
        // st_value is the offset within st_shndx (the section index)
        *address = function_sym.st_value;
        free(ElfFile); // guy
        free(symTabShdr); // guy
        return 0;
    }
    
}

void debugger(pid_t child_pid, Elf64_Addr address, int is_dynamic)
{
    int wait_status;
    struct user_regs_struct regs;
    unsigned long data, data_trap, next_instr, next_trap;
    Elf64_Addr got_entry, next_addr, stack_addr, base_address;
    int counter = 0;

    /* Wait for child to stop on its first instruction */
    waitpid(child_pid, &wait_status, 0);

    if (is_dynamic)
    {
        got_entry = address;
        address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)got_entry, NULL);
    }

    /* Look at the word at the address we're interested in */
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)address, NULL);

    /* Write the trap instruction 'int 3' into the address */
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *)address, (void *)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    waitpid(child_pid, &wait_status, 0);

    while (!WIFEXITED(wait_status))
    {
        counter++;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        base_address = regs.rsp + 8;
        // change the command back:
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void *)address, (void *)data);
        // next cmd:
        stack_addr = regs.rsp;
        next_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)stack_addr, NULL);
        // Add break point at return addres
        next_instr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)next_addr, NULL);
        next_trap = (next_instr & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *)next_addr, (void *)next_trap);

        // child run to next instr
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        waitpid(child_pid, &wait_status, 0);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        while (regs.rsp != base_address)
        {
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void *)next_addr, (void *)next_instr);
            ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0);
            if(waitpid(child_pid, &wait_status, 0) == -1)
                exit(1);
            ptrace(PTRACE_POKETEXT, child_pid, next_addr, next_trap);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            if(waitpid(child_pid, &wait_status, 0) == -1)
                exit(1);
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        }
        // ret val
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        unsigned long long return_value = regs.rax;
        printf("PRF:: run #%d returned with %lld\n", counter, return_value);

        // Remove the second breakpoint by restoring the previous data
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void *)next_addr, (void *)next_instr);

        // add the first breakpoint
        if (is_dynamic && counter == 1)
        {
            // Now the data in the GOT entry is symbol's addres
            address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)got_entry, NULL);
            data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)address, NULL);
            data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        }
        ptrace(PTRACE_POKETEXT, child_pid, (void *)address, (void *)data_trap);

        // Let the child run to the breakpoint and wait for it to reach it
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        waitpid(child_pid, &wait_status, 0);
    }
}

int main(int argc, char **argv)
{
    pid_t child_pid;
    char *function = (char *)malloc(sizeof(char) * MAX_SIZE);
    function = argv[1];
    char *program = (char *)malloc(sizeof(char) * MAX_SIZE);
    program = argv[2];
    Elf64_Addr *address = (Elf64_Addr *)malloc(sizeof(Elf64_Addr));
    int is_dynamic = check_data(program, function, address);
    // printf("%ld", *address);
    child_pid = run_target(program, argv);
    debugger(child_pid, *address, is_dynamic);

    free(function);
    free(program);
    free(address);

    return 0;
}
