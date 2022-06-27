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


int run_target(const char *program_name, char **argv)
{
    // printf("run target");
    pid_t child;
    child = fork();
    if (child == 0) // childish about to get debuggggedddd
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("TraceMe failed.");
            exit(1);
        }
        execv(program_name, argv + 2);
    }
    else if (child > 0)
    {
        // imma debug my childddd morty
        return child;
    }
    else
    {
        // error
        perror("fork failed.");
        exit(1);
    }
}

int readSectionHeader(FILE *file, Elf64_Ehdr *hdr, char *section_names, char *shdr_name,
                      Elf64_Shdr *shdr_to_fill) // to change/////////////////////////////
{
    // printf("section getting:%s", shdr_name);
    Elf64_Shdr *header = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    fseek(file, hdr->e_shoff, SEEK_SET);
    int found = 0;
    for (int i = 0; i < hdr->e_shnum; i++)
    {
        if (fread(header, sizeof(Elf64_Shdr), 1, file) != sizeof(Elf64_Shdr))
            break; // Could not read section header
        if (!strcmp(section_names + header->sh_name, shdr_name))
        {
            memcpy(shdr_to_fill, header, sizeof(Elf64_Shdr));
            found = 1;
            break;
        }
    }
    free(header);
    return found;
}

char *getString(FILE *file, Elf64_Shdr *Shdr)
{
    fseek(file, Shdr->sh_offset, SEEK_SET);
    char *s = (char *)malloc(Shdr->sh_size);
    int n = fread(s, Shdr->sh_size, 1, file);
    if (n != Shdr->sh_size)
    {
        // Could not read section
        printf("her!!");
        free(s);
        return NULL;
    }
    printf("%s",s);
    return s;
}

int getHeaders(FILE *file, Elf64_Ehdr *hdr, char **names)
{
    Elf64_Shdr *shdrs_strtab = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    // Go to section header table
    fseek(file, hdr->e_shoff, SEEK_SET);
    // Get section header string table section header
    fseek(file, hdr->e_shstrndx * sizeof(Elf64_Shdr), SEEK_CUR);
    if (fread(shdrs_strtab, sizeof(Elf64_Shdr), 1, file) != sizeof(Elf64_Shdr))
    {
        free(shdrs_strtab);
        return 0; // could not load section header string table
    }
    if ((*names = getString(file, shdrs_strtab)) == NULL)
    {
        free(shdrs_strtab);
        return 0;
    }
    free(shdrs_strtab);
    return 1;
}

int findSymbol(FILE *file, const char *function, Elf64_Shdr *dynsym, Elf64_Sym *symbol, char *string_section)
{
    // Go to symbol table
    fseek(file, dynsym->sh_offset, SEEK_SET);
    // Look for func's symbol
    int num_symbols = dynsym->sh_size / dynsym->sh_entsize;
    for (int i = 0; i < num_symbols; i++)
    {
        int n = fread(symbol, dynsym->sh_entsize, 1, file);
        if (n != dynsym->sh_entsize)
        {
            // Could not read symbol en
            return -1;
        }
        char *temp = string_section + symbol->st_name;
        if (!strcmp(temp, function))
        {
            return i;
        }
    }
}

Elf64_Addr check_data(const char *program_name, const char *function, Elf64_Addr *address)
{
    FILE *ElfFile = NULL;
    char *SectNames = NULL;
    Elf64_Sym elfSym;
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;
    Elf64_Shdr dynShdr;
    Elf64_Shdr relaShdr;
    Elf64_Shdr *symTabShdr = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr targetShdr;
    Elf64_Shdr strTabShdr;
    Elf64_Shdr dynStrShdr;
    Elf64_Sym sym;
    Elf64_Sym dynSym;
    uint32_t idx;
    int wait_status;

    // read ELF header, first thing in the file
    if ((ElfFile = fopen(program_name, "rw")) == NULL)
    {
        perror("[E] Error opening file:");
        exit(1);
    }
    fread(&elfHdr, sizeof(Elf64_Ehdr), 1, ElfFile);

    // stage 1 - executable
    if (elfHdr.e_type != ET_EXEC)
    {
        /* non-executable */
        printf("PRF:: %s not an executable! :(\n", program_name);
        exit(1);
    }
    printf("before get Headers\n");
    getHeaders(ElfFile, &elfHdr, &SectNames);
    printf("%s\n", SectNames);
    // stage 2 - looking for function
    if (!readSectionHeader(ElfFile, &elfHdr, SectNames, ".symtab", symTabShdr))
    {
        printf("PRF:: %s not found! 1\n", function);
        exit(1);
    }
    readSectionHeader(ElfFile, &elfHdr, SectNames, ".dynsym", &dynShdr);
    readSectionHeader(ElfFile, &elfHdr, SectNames, ".strtab", &strTabShdr);
    readSectionHeader(ElfFile, &elfHdr, SectNames, ".dynstr", &dynStrShdr);
    readSectionHeader(ElfFile, &elfHdr, SectNames, ".rela.plt", &relaShdr);
   
    Elf64_Sym function_sym;
    int flag = 0;
    int index_of_symbol;
    int num_of_symbols = symTabShdr->sh_size / symTabShdr->sh_entsize;
    for (int idx = 0; idx < num_of_symbols; idx++)
    {
        fseek(ElfFile, symTabShdr->sh_offset + idx * symTabShdr->sh_entsize, SEEK_SET);
        fread(&sym, symTabShdr->sh_entsize, 1, ElfFile);

        if (strcmp(SectNames + sym.st_name, function) == 0)
        {
            index_of_symbol = idx;
            flag = 1;
            function_sym = sym;
            break;
        }
    }
    if (!flag)
    {
        printf("PRF:: %s not found! 2\n", function);
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
    if (function_sym.st_shndx != SHN_UNDEF)
    {
        // dynamically alocated.
        // stage 5 - find the ptr location
        char *dyn_str = getString(ElfFile, &dynStrShdr);
        Elf64_Sym dyn_sym_func;
        int dyn_index = findSymbol(ElfFile, function, &dynShdr, &dyn_sym_func, dyn_str);
        if (dyn_index < 0)
        {
            printf("PRF:: %s not found! 3\n", function);
            exit(1);
        }

        Elf64_Rela rela;
        // Go to rela table
        fseek(ElfFile, relaShdr.sh_offset, SEEK_SET);
        // Look for func's symbol
        int num_symbols = relaShdr.sh_size / relaShdr.sh_entsize;
        for (int i = 0; i < num_symbols; i++)
        {
            int n = fread((void *)&rela, relaShdr.sh_entsize, 1, ElfFile);
            if (n != relaShdr.sh_entsize)
            {
                // Could not read rela entry
                return -1;
            }
            int index = ELF64_R_SYM(rela.r_info);
            if (index == dyn_index)
            {
                *address = rela.r_offset;
            }
        }
        // The symbol is not in the symtab
        return 1;
    }
    else
    {
        // st_value is the offset within st_shndx (the section index)
        *address = function_sym.st_value;
        return 0;
    }
}

void debugger(pid_t child_pid, Elf64_Addr *address, int is_dynamic)
{
    int wait_status;
    struct user_regs_struct regs;
    unsigned long data, data_trap, next_instr, next_trap;
    Elf64_Addr got_entry, next_addr, stack_addr;
    int counter = 0;

    /* Wait for child to stop on its first instruction */
    waitpid(child_pid, &wait_status, 0);

    if (is_dynamic)
    {
        got_entry = *address;
        *address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)got_entry, NULL);
    }

    /* Look at the word at the address we're interested in */
    data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)address, NULL);

    /* Write the trap instruction 'int 3' into the address */
    data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void *)address, (void *)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    waitpid(child_pid, &wait_status, 0);

    while(!WIFEXITED(wait_status))
    {
        counter++;
        //change the command back:
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        ptrace(PTRACE_POKETEXT, child_pid, (void *)address, (void *)data);
        //next cmd:
        stack_addr = regs.rsp;
        next_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)stack_addr, NULL);
        // Add break point at return addres
        next_instr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)next_addr, NULL);
        next_trap = (next_instr & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *)next_addr, (void *)next_trap);

        // child run to next instr
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        waitpid(child_pid, &wait_status, 0);

        //ret val
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
            *address = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)got_entry, NULL);
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
    pid_t child;
    // if (argc != NUM_OF_ARGS)
    // {
    //     return 1;
    // }
    
    char *function = (char *)malloc(sizeof(char) * MAX_SIZE);
    char *program = (char *)malloc(sizeof(char) * MAX_SIZE);
    strcpy(function, argv[1]);
    strcpy(program, argv[2]);
    Elf64_Addr *address = (Elf64_Addr *)malloc(sizeof(Elf64_Addr));
    printf("before everything");
    int is_dynamic = check_data(program, function, address);
    int child_pid = run_target(program, argv);
    debugger(child_pid, address, is_dynamic);
    free(function);
    free(program);
    free(address);
    return 0;
}