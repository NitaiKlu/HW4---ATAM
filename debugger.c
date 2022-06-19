#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#define NUM_OF_ARGS 2
#define MAX_SIZE 200
int main(int argc, char **argv)
{
    pid_t child;
    if (argc != NUM_OF_ARGS)
    {
        return 1;
    }

    char * function = (char*)malloc(sizeof(char)*MAX_SIZE);
    strcpy(function, argv[0]);
    child = run_target(argv[1]);

    return 0;
}

int run_target(const char *program_name)
{
    pid_t child;
    child = fork();
    if (child == 0) // childish about to get debuggggedddd
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("TraceMe failed.");
            exit(1);
        }
        execv(program_name, program_name, NULL);
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

int run_debugger(pid_t child_pid, const char *program_name, const char* function)
{
    FILE *ElfFile = NULL;
    char *SectNames = NULL;
    Elf64_Sym elfSym;
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;
    Elf64_Sym sym;
    uint32_t idx;
    int wait_status;
    struct stat buf;
    if (wait(&wait_status) < 0)
    {
        perror("wait error.\n");
    }
    /**
     * 1-4 stages
     * */
    // if (!(stat(program_name, &buf) == 0 && buf.st_mode & S_IXUSR))
    // {
    //     /* non-executable */
    //     printf("PRF:: %s not an executable! :(\n", program_name);
    //     exit(1);
    // }
    // read ELF header, first thing in the file
    if ((ElfFile = fopen(program_name, "rw")) == NULL)
    {
        perror("[E] Error opening file:");
        exit(1);
    }
    fread(&elfHdr, 1, sizeof(Elf64_Ehdr), ElfFile);

    // stage 1 - executable
    if (elfHdr.e_type != ET_EXEC)
    {
        /* non-executable */
        printf("PRF:: %s not an executable! :(\n", program_name);
        exit(1);
    }

    // stage 2 - looking for function
    int flag = 0;
    char* SectNames = malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    fread(SectNames, 1, sectHdr.sh_size, ElfFile);

    // read all section headers
    for (int idx = 0; idx < elfHdr.e_shnum; idx++)
    {

        fseek(ElfFile, elfHdr.e_shoff + idx * sizeof sectHdr, SEEK_SET);
        fread(&sectHdr, 1, sizeof sectHdr, ElfFile);

        // if we got the symtab, we want to keep it for further use.
        if (sectHdr.sh_type == SHT_SYMTAB)
        {
            flag = 1;
            break;
        }  
    }
    free(SectNames);
    if(!flag) { // no symtab was found, unusual.
        perror("no symtab??");
        exit(1);
    }


    // read from symbol table
    flag = 0;
    for (int idx = 0; idx < ???; idx++)
    {

        fseek(ElfFile, sectHdr.sh_offset + idx * sizeof(Elf64_Sym), SEEK_SET);
        fread(&sym, 1, sizeof(Elf64_Sym), ElfFile);

        // if we got the symtab, we want to keep it for further use.
        if (strcmp(sym.st_name, function) == 0)
        {
            flag = 1;
            break;
        }  
    }
    if(!flag) {
        printf("PRF:: %s not found!\n", function);
        exit(1);
    }

    // stage 3 - global symbol or not
    if(sym.st_info != STB_GLOBAL) {
        printf("PRF:: %s is not a global symbol! :(\n", function);
        exit(1);
    }

    // stage 4 - check if the function is defined in a section 
    if(sym.st_shndx != SHN_UNDEF) {
        // dynamically alocated. 
        // stage 5 - 
    }
    // else - stage 6:

    wait(&wait_status);
    while (WIFSTOPPED(wait_status))
    {
    }
}