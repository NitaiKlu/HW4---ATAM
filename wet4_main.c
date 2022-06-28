#include <stdio.h>
#include <stdlib.h>
#include "revivo_debugger.h"
#include "elf_utils.h"

#define MIN_ARG_C 3

pid_t run_target(const char *program_name, char **argv)
{
    pid_t pid;

    pid = fork();

    if (pid > 0)
    {
        return pid;
    }
    else if (pid == 0)
    {
        // Allow tracing of this process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("ptrace");
            exit(1);
        }
        // Replace this process's image with the given program
        execv(program_name, argv + 2);
    }
    else
    {
        // fork error
        perror("fork");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    pid_t child_pid;
    Elf64_Addr func_addr;

    char *func_name, *prog_name;
    if (argc < MIN_ARG_C)
    {
        fprintf(stderr, "PRF:: Not enough args");
        exit(1);
    }
    func_name = argv[1];
    prog_name = argv[2];

    elf_res res = getFuncAddr(prog_name, func_name, &func_addr);
    switch (res)
    {
    case ELF_OPEN_FAIL:
        printf("Elf open failed\n");
        exit(1);
    case ELF_NOT_EXECUTABLE:
        printf("PRF:: %s not an executable! :(\n", prog_name);
        exit(1);
    case ELF_NOT_FOUND:
        printf("PRF:: %s not found!\n", func_name);
        exit(1);
    case ELF_UND:
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        exit(1);
    }
    
    child_pid = run_target(prog_name, argv);
    run_revivo_debugger(child_pid, func_addr, res == ELF_DYNAMIC);

    return 0;
}