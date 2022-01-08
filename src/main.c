#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include "headers/handlers.h"
#define NUMBER_OF_SYSCALLS 332  // x86_64

handler_t* handlers[NUMBER_OF_SYSCALLS];

void setupHandlers() {
    size_t i;
    for (i = 0; i < NUMBER_OF_SYSCALLS; ++i) {
        handlers[i] = &defaultHandler;
    }
    handlers[SYS_write] = &writeHandler;
    handlers[SYS_read] = &readHandler;
    handlers[SYS_mmap] = &mmapHandler;
    handlers[SYS_execve] = &execveHandler;
    handlers[SYS_openat] = &openatHandler;
    handlers[SYS_fstat] = &fstatHandler;
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: SyscallTracer [path_to_executable] [-args-]\n");
        return -1;
    }
    // checking if file exists and is executable, on success, access returns 0
    if (access(argv[1], F_OK | X_OK)) {
        printf("File doesn't exist or isn't executable\n");
        return -1;
    }
    setupHandlers();
    pid_t tracee = fork();
    long orig_rax;
    if (tracee == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        argv++;
        execvp(argv[0], argv);
    } else if (tracee == -1) {
        perror("Fork error\n");
        return -1;
    } else {
        // parent process
        bool inSyscall = false;
        while (1) {
            long rax;
            int status;
            wait(&status);
            if (WIFEXITED(status)) {
                break;
            }
			// every entry on the user_regs struct is unsigned long
            orig_rax = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * ORIG_RAX, NULL);
            (*handlers[orig_rax])(tracee, &inSyscall);
            ptrace(PTRACE_SYSCALL, tracee, NULL, NULL);
        }
    }
    printf("+++ exited +++\n");
}
