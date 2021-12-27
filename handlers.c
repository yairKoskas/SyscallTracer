#include "handlers.h"

void defaultHandler(pid_t tracee, bool* inSyscall) {
    return;
}

void readHandler(pid_t tracee, bool* inSyscall) {
    long params[3];
    if (!*inSyscall) {
        *inSyscall = true;
        params[0] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RDI, NULL);
        params[1] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RSI, NULL);
        params[2] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RDX, NULL);
        printf("SYS_read("
                    "0x%lx, 0x%lx, 0x%lx)\n",
                    params[0], params[1],
                    params[2]);
    } else {
        long returnValue = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RAX, NULL);
        printf("SYS_read returned 0x%lx\n", returnValue);
        *inSyscall = false;
    }
}

void mmapHandler(pid_t tracee, bool* inSyscall) {
    long params[6];
    if (!*inSyscall) {
        *inSyscall = true;
        params[0] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RDI, NULL);
        params[1] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RSI, NULL);
        params[2] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RDX, NULL);
        params[3] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * R10, NULL);
        params[4] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * R8, NULL);
        params[5] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * R9, NULL);
        printf("SYS_mmap("
                    "0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
                    params[0], params[1],
                    params[2], params[3],
					params[4], params[5]);
    } else {
        long returnValue = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RAX, NULL);
        printf("SYS_mmap returned 0x%lx\n", returnValue);
        *inSyscall = false;
    }
}

void writeHandler(pid_t tracee, bool* inSyscall) {
    // in the future maybe make a syscall to number of params map
    // and reduce the number of handlers to 7
    long params[3];
    if (!*inSyscall) {
        *inSyscall = true;
        params[0] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RDI, NULL);
        params[1] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RSI, NULL);
        // params[1] is a pointer to a string, get it with PEEKDATA
        params[2] = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RDX, NULL);
        printf("SYS_write("
                       "0x%lx, 0x%lx, 0x%lx)\n",
                       params[0], params[1],
                       params[2]);
    } else {
        long returnValue = ptrace(PTRACE_PEEKUSER, tracee, sizeof(unsigned long) * RAX, NULL);
        printf("SYS_write returned %ld\n", returnValue);
        *inSyscall = false;
    }
}
