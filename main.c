#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#define BITS 8  // 4 on 32 bit


void writeHandler(pid_t tracee, bool* inSyscall) {
    // in the future maybe make a syscall to number of params map
    // and reduce the number of handlers to 7
    long params[3];
    if (!*inSyscall) {
        *inSyscall = true;
        params[0] = ptrace(PTRACE_PEEKUSER, tracee, BITS * RDI, NULL);
        params[1] = ptrace(PTRACE_PEEKUSER, tracee, BITS * RSI, NULL);
        params[2] = ptrace(PTRACE_PEEKUSER, tracee, BITS * RDX, NULL);
        printf("SYS_write called with "
                       "0x%lx, 0x%lx, 0x%lx\n",
                       params[0], params[1],
                       params[2]);
    } else {
        long returnValue = ptrace(PTRACE_PEEKUSER, tracee, BITS * RAX, NULL);
        printf("SYS_write returned %ld\n", returnValue);
        *inSyscall = false;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage Koskasyscall [path_to_executable] [-args-]\n");
        return -1;
    }
    // checking if file exists and is executable, on success, access returns 0
    if (access(argv[1], F_OK | X_OK)) {
        printf("File doesn't exist or isn't executable\n");
        return -1;
    }
    pid_t tracee = fork();
	long orig_rax;
    if (tracee == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(argv[1], argv+1);
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
            orig_rax = ptrace(PTRACE_PEEKUSER, tracee, BITS * ORIG_RAX, NULL);
            switch (orig_rax) {
                case SYS_write:
                    writeHandler(tracee, &inSyscall);
                    break;
                default:
                    printf("User called syscall: %ld\n", orig_rax);
                    break;
            }
		    ptrace(PTRACE_SYSCALL, tracee, NULL, NULL);
		}
    }
    printf("+++ exited +++\n");
}
