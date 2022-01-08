#ifndef __HANDLERS_H
#define __HANDLERS_H

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

typedef void (handler_t)(pid_t, bool*);

handler_t defaultHandler;

handler_t mmapHandler;
handler_t readHandler;
handler_t writeHandler;
handler_t execveHandler;
handler_t openatHandler;
handler_t fstatHandler;

#endif
