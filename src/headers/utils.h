#ifndef __UTILS_H
#define __UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/ptrace.h>

char* getStringAtAddress(unsigned long address, pid_t tracee, int maxLen);

#endif