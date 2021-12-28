#include "headers/utils.h"

#define haszero(v) (((v) - 0x01010101UL) & ~(v) & 0x80808080UL)

char* getStringAtAddress(unsigned long address, pid_t tracee, int maxLen) {
    char* buf = (char*) calloc(32, sizeof(char));
    // basically char[8]
    long temp;
    size_t currSize = 0;
    size_t overallSize = sizeof(buf);
    bool eos = false;
    while (!eos) {
        temp = ptrace(PTRACE_PEEKDATA, tracee, address + currSize, NULL);
		if (currSize >= maxLen) {
			eos = true;
		}
        strncat(buf, (char*)&temp, sizeof(temp));
        if (strnlen((char*)&temp, 8) < 8) {
            eos = true;
        }
        currSize += sizeof(temp);
        if (overallSize == currSize) {
            buf = realloc(buf, 2 * overallSize);
            overallSize *= 2;
        }
    }
    return buf;
}
