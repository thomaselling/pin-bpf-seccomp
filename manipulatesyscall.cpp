#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <tr1/unordered_map>
#include <stdlib.h>
#include <errno.h>
//#include <asm/unaligned.h>
#include </usr/src/kernels/3.7.9-104.fc17.x86_64/include/uapi/linux/prctl.h>
#include <sys/types.h>
#include </usr/include/asm/unistd_64.h>
#include "pin.H"

using namespace std;
using namespace std::tr1;

typedef struct seccomp_data {
    uint32_t    nr;
    uint32_t    arch;
    uint64_t    instruction_pointer;
    uint64_t    args[6];
} seccomp_data_t;

unordered_map <uint64_t, bool> hashmap;
unordered_map<uint64_t, bool>::const_iterator it;

void syscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    seccomp_data_t seccomp;

    seccomp.nr = (uint64_t)PIN_GetSyscallNumber(ctxt, std);
    seccomp.args[0] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 0);
    seccomp.args[1] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 1);
    seccomp.args[2] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 2);
    seccomp.args[3] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 3);
    seccomp.args[4] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 4);
    seccomp.args[5] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 5);

    hashmap[threadIndex] = false;


    //TODO prctl syscallnum = 157
    if (seccomp.nr == 157) {
        fprintf(stdout, "INFO: (from syscallentry)seccomp.nr = %d\n", seccomp.nr);
        PIN_SetSyscallNumber(ctxt, std, 39); 
        seccomp.nr = (uint64_t)PIN_GetSyscallNumber(ctxt, std);
        fprintf(stdout, "INFO: AFTER SETSYSCALL seccomp.nr = %d\n", seccomp.nr);
        hashmap[threadIndex] = true;
    }

    //fprintf(stdout, "seccomp.nr = %d\n", seccomp.nr);
    //thread = PIN_ThreadUid();
    //fprintf(stdout, "ThreadIndex = %lu\n", thread);

    cout << "\nhashmap contains:";
    for (it = hashmap.begin(); it != hashmap.end(); it++) {
        cout << " " << it->first << ":" << it->second;
    }
    cout << endl;

    fprintf(stdout, "INFO: EXIT %s\n", __FUNCTION__);
}

void syscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    ADDRINT return_value;

    for (it = hashmap.begin(); it != hashmap.end(); ++it) {
        if (it->second == true) {
            cout << "threadid " << it->first << " is true" << endl;
            return_value = PIN_GetContextReg(ctxt, REG_GAX);
            fprintf(stdout, "REG_GAX = %lu\n", return_value);
            PIN_SetContextReg(ctxt, REG_GAX, 0);
            return_value = PIN_GetContextReg(ctxt, REG_GAX);
            fprintf(stdout, "REG_GAX = %lu\n", return_value);
        } else {
            cout << "threadid " << it->first << " is false" << endl;
        }
    }

}

int32_t main(int32_t argc, char *argv[])
{
    if (PIN_Init(argc, argv))
    {
        printf("Usage: \n");
        return 0;
    }

    fprintf(stdout, "call PIN_AddSyscallEntryFunction\n");
    PIN_AddSyscallEntryFunction(&syscallEntry, NULL);

    fprintf(stdout, "call PIN_AddSyscallExitFunction\n");
    PIN_AddSyscallExitFunction(&syscallExit, NULL);

    fprintf(stdout, "call PIN_StartProgram()\n");
    PIN_StartProgram();

    return(0);
}
