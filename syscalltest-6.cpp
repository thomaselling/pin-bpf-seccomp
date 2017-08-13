#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
//#include <asm/unaligned.h>
#include </usr/src/kernels/3.7.9-104.fc17.x86_64/include/uapi/linux/prctl.h>
#include </usr/include/asm/unistd_64.h>
#include "pin.H"


/*
 * Instruction classes
 */

#define BPF_CLASS(code) ((code) & 0x07)
#define         BPF_LD          0x00
#define         BPF_LDX         0x01
#define         BPF_ST          0x02
#define         BPF_STX         0x03
#define         BPF_ALU         0x04
#define         BPF_JMP         0x05
#define         BPF_RET         0x06
#define         BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define         BPF_W           0x00
#define         BPF_H           0x08
#define         BPF_B           0x10
#define BPF_MODE(code)  ((code) & 0xe0)
#define         BPF_IMM         0x00
#define         BPF_ABS         0x20
#define         BPF_IND         0x40
#define         BPF_MEM         0x60
#define         BPF_LEN         0x80
#define         BPF_MSH         0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define         BPF_ADD         0x00
#define         BPF_SUB         0x10
#define         BPF_MUL         0x20
#define         BPF_DIV         0x30
#define         BPF_OR          0x40
#define         BPF_AND         0x50
#define         BPF_LSH         0x60
#define         BPF_RSH         0x70
#define         BPF_NEG         0x80
#define         BPF_MOD         0x90
#define         BPF_XOR         0xa0

#define         BPF_JA          0x00
#define         BPF_JEQ         0x10
#define         BPF_JGT         0x20
#define         BPF_JGE         0x30
#define         BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define         BPF_K           0x00
#define         BPF_X           0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)  ((code) & 0x18)
#define         BPF_A           0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

/*  
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/*
 * Number of scratch memory words for: BPF_ST and BPF_STX
 */

#define BPF_MEMWORDS 16

/* RATIONALE. Negative offsets are invalid in BPF.
 * We use them to reference ancillary data.
 * Unlike introduction new instructions, it does not break
 * existing compilers/optimizers.
 */
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE  4
#define SKF_AD_IFINDEX  8
#define SKF_AD_NLATTR   12
#define SKF_AD_NLATTR_NEST      16
#define SKF_AD_MARK     20
#define SKF_AD_QUEUE    24
#define SKF_AD_HATYPE   28
#define SKF_AD_RXHASH   32
#define SKF_AD_CPU      36
#define SKF_AD_ALU_XOR_X        40
#define SKF_AD_MAX      44
#define SKF_NET_OFF   (-0x100000)
#define SKF_LL_OFF    (-0x200000)

enum {
    BPF_S_RET_K = 1,
    BPF_S_RET_A,
    BPF_S_ALU_ADD_K,
    BPF_S_ALU_ADD_X,
    BPF_S_ALU_SUB_K,
    BPF_S_ALU_SUB_X,
    BPF_S_ALU_MUL_K,
    BPF_S_ALU_MUL_X,
    BPF_S_ALU_DIV_X,
    BPF_S_ALU_MOD_K,
    BPF_S_ALU_MOD_X,
    BPF_S_ALU_AND_K,
    BPF_S_ALU_AND_X,
    BPF_S_ALU_OR_K,
    BPF_S_ALU_OR_X,
    BPF_S_ALU_XOR_K,
    BPF_S_ALU_XOR_X,
    BPF_S_ALU_LSH_K,
    BPF_S_ALU_LSH_X,
    BPF_S_ALU_RSH_K,
    BPF_S_ALU_RSH_X,
    BPF_S_ALU_NEG,
    BPF_S_LD_W_ABS,
    BPF_S_LD_H_ABS,
    BPF_S_LD_B_ABS,
    BPF_S_LD_W_LEN,
    BPF_S_LD_W_IND,
    BPF_S_LD_H_IND,
    BPF_S_LD_B_IND,
    BPF_S_LD_IMM,
    BPF_S_LDX_W_LEN,
    BPF_S_LDX_B_MSH,
    BPF_S_LDX_IMM,
    BPF_S_MISC_TAX,
    BPF_S_MISC_TXA,
    BPF_S_ALU_DIV_K,
    BPF_S_LD_MEM,
    BPF_S_LDX_MEM,
    BPF_S_ST,
    BPF_S_STX,
    BPF_S_JMP_JA,
    BPF_S_JMP_JEQ_K,
    BPF_S_JMP_JEQ_X,
    BPF_S_JMP_JGE_K,
    BPF_S_JMP_JGE_X,
    BPF_S_JMP_JGT_K,
    BPF_S_JMP_JGT_X,
    BPF_S_JMP_JSET_K,
    BPF_S_JMP_JSET_X,
    /* Ancillary data */
    BPF_S_ANC_PROTOCOL,
    BPF_S_ANC_PKTTYPE,
    BPF_S_ANC_IFINDEX,
    BPF_S_ANC_NLATTR,
    BPF_S_ANC_NLATTR_NEST,
    BPF_S_ANC_MARK,
    BPF_S_ANC_QUEUE,
    BPF_S_ANC_HATYPE,
    BPF_S_ANC_RXHASH,
    BPF_S_ANC_CPU,
    BPF_S_ANC_ALU_XOR_X,
    BPF_S_ANC_SECCOMP_LD_W,
};

struct sock_filter {
    uint16_t	code;
    uint8_t	jt;
    uint8_t	jf;
    uint32_t	k;
};

struct sock_fprog {             /* Required for SO_ATTACH_FILTER. */
    unsigned short len;         /* Number of filter blocks */
    struct sock_filter  *filter;
};

typedef struct seccomp_data {
    uint32_t	nr;
    uint32_t	arch;
    uint64_t	instruction_pointer;
    uint64_t    args[6];
} seccomp_data_t; 


extern uint32_t reciprocal_value(uint32_t B);

static inline uint32_t reciprocal_divide(uint32_t A, uint32_t R)
{
    return (uint32_t)(((uint64_t)A * R) >> 32);
}

static inline uint32_t *loadpointer(seccomp_data_t *seccomp_ptr, uint64_t offset)
{
    uint32_t *result;

    if (offset > sizeof(seccomp_data_t)) {
        printf("ERROR: offset greater than size of seccomp;\n");
        exit(1);
    }

    result = ((uint32_t *)((ptrdiff_t)seccomp_ptr + offset));
    fprintf(stdout, "offset:%lu\n", offset);
    fprintf(stdout, "result:%d\n", *result);
    return result;
     
}

unsigned int sk_run_filter(seccomp_data_t *seccomp, const struct sock_filter *fentry)
{
    uint32_t *ptr; //changed from void to uint32_t
    uint32_t A = 0;
    uint32_t X = 0;
    uint32_t mem[BPF_MEMWORDS];
//    uint32_t tmp;
    uint64_t k;


    for(;; fentry++) {
#if defined(CONFIG_X86_32)
#define K (fentry->k)
#else
        const uint32_t K = fentry->k;
#endif

    switch (fentry->code) {
        case BPF_S_ALU_ADD_X:
                A += X;
                fprintf(stdout, "ADD X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_ADD_K:
                A += K;
                fprintf(stdout, "ADD K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);                
                continue;

        case BPF_S_ALU_SUB_X:
                A -= X;
                fprintf(stdout, "SUB X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;
        
        case BPF_S_ALU_SUB_K:
                A -= K;
                fprintf(stdout, "SUB K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_NEG:
                A = -A;
                fprintf(stdout, "NEG A\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LD_MEM:
                fprintf(stdout, "A = %d\n", A);
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                A = mem[K];
                fprintf(stdout, "LD MEM\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LDX_MEM:
                fprintf(stdout, "X = %d\n", X);
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                X = mem[K];
                fprintf(stdout, "LDX MEM\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ST:
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                fprintf(stdout, "A = %d\n", A);
                mem[K] = A;
                fprintf(stdout, "STA\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_STX:
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                fprintf(stdout, "X = %d\n", X);
                mem[K] = X;
                fprintf(stdout, "STX\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "mem[K] = %u\n", mem[K]);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_MUL_X:
                A *= X;
                fprintf(stdout, "MUL X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_MUL_K:
                A *= K;
                fprintf(stdout, "MUL K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_DIV_X:
                if (X == 0)
                return 0;
                fprintf(stdout, "A = %d\n", A);
                fprintf(stdout, "X = %d\n", X);
                A /= X;
                fprintf(stdout, "DIV X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_DIV_K:
                fprintf(stdout, "A = %d\n", A);
                fprintf(stdout, "K = %d\n", K);
                A = reciprocal_divide(A, K);
                fprintf(stdout, "DIV K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;
        
        case BPF_S_ALU_AND_X:
                A &= X;
                fprintf(stdout, "AND X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_AND_K:
                A &= K;
                fprintf(stdout, "AND K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_OR_X:
                A |= X;
                fprintf(stdout, "OR X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_OR_K:
                A |= K;
                fprintf(stdout, "OR K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_LSH_X:
                A <<= X;
                fprintf(stdout, "LSH X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_LSH_K:
                A <<= K;
                fprintf(stdout, "LSH K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_RSH_X:
                A >>= X;
                fprintf(stdout, "RSH X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_ALU_RSH_K:
                A >>= K;
                fprintf(stdout, "RSH K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LD_IMM:
                A = K;
                fprintf(stdout, "LD IMM\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LDX_IMM:
                X = K;
                fprintf(stdout, "LDX IMM\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_MISC_TAX:
                fprintf(stdout, "X = %d\n", X);
                fprintf(stdout, "A = %d\n", A);
                X = A;
                fprintf(stdout, "TAX\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_MISC_TXA:
                fprintf(stdout, "X = %d\n", X);
                fprintf(stdout, "A = %d\n", A);
                A = X;
                fprintf(stdout, "TXA\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LD_W_LEN:
                fprintf(stdout, "A = %d\n", A);
                A = sizeof(*seccomp);
                fprintf(stdout, "LD LEN\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LDX_W_LEN:
                fprintf(stdout, "X = %d\n", X);
                X = sizeof(*seccomp);
                fprintf(stdout, "LDX LEN\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_LD_W_ABS:
                k = K;
                fprintf(stdout, "LD ABS\n");
                fprintf(stdout, "K = %d\n", K);
            ptr = loadpointer(seccomp, k);
            if (ptr != NULL) {
                    A = *ptr;
                    fprintf(stdout, "A = %d\n", A);
                    fprintf(stdout, "sizeof seccomp = %lu\n", 
                                      sizeof(*seccomp));              
                    fprintf(stdout, "fentry:%p\n", fentry);
                    continue;
             }
             return 0;

        case BPF_S_JMP_JA:
                fentry += K;
                fprintf(stdout, "JMP JA\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JGT_K:
                fentry += (A > K) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JGT K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JGE_K:
                fentry += (A >= K) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JGE K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JEQ_K:
                fentry += (A == K) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JEQ K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JSET_K:
                fentry += (A & K) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JSET K\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JGT_X:
                fentry += (A > X) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JGT X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JGE_X:
                fentry += (A >= X) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JGE X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JEQ_X:
                fentry += (A == X) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JEQ X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_JMP_JSET_X:
                fentry += (A & X) ? fentry->jt : fentry->jf;
                fprintf(stdout, "JMP JSET X\n");
                fprintf(stdout, "K = %d\nX = %d\nA = %d\n", K, X, A);
                fprintf(stdout, "fentry:%p\n", fentry);
                continue;

        case BPF_S_RET_K:
                return K;
        case BPF_S_RET_A:
                return A;

        }

    }

}

/* Get/set process seccomp mode */
#define PR_GET_SECCOMP  21
#define PR_SET_SECCOMP  22

/* Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
#define SECCOMP_MODE_DISABLED   0 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT     1 /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER     2 /* uses user-supplied filter. */


int64_t seccomp_attach_user_filter(char *filter) 
{
    //TODO
    //struct sock_fprog fprog;
    int64_t ret = 0;
    return ret;
}


/**
 * prctl_set_seccomp: configures current->seccomp.mode
 * @seccomp_mode: requested mode to use
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * This function may be called repeatedly with a @seccomp_mode of
 * SECCOMP_MODE_FILTER to install additional filters.  Every filter
 * successfully installed will be evaluated (in reverse order) for each system
 * call the task makes.
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
int64_t prctl_set_seccomp(uint64_t seccomp_mode, char *filter)
{
    int64_t ret = 0;

    switch (seccomp_mode) {
             
        case SECCOMP_MODE_STRICT:
             ret = 0;
             break;

        case SECCOMP_MODE_FILTER:
             ret = seccomp_attach_user_filter(filter);
             break;
    }

    return ret;
        
}


int64_t prctl_handler(uint64_t option, uint64_t arg2, uint64_t arg3)
{
    int64_t error;
    error = 0;
   
    switch (option) {
   	  
        case PR_SET_SECCOMP:
             error = prctl_set_seccomp(arg2, (char *)arg3);
             break; 
    }

    return error;

}


void syscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    //TODO
    struct sock_fprog fprog {
        struct sock_filter *fentry[]; 
    };

    struct sock_filter fentry[] = {
        {BPF_S_LD_W_ABS, 0, 0, 0},
        {BPF_S_LD_W_ABS, 0, 0, 4},
        {BPF_S_LD_W_ABS, 0, 0, 8},
        {BPF_S_LD_W_ABS, 0, 0, 16},
        {BPF_S_LD_W_ABS, 0, 0, 24},
        {BPF_S_LD_W_ABS, 0, 0, 32},
        {BPF_S_LD_W_ABS, 0, 0, 40},
        {BPF_S_LD_W_ABS, 0, 0, 48},
        {BPF_S_LD_W_ABS, 0, 0, 56},
        //{BPF_S_LD_W_ABS, 0, 0, 7},
        //{BPF_S_LD_W_ABS, 0, 0, 100},
        //{BPF_S_LDX_W_LEN, 0, 0, 40},
        //{BPF_S_ALU_ADD_X, 0, 0, 0},
        //{BPF_S_ALU_ADD_K, 0, 0, 2},
        //{BPF_S_ALU_SUB_X, 0, 0, 0},
        //{BPF_S_ALU_SUB_K, 0, 0, 0},
        {BPF_S_RET_K, 0, 0, 0},
        {BPF_S_RET_A, 0, 0, 0}

    };

    seccomp_data_t seccomp;

    seccomp.nr = 157;//(uint64_t)PIN_GetSyscallNumber(ctxt, std);
    seccomp.args[0] = 22;//(uint64_t)PIN_GetSyscallArgument(ctxt, std, 0);
    seccomp.args[1] = 2;//(uint64_t)PIN_GetSyscallArgument(ctxt, std, 1);
    seccomp.args[2] = fprog.fentry;//(uint64_t)PIN_GetSyscallArgument(ctxt, std, 2);
    seccomp.args[3] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 3);
    seccomp.args[4] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 4);
    seccomp.args[5] = (uint64_t)PIN_GetSyscallArgument(ctxt, std, 5);


    //TODO prctl syscallnum = 157
    if (seccomp.nr == 157) {
        fprintf(stdout, "seccomp.nr = %d\n", seccomp.nr);
        prctl_handler(seccomp.args[0], seccomp.args[1], seccomp.args[2]);
    }

    printf("%lu\n", sizeof(seccomp));
    sk_run_filter(&seccomp, fentry);
}

void syscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
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
