#include <xpc/xpc.h>

//launchd functions (Thanks J)
extern int xpc_pipe_routine (xpc_object_t xpc_pipe, xpc_object_t inDict, xpc_object_t *reply);
extern char *xpc_strerror (int);

// Some of the routine #s launchd recognizes. There are quite a few subsystems

#define HANDLE_SYSTEM 0

#define ROUTINE_SUBMIT 100
#define ROUTINE_LOAD		0x320	// 800
#define ROUTINE_ENABLE 0x328
#define ROUTINE_DISABLE 0x329

#define ROUTINE_START        0x32d    // 813
#define ROUTINE_STOP        0x32e    // 814
#define ROUTINE_LIST        0x32f    // 815

// os_alloc_once_table:
//
// Ripped this from XNU's libsystem
#define OS_ALLOC_ONCE_KEY_MAX    100

struct _os_alloc_once_s {
    long once;
    void *ptr;
};

extern struct _os_alloc_once_s _os_alloc_once_table[];

// XPC sets up global variables using os_alloc_once. By reverse engineering
// you can determine the values. The only one we actually need is the fourth
// one, which is used as an argument to xpc_pipe_routine

struct xpc_global_data {
    uint64_t    a;
    uint64_t    xpc_flags;
    mach_port_t    task_bootstrap_port;  /* 0x10 */
#ifndef _64
    uint32_t    padding;
#endif
    xpc_object_t    xpc_bootstrap_pipe;   /* 0x18 */
    // and there's more, but you'll have to wait for MOXiI 2 for those...
    // ...
};