//
//  dylib-inject.c
//  dylib-inject
//
//  Created by CoolStar on 2/5/20.
//  Copyright © 2020 coolstar. All rights reserved.
//

#include "dylib-inject.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread/pthread.h>
#include <stdio.h>
#include <unistd.h>

#ifdef INJECT_CRITICALD_DEBUG
#define CHK_KR(kr, msg) \
if (kr != KERN_SUCCESS){ \
printf(msg " failed: %d\n", kr); \
return kr; \
}
#else
#define CHK_KR(kr, msg) \
if (kr != KERN_SUCCESS)\
return kr;
#endif

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size);

kern_return_t inject_dylib(mach_port_t target, char *dylib){
    kern_return_t kr = KERN_SUCCESS;
    kr = mach_port_insert_right(mach_task_self(), target, target, MACH_MSG_TYPE_COPY_SEND);
#define STACK_SIZE (mach_vm_size_t)0x4000
    
    mach_vm_address_t remoteStack;
    kr = mach_vm_allocate(target, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate");
    kr = mach_vm_protect(target, remoteStack, STACK_SIZE, 1, VM_PROT_READ | VM_PROT_WRITE);
    CHK_KR(kr, "mach_vm_protect");
    
    mach_vm_address_t remoteStr;
    kr = mach_vm_allocate(target, &remoteStr, 0x100 + strlen(dylib) + 1, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate2");
    kr = mach_vm_write(target, 0x100 + remoteStr, (vm_offset_t)dylib, (mach_msg_type_number_t)strlen(dylib) + 1);
    CHK_KR(kr, "mach_vm_write2");
    
    uint64_t *localStack = malloc(STACK_SIZE);
    size_t stackPointer = (STACK_SIZE / 8) - 1;
    stackPointer--;
    
    mach_port_t remoteThread;
    kr = thread_create(target, &remoteThread);
    
    kr = mach_vm_write(target, remoteStack, (vm_offset_t)localStack, (mach_msg_type_number_t)STACK_SIZE);
    CHK_KR(kr, "mach_vm_write3");
    
    arm_thread_state64_t state = {};
    bzero(&state, sizeof(arm_thread_state64_t));
    
    state.__x[0] = (uint64_t)remoteStack;
    state.__x[2] = (uint64_t)dlsym(RTLD_NEXT, "dlopen");
    state.__x[3] = (uint64_t)(remoteStr + 0x100);
    __darwin_arm_thread_state64_set_lr_fptr(state, (void *)0x7171717171717171); //actual magic end
    __darwin_arm_thread_state64_set_pc_fptr(state, dlsym(RTLD_NEXT, "pthread_create_from_mach_thread"));
    __darwin_arm_thread_state64_set_sp(state, (void *)(remoteStack + stackPointer*sizeof(uint64_t)));
    
    kr = thread_set_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
    CHK_KR(kr, "thread_set_state");
    
    mach_port_t exceptionHandler;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionHandler);
    CHK_KR(kr, "mach_port_allocate");
    
    kr = mach_port_insert_right(mach_task_self(), exceptionHandler, exceptionHandler, MACH_MSG_TYPE_MAKE_SEND);
    CHK_KR(kr, "mach_port_insert_right");
    
    kr = thread_set_exception_ports(remoteThread, EXC_MASK_BAD_ACCESS, exceptionHandler, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    CHK_KR(kr, "thread_set_exception_ports");
    
    kr = thread_resume(remoteThread);
    CHK_KR(kr, "thread_resume");
    
    //Wait for exception
    
    mach_msg_header_t *head = malloc(0x4000);
    kr = mach_msg(head, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0x4000, exceptionHandler, 0, MACH_PORT_NULL);
    CHK_KR(kr, "mach_msg");
    free(head);
    
    kr = thread_terminate(remoteThread);
    CHK_KR(kr, "thread_terminate");
    
    usleep(500 * 1000);
    
    kr = mach_vm_deallocate(target, remoteStr, STACK_SIZE);
    CHK_KR(kr, "mach_vm_deallocate");
    kr = mach_vm_deallocate(target, remoteThread, STACK_SIZE);
    CHK_KR(kr, "mach_vm_deallocate2");
    
    kr = mach_port_destroy(mach_task_self(), exceptionHandler);
    CHK_KR(kr, "mach_port_destroy");
    
    kr = mach_port_deallocate(mach_task_self(), target);
    CHK_KR(kr, "mach_port_deallocate");
    
    free(localStack);
    return kr;
}
