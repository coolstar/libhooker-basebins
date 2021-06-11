//
//  dylib-inject.c
//  libhooker-inject-test
//
//  Created by CoolStar on 6/2/20.
//  Copyright © 2020 coolstar. All rights reserved.
//

#include "dylib-inject.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <pthread/pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <ptrauth.h>
#include <assert.h>
#include <mach-o/dyld_images.h>

extern int __shared_region_check_np(uint64_t *startAddress);

#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // the bits we need at least

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exception_raise_reply;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[614];
} exception_raise_state_reply;
#pragma pack()

#ifdef INJECT_CRITICALD_DEBUG
#define CHK_KR(kr, msg) \
if (kr != KERN_SUCCESS){ \
printf(msg " failed: %d %s\n", kr, mach_error_string(kr)); \
assert(kr == KERN_SUCCESS);\
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

kern_return_t replyException(exception_raise_request *req)
{
    exception_raise_reply reply = {};
    bzero(&reply, sizeof(exception_raise_reply));
    reply.Head.msgh_bits = req->Head.msgh_bits & MACH_MSGH_BITS_REMOTE_MASK;
    reply.Head.msgh_size = sizeof(exception_raise_reply);
    reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
    reply.Head.msgh_local_port = MACH_PORT_NULL;
    reply.Head.msgh_id = req->Head.msgh_id + 0x64;
    reply.NDR = req->NDR;
    reply.RetCode = KERN_SUCCESS;
    return mach_msg(&reply.Head, MACH_SEND_MSG | MACH_MSG_OPTION_NONE , reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

unsigned long remoteStrlen(mach_port_t target,
                           mach_vm_address_t string)
{
    if (!string){
        return 0;
    }
    
    unsigned long len = 0;
    char ch = 0;
    while (true){
        mach_vm_size_t outSz;
        mach_vm_read_overwrite(target, string + len, sizeof(char), (mach_vm_address_t)&ch, &outSz);
        if (!ch)
            break;
        len++;
    }
    return len;
}

kern_return_t LHRunFunc(mach_port_t remoteThread,
                      arm_thread_state64_t state,
                      void *head,
                      mach_port_t exceptionHandler)
{
    exception_raise_request *req = (exception_raise_request *)head;
    
    kern_return_t kr = KERN_SUCCESS;
    __darwin_arm_thread_state64_set_lr_fptr(state, ptrauth_sign_unauthenticated((void *)0x1717171, ptrauth_key_asia, 0)); //actual magic end
    
    kr = thread_set_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
    CHK_KR(kr, "thread_set_state");
    
    kr = thread_resume(remoteThread);
    CHK_KR(kr, "thread_resume");
    
    kr = mach_msg(head, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0x4000, exceptionHandler, 0, MACH_PORT_NULL);
    CHK_KR(kr, "mach_msg pthread_mutex_lock");
    
    kr = thread_suspend(remoteThread);
    CHK_KR(kr, "thread_suspend");
    
    kr = replyException(req);
    CHK_KR(kr, "replyException pthread_mutex_lock");
    return kr;
}

void LHSetPtrReg(uint64_t *reg, uint64_t val, arm_thread_state64_t state){
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
    if (state.__opaque_flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH){
        *reg = (uint64_t)ptrauth_strip((void *)val, ptrauth_key_asia);
    } else {
        *reg = val;
    }
#else
    *reg = val;
#endif
}

void *LHReslideFunc(void *addr, int64_t slideDiff){
    uintptr_t addrRaw = (uintptr_t)ptrauth_strip(addr, ptrauth_key_asia);
    addrRaw -= slideDiff;
    return ptrauth_sign_unauthenticated((void *)addrRaw, ptrauth_key_asia, 0);
}

kern_return_t LHGetRemoteMachThread(mach_port_t target,
                              kern_return_t (^threadCall)(mach_port_t remoteThread,
                                                 mach_port_t exceptionHandler,
                                                 int64_t slideDiff))
{
    kern_return_t kr = KERN_SUCCESS;

    int64_t slideDiff = 0;
    uint64_t ourSlide = 0;

    kr = __shared_region_check_np(&ourSlide);
    CHK_KR(kr, "__shared_region_check_np");
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    kr = task_info(target, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    CHK_KR(kr, "task_info");
    
    struct dyld_all_image_infos *infos = malloc(dyld_info.all_image_info_size);
    mach_vm_size_t outSz;
    kr = mach_vm_read_overwrite(target, dyld_info.all_image_info_addr, dyld_info.all_image_info_size, (mach_vm_address_t)infos, &outSz);
    CHK_KR(kr, "mach_vm_read dyld_all_image_infos");

    uint64_t dyldBase = infos->sharedCacheBaseAddress - infos->sharedCacheSlide;
    ourSlide -= dyldBase;
    slideDiff = ourSlide - infos->sharedCacheSlide;

    free(infos);

    #define STACK_SIZE (mach_vm_size_t)0x4000
        
    mach_vm_address_t remoteStack;
    kr = mach_vm_allocate(target, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate remoteStack");
    kr = mach_vm_protect(target, remoteStack, STACK_SIZE, 1, VM_PROT_READ | VM_PROT_WRITE);
    CHK_KR(kr, "mach_vm_protect remoteStack");
    
    mach_vm_address_t remotePThreads;
    kr = mach_vm_allocate(target, &remotePThreads, 0x100 + sizeof(pthread_t) * 4, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate remotePThreads");
    
    mach_vm_address_t remotePThreadsPtr = remotePThreads + 0x100;
    
    uint64_t *localStack = malloc(STACK_SIZE);
    size_t stackPointer = (STACK_SIZE / 8) - 1;
    stackPointer--;
    
    thread_act_array_t remoteThreads;
    mach_msg_type_number_t remoteThreadCount;
    kr = task_threads(target, &remoteThreads, &remoteThreadCount);
    CHK_KR(kr, "task_threads");
    
    mach_port_t remoteThread;
    kr = thread_create(target, &remoteThread);
    CHK_KR(kr, "thread_create remoteThread");
    
    kr = mach_vm_write(target, remoteStack, (vm_offset_t)localStack, (mach_msg_type_number_t)STACK_SIZE);
    CHK_KR(kr, "mach_vm_write remoteStack");
    
    free(localStack);
    
    //set up mach_msg handler for subsequent calls
    mach_msg_header_t *head = malloc(0x4000);
    
    mach_port_t exceptionHandler;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionHandler);
    CHK_KR(kr, "mach_port_allocate exceptionHandler");
    
    kr = mach_port_insert_right(mach_task_self(), exceptionHandler, exceptionHandler, MACH_MSG_TYPE_MAKE_SEND);
    CHK_KR(kr, "mach_port_insert_right exceptionHandler");
    
    kr = thread_set_exception_ports(remoteThread, EXC_MASK_BAD_ACCESS, exceptionHandler, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    CHK_KR(kr, "thread_set_exception_ports exceptionHandler");
    
    arm_thread_state64_t state = {};
    mach_msg_type_number_t stateCnt = ARM_THREAD_STATE64_COUNT;
    thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt);
    
    mach_vm_address_t remoteMutex;
    kr = mach_vm_allocate(target, &remoteMutex, sizeof(pthread_mutex_t), VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate remoteMutex");
    
    pthread_mutex_t localMutex = PTHREAD_MUTEX_INITIALIZER;
    kr = mach_vm_write(target, remoteMutex, (mach_vm_address_t)&localMutex, sizeof(pthread_mutex_t));
    CHK_KR(kr, "mach_vm_write remoteMutex");
    
    //Start Mem Leak
    for (int i = 0; i < 2; i++){
        //lock mutex twice
        state.__x[0] = (uint64_t)remotePThreadsPtr;
        state.__x[1] = 0;
        LHSetPtrReg(&state.__x[2], (uint64_t)LHReslideFunc(dlsym(RTLD_NEXT, "pthread_mutex_lock"), slideDiff), state);
        state.__x[3] = (uint64_t)remoteMutex;
        __darwin_arm_thread_state64_set_pc_fptr(state, LHReslideFunc(dlsym(RTLD_NEXT, "pthread_create_from_mach_thread"), slideDiff));
        __darwin_arm_thread_state64_set_sp(state, (void *)(remoteStack + stackPointer*sizeof(uint64_t)));
        kr = LHRunFunc(remoteThread, state, head, exceptionHandler);
        CHK_KR(kr, "runFunc pthread_mutex_lock");
        
        remotePThreadsPtr += sizeof(pthread_t);
    }
    
    usleep(100);
    
    thread_act_array_t remoteThreads2;
    mach_msg_type_number_t remoteThreadCount2 = 0;
    
    mach_port_t remotePThread = MACH_PORT_NULL;
    while (remotePThread == MACH_PORT_NULL || remoteThreadCount == remoteThreadCount2){
        kr = task_threads(target, &remoteThreads2, &remoteThreadCount2);
        if (kr != KERN_SUCCESS){
            continue;
        }
        
        for (int i = 0; i < remoteThreadCount2; i++){
            if (remoteThreads2[i] == remoteThread){
                continue;
            }
            bool wasThread = false;
            for (int j = 0; j < remoteThreadCount; j++){
                if (remoteThreads[j] == remoteThreads2[i]){
                    wasThread = true;
                }
            }
            
            if (wasThread){
                continue;
            }
            arm_thread_state64_t threadState = {};
            mach_msg_type_number_t threadStateCnt = ARM_THREAD_STATE64_COUNT;
            kr = thread_get_state(remoteThreads2[i], ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCnt);
            if (kr != KERN_SUCCESS){
                continue;
            }
            
            uint64_t fp = __darwin_arm_thread_state64_get_fp(threadState);
            if (fp == 0){
                continue;
            }
            
            remotePThread = remoteThreads2[i];
        }
        
        for (int i = 0; i < remoteThreadCount2; i++){
            if (remoteThreads2[i] != remotePThread){
                mach_port_deallocate(mach_task_self(), remoteThreads2[i]);
            }
        }
        vm_deallocate(mach_task_self(), (vm_address_t)remoteThreads2, sizeof(thread_t) * remoteThreadCount2);
        usleep(100);
    }
    
    //End Mem Leak
    
    for (int i = 0; i < remoteThreadCount; i++){
        mach_port_deallocate(mach_task_self(), remoteThreads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)remoteThreads, sizeof(thread_t) * remoteThreadCount);
    
    //Start Mem Leak
    if (!MACH_PORT_VALID(remotePThread)){
        kr = KERN_FAILURE;
        return kr;
    }
    
    //set up mach_msg handler for subsequent calls
    mach_msg_header_t *head2 = malloc(0x4000);
    exception_raise_request *req2 = (exception_raise_request *)head2;
    
    mach_port_t exceptionHandler2;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionHandler2);
    CHK_KR(kr, "mach_port_allocate exceptionHandler2");
    
    kr = mach_port_insert_right(mach_task_self(), exceptionHandler2, exceptionHandler2, MACH_MSG_TYPE_MAKE_SEND);
    CHK_KR(kr, "mach_port_insert_right exceptionHandler2");
    
    kr = thread_set_exception_ports(remotePThread, EXC_MASK_BAD_ACCESS, exceptionHandler2, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    CHK_KR(kr, "thread_set_exception_ports exceptionHandler2");
    
    arm_thread_state64_t threadState = {};
    mach_msg_type_number_t threadStateCnt = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCnt);
    CHK_KR(kr, "thread_get_state remotePThread threadState");
    
    void *correctLr = __darwin_arm_thread_state64_get_lr_fptr(threadState);
    if (correctLr == NULL){
        correctLr = (void *)__darwin_arm_thread_state64_get_lr(threadState);
        correctLr = ptrauth_sign_unauthenticated(correctLr, ptrauth_key_asia, 0);
    }
    __darwin_arm_thread_state64_set_lr_fptr(threadState, ptrauth_sign_unauthenticated((void *)0x1717171, ptrauth_key_asia, 0)); //set lr
    
    kr = thread_set_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&threadState, ARM_THREAD_STATE64_COUNT);
    CHK_KR(kr, "thread_set_state remotePThread state");
    
    //setup third call (unlock mutex)
    memcpy(&state, &threadState, sizeof(arm_thread_state64_t));
    state.__x[0] = (uint64_t)remotePThreadsPtr;
    state.__x[1] = 0;
    LHSetPtrReg(&state.__x[2], (uint64_t)LHReslideFunc(dlsym(RTLD_NEXT, "pthread_mutex_unlock"), slideDiff), state);
    state.__x[3] = (uint64_t)remoteMutex;
    __darwin_arm_thread_state64_set_pc_fptr(state, LHReslideFunc(dlsym(RTLD_NEXT, "pthread_create_from_mach_thread"), slideDiff));
    __darwin_arm_thread_state64_set_sp(state, (void *)(remoteStack + stackPointer*sizeof(uint64_t)));
    remotePThreadsPtr += sizeof(pthread_t);
    
    kr = LHRunFunc(remoteThread, state, head, exceptionHandler);
    CHK_KR(kr, "runFunc pthread_mutex_unlock");
    
    //setup fourth call (destroy mutex)
    memcpy(&state, &threadState, sizeof(arm_thread_state64_t));
    state.__x[0] = (uint64_t)remotePThreadsPtr;
    state.__x[1] = 0;
    LHSetPtrReg(&state.__x[2], (uint64_t)LHReslideFunc(dlsym(RTLD_NEXT, "pthread_mutex_destroy"), slideDiff), state);
    state.__x[3] = (uint64_t)remoteMutex;
    __darwin_arm_thread_state64_set_pc_fptr(state, LHReslideFunc(dlsym(RTLD_NEXT, "pthread_create_from_mach_thread"), slideDiff));
    __darwin_arm_thread_state64_set_sp(state, (void *)(remoteStack + stackPointer*sizeof(uint64_t)));
    remotePThreadsPtr += sizeof(pthread_t);
    
    kr = LHRunFunc(remoteThread, state, head, exceptionHandler);
    CHK_KR(kr, "runFunc pthread_mutex_destroy");
    //End Mem Leak
    
    // Terminate Initial Mach Thread as we no longer need it
    
    usleep(1000);
    
    kr = thread_terminate(remoteThread);
    CHK_KR(kr, "thread_terminate");
    
    kr = mach_port_destroy(mach_task_self(), remoteThread);
    CHK_KR(kr, "mach_port_destroy remoteThread");
    
    kr = mach_port_destroy(mach_task_self(), exceptionHandler);
    CHK_KR(kr, "mach_port_destroy exceptionHandler");
    
    kr = mach_vm_deallocate(target, remoteStack, STACK_SIZE);
    CHK_KR(kr, "mach_vm_deallocate remoteStack");
    
    free(head);
    
    //Start Mem Leak
    
    // Set up our new pthread
    
    kr = mach_msg(head2, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0x4000, exceptionHandler2, 0, MACH_PORT_NULL); //wait for pthread to fall here
    CHK_KR(kr, "mach_msg pthread ready");
    
    thread_suspend(remotePThread);
    
    kr = thread_get_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCnt);
    CHK_KR(kr, "thread_get_state remotePThread threadState");
    
    kr = replyException(req2);
    CHK_KR(kr, "replyException pthread_mutex_init");
    
    //free it now
    for (int i = 0; i < 4; i++){
        remotePThreadsPtr -= sizeof(pthread_t);
        uint64_t remotePThreadStruct;
        mach_vm_size_t outSz;
        kr = mach_vm_read_overwrite(target, remotePThreadsPtr, sizeof(uint64_t), (mach_vm_address_t)&remotePThreadStruct, &outSz);
        CHK_KR(kr, "mach_vm_read pthread_detach");
        
        memcpy(&state, &threadState, sizeof(arm_thread_state64_t));
        state.__x[0] = remotePThreadStruct;
        state.__x[1] = 0;
        __darwin_arm_thread_state64_set_pc_fptr(state, LHReslideFunc(dlsym(RTLD_NEXT, "pthread_detach"), slideDiff));
        
        kr = LHRunFunc(remotePThread, state, head2, exceptionHandler2);
        CHK_KR(kr, "runFunc pthread_detach");
        
        kr = thread_get_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&state, &threadStateCnt);
        CHK_KR(kr, "thread_get_state remotePThread threadState");
        
        CHK_KR((int)state.__x[0], "pthread_detach");
    }
    
    free(head2);
    
    kr = thread_set_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&threadState, ARM_THREAD_STATE64_COUNT);
    CHK_KR(kr, "thread_set_state");
    
    kr = threadCall(remotePThread, exceptionHandler2, slideDiff);
    CHK_KR(kr, "threadCall");
    
    __darwin_arm_thread_state64_set_lr_fptr(threadState, (void *)correctLr);
    __darwin_arm_thread_state64_set_pc_fptr(threadState, (void *)correctLr);
    
    kr = thread_set_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&threadState, ARM_THREAD_STATE64_COUNT);
    CHK_KR(kr, "thread_set_state");
    
    kr = mach_port_destroy(mach_task_self(), exceptionHandler2);
    CHK_KR(kr, "mach_port_destroy exceptionHandler2");
    
    kr = thread_resume(remotePThread);
    CHK_KR(kr, "thread_resume");
    
    while (true){
        kern_return_t threadValid = thread_get_state(remotePThread, ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCnt);
        if (threadValid != KERN_SUCCESS){
            break;
        }
        usleep(100);
    }
    
    kr = mach_port_destroy(mach_task_self(), remotePThread);
    CHK_KR(kr, "mach_port_destroy remotePThread");
    
    //End Mem Leak
    
    kr = mach_vm_deallocate(target, remotePThreads, 0x100 + sizeof(pthread_t) * 4);
    CHK_KR(kr, "mach_vm_deallocate remotePThreads");
    kr = mach_vm_deallocate(target, remoteMutex, sizeof(pthread_mutex_t));
    CHK_KR(kr, "mach_vm_deallocate remoteMutex");
    return kr;
}

kern_return_t LHdlsymRemote(mach_port_t target,
                          mach_port_t remoteThread,
                          mach_port_t exceptionHandler,
                          int64_t slideDiff,
                          char *dylib,
                          char *symbol,
                          kern_return_t (^resultCall)(uint64_t funcAddr))
{
    kern_return_t kr = KERN_SUCCESS;
    
    //set up mach_msg handler for subsequent calls
    mach_msg_header_t *head = malloc(0x4000);
    
    arm_thread_state64_t state = {};
    mach_msg_type_number_t stateCnt = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt);
    CHK_KR(kr, "thread_get_state");
    
    mach_vm_address_t remoteStr;
    kr = mach_vm_allocate(target, &remoteStr, 0x4000, VM_FLAGS_ANYWHERE);
    CHK_KR(kr, "mach_vm_allocate dylibName");
    kr = mach_vm_write(target, 0x100 + remoteStr, (vm_offset_t)dylib, (mach_msg_type_number_t)strlen(dylib) + 1);
    CHK_KR(kr, "mach_vm_write dylibName");
    
    state.__x[0] = 0x100 + remoteStr;
    state.__x[1] = RTLD_NOW;
    state.__x[2] = 0;
    __darwin_arm_thread_state64_set_pc_fptr(state, LHReslideFunc(dlsym(RTLD_NEXT, "dlopen"), slideDiff));
    
    kr = LHRunFunc(remoteThread, state, head, exceptionHandler);
    CHK_KR(kr, "dlopen");
    
    kr = thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt);
    CHK_KR(kr, "thread_get_state dlopen");
    
    uint64_t dlAddr = state.__x[0];
    if (dlAddr != 0){
        //char *symName = "MSmain0";
        kr = mach_vm_write(target, 0x100 + remoteStr, (vm_offset_t)symbol, (mach_msg_type_number_t)strlen(symbol) + 1);
        CHK_KR(kr, "mach_vm_write symbol");
        
        state.__x[0] = dlAddr;
        state.__x[1] = 0x100 + remoteStr;
        state.__x[2] = 0;
        __darwin_arm_thread_state64_set_pc_fptr(state, LHReslideFunc(dlsym(RTLD_NEXT, "dlsym"), slideDiff));
        
        kr = LHRunFunc(remoteThread, state, head, exceptionHandler);
        CHK_KR(kr, "dlsym");
        
        kr = thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt);
        CHK_KR(kr, "thread_get_state dlsym");
        
        uint64_t dlSym = state.__x[0];
        if (dlSym != 0){
            kr = resultCall(dlSym);
            CHK_KR(kr, "dlsym result");
        }
    }
    
    mach_vm_deallocate(target, remoteStr, 0x4000);
    
    free(head);
    
    return kr;
}

kern_return_t LHInjectDylib(mach_port_t target, char *dylib, int argc, char *argv[]){
    return LHGetRemoteMachThread(target, ^kern_return_t (mach_port_t remoteThread, mach_port_t exceptionHandler, int64_t slideDiff){
        return LHdlsymRemote(target, remoteThread, exceptionHandler, slideDiff, "/usr/lib/libhooker.dylib", "LHWrapFunction", ^kern_return_t(uint64_t wrapFunction) {
            return LHdlsymRemote(target, remoteThread, exceptionHandler, slideDiff, dylib, "MSmain0", ^kern_return_t(uint64_t funcAddr) {
                kern_return_t kr = KERN_SUCCESS;
                mach_vm_address_t remoteArr;
                kr = mach_vm_allocate(target, &remoteArr, 0x100 + (sizeof(mach_vm_address_t) * argc), VM_FLAGS_ANYWHERE);
                CHK_KR(kr, "mach_vm_allocate remoteArr");
                
                //set up mach_msg handler for subsequent calls
                mach_msg_header_t *head = malloc(0x4000);
                
                mach_vm_address_t *localArr = malloc(sizeof(mach_vm_address_t) * argc);
                bzero(localArr, sizeof(void *) * argc);
                
                for (int i = 0; i < argc; i++){
                    char *localStr = argv[i];
                    
                    mach_vm_address_t remoteStr;
                    kr = mach_vm_allocate(target, &remoteStr, 0x100 + strlen(localStr) + 1, VM_FLAGS_ANYWHERE);
                    CHK_KR(kr, "mach_vm_allocate remoteStr");
                    
                    mach_msg_type_number_t bufLen = (mach_msg_type_number_t)(strlen(localStr) + 1);
                    
                    kr = mach_vm_write(target, 0x100 + remoteStr, (mach_vm_offset_t)localStr, bufLen);
                    CHK_KR(kr, "mach_vm_write remoteStr");
                    localArr[i] = 0x100 + remoteStr;
                }
                kr = mach_vm_write(target, 0x100 + remoteArr, (mach_vm_address_t)localArr, sizeof(mach_vm_address_t) * argc);
                CHK_KR(kr, "mach_vm_write remoteArr");
                
                arm_thread_state64_t state = {};
                mach_msg_type_number_t stateCnt = ARM_THREAD_STATE64_COUNT;
                kr = thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt);
                CHK_KR(kr, "thread_get_state dlsym");
                
                state.__x[0] = argc;
                state.__x[1] = 0x100 + remoteArr;
                state.__x[2] = funcAddr;
                state.__x[3] = 0;

                void *rawFunction = ptrauth_strip((void *)wrapFunction, ptrauth_key_asia);
                __darwin_arm_thread_state64_set_pc_fptr(state, ptrauth_sign_unauthenticated(rawFunction, ptrauth_key_asia, 0));
                
                kr = LHRunFunc(remoteThread, state, head, exceptionHandler);
                CHK_KR(kr, "MSMain0");
                
                kr = thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCnt);
                CHK_KR(kr, "thread_get_state MSmain0");
                
                mach_vm_address_t remoteStr = state.__x[0];
                size_t remoteStrLen = remoteStrlen(target, remoteStr);
                
                char *localStr = malloc(remoteStrLen + 1);
                mach_vm_size_t outSz;
                kr = mach_vm_read_overwrite(target, remoteStr, remoteStrLen + 1, (mach_vm_address_t)localStr, &outSz);
                CHK_KR(kr, "mach_vm_read remoteStr");
                printf("%s\n", localStr);
                
                free(localStr);
                
                for (int i = 0; i < argc; i++){
                    char *localStr = argv[i];
                    mach_vm_address_t remoteStr = localArr[i] - 0x100;
                    mach_vm_deallocate(target, remoteStr, 0x100 + strlen(localStr) + 1);
                }
                mach_vm_deallocate(target, remoteArr, 0x100 + (sizeof(mach_vm_address_t) * argc));
                free(localArr);
                
                free(head);
                return kr;
            });
        });
    });
}
