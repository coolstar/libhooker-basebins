#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mach/mach.h>
#include "dylib-inject.h"

int main(int argc, char* argv[]){
	if (argc < 3){
		printf("Usage: libsyringe <pid> <dylib> [args...]\n");
		return 0;
	}
	
	uint32_t pid = atoi(argv[1]);
	char *dylib = argv[2];
	
	task_t remoteTask;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
	if (kr != KERN_SUCCESS) {
		printf("[libhooker] Failed to get task for pid %u!\n", pid);
		return -1;
	}
    
    int dylibArgc = argc - 2;
    char **dylibArgv = argv += 2;
	
    kern_return_t ret = LHInjectDylib(remoteTask, dylib, dylibArgc, dylibArgv);

	if (ret != 0){
        printf("[libhooker] Something happened!\n");
        return ret;
	}
	return 0;
}
