#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mach/mach.h>
#include "dylib-inject.h"

int main(int argc, char* argv[]){
	if (argc < 3){
		printf("Usage: inject_criticald <pid> <dylib>\n");
		return 0;
	}
	
	uint32_t pid = atoi(argv[1]);
	char *dylib = argv[2];
	
	task_t remoteTask;
	kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "Failed to get task for pid %u!\n", pid);
		return -1;
	}

	printf("Remote task: 0x%x\n", remoteTask);
	
    kern_return_t ret = inject_dylib(remoteTask, dylib);

	if (ret == 0){
		fprintf(stderr, "No error occurred!\n");
	} else {
        fprintf(stderr, "Something happened!\n");
	}
	return 0;
}
