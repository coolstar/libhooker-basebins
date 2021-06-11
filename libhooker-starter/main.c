#include <stdio.h>
#include <spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>

extern char **environ;

int main(){
	mach_port_t taskPort;
	if (task_for_pid(mach_task_self_, 0, &taskPort) != KERN_SUCCESS){
		printf("No tfp0 / checkm8. Exiting\n");
		return 0;
	}
	mach_port_deallocate(mach_task_self_, taskPort);

	printf("Starting libhooker\n");
	int status = 0;
	pid_t pid;
	char *argv[] = {"inject_criticald", "1", "/usr/libexec/libhooker/pspawn_payload.dylib", NULL};
	posix_spawn(&pid, "/usr/libexec/libhooker/inject_criticald", NULL, NULL, argv, environ);
	waitpid(pid, &status, 0);
	return status;
}
