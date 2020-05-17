#include <stdlib.h>
#if PSPAWN_PAYLOAD_DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <sys/stat.h>
#include <spawn.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include "fishhook.h"

int file_exist(const char *filename) {
    struct stat buffer;
    int r = stat(filename, &buffer);
    return (r == 0);
}

#ifdef PSPAWN_PAYLOAD_DEBUG
#define LAUNCHD_LOG_PATH "/pspawn_payload_launchd.log"
// XXX multiple xpcproxies opening same file
// XXX not closing logfile before spawn
#define XPCPROXY_LOG_PATH "/pspawn_payload_xpcproxy.log"
FILE *log_file;
#define DEBUGLOG(fmt, args...)\
do {\
if (log_file == NULL) {\
char *logpath = (current_process == PROCESS_LAUNCHD) ? LAUNCHD_LOG_PATH : XPCPROXY_LOG_PATH;\
log_file = fopen(logpath, "a"); \
if (log_file == NULL) break; \
} \
time_t mytime = time(NULL);\
char * time_str = ctime(&mytime);\
time_str[strlen(time_str)-1] = '\0';\
fprintf(log_file, "%s ", time_str); \
fprintf(log_file, fmt "\n", ##args); \
fflush(log_file); \
} while(0)
#else
#define DEBUGLOG(fmt, args...)
#endif

#define PSPAWN_PAYLOAD_DYLIB "/usr/libexec/libhooker/pspawn_payload.dylib"
#define SBINJECT_PAYLOAD_DYLIB "/usr/lib/TweakInject.dylib"

// since this dylib should only be loaded into launchd and xpcproxy
// it's safe to assume that we're in xpcproxy if getpid() != 1
enum currentprocess {
    PROCESS_LAUNCHD,
    PROCESS_XPCPROXY
};

int current_process = PROCESS_XPCPROXY;

const char* xpcproxy_blacklist[] = {
    "com.apple.diagnosticd",  // syslog
    "com.apple.logd",         // syslog
    "com.apple.MTLCompilerService",     // ?_?
    "com.apple.Maps.mapspushd",              // stupid Apple Maps
    "com.apple.nsurlsessiond",          // stupid Reddit app
    "com.apple.applecamerad",
    "com.apple.videosubscriptionsd",    // u_u
    "com.apple.notifyd",
    "OTAPKIAssetTool",        // h_h
    "com.apple.cfprefsd.xpc.daemon",               // o_o
    "com.apple.FileProvider.LocalStorage",  // seems to crash from oosb r/w etc
    "jailbreakd",             // don't inject into jbd since we'd have to call to it
    "amfid",        // don't inject into amfid on corellium
    NULL
};

typedef int (*pspawn_t)(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], const char* envp[]);

pspawn_t old_pspawn, old_pspawnp;
pspawn_t old_pspawn_broken, old_pspawnp_broken;

static int fake_posix_spawn_common(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], const char* envp[], pspawn_t old) {
    DEBUGLOG("We got called (fake_posix_spawn)! %s", path);

    const char *inject_me = NULL;
    
    if (current_process == PROCESS_LAUNCHD && strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        inject_me = PSPAWN_PAYLOAD_DYLIB;
        
        const char* startd = argv[1];
        if (startd != NULL) {
            DEBUGLOG("Starting xpcproxy service %s", startd);
            const char **blacklist = xpcproxy_blacklist;
        
            while (*blacklist) {
                if (strncmp(startd, *blacklist, strlen(*blacklist)) == 0) {
                    DEBUGLOG("xpcproxy for '%s' which is in blacklist, not injecting", startd);
                    inject_me = NULL;
                    break;
                }
                
                ++blacklist;
            }
        }
    } else {
        inject_me = SBINJECT_PAYLOAD_DYLIB;
    }
    
    // XXX log different err on inject_me == NULL and nonexistent inject_me
    if (inject_me == NULL || !file_exist(inject_me)) {
        DEBUGLOG("Nothing to inject");
        return old(pid, path, file_actions, attrp, argv, envp);
    }
    
    DEBUGLOG("Injecting %s into %s", inject_me, path);
    
#ifdef PSPAWN_PAYLOAD_DEBUG
    if (argv != NULL){
        DEBUGLOG("Args: ");
        const char** currentarg = argv;
        while (*currentarg != NULL){
            DEBUGLOG("\t%s", *currentarg);
            currentarg++;
        }
    }
#endif
    
    int envcount = 0;
    int allenvs = 0;
    
    if (envp != NULL){
        DEBUGLOG("Env: ");
        const char** currentenv = envp;
        while (*currentenv != NULL){
            DEBUGLOG("\t%s", *currentenv);
            if (strstr(*currentenv, "DYLD_INSERT_LIBRARIES") == NULL) {
                envcount++;
            }
            allenvs++;
            currentenv++;
        }
    }
    
    char const** newenvp = malloc((envcount+2) * sizeof(char **));
    int j = 0;
    for (int i = 0; i < allenvs; i++){
        if (strstr(envp[i], "DYLD_INSERT_LIBRARIES") != NULL){
            continue;
        }
        newenvp[j] = envp[i];
        j++;
    }
    
    char *envp_inject = malloc(strlen("DYLD_INSERT_LIBRARIES=") + strlen(inject_me) + 1);
    
    envp_inject[0] = '\0';
    strcat(envp_inject, "DYLD_INSERT_LIBRARIES=");
    strcat(envp_inject, inject_me);
    
    newenvp[j] = envp_inject;
    newenvp[j+1] = NULL;
    
#if PSPAWN_PAYLOAD_DEBUG
    DEBUGLOG("New Env:");
    const char** currentenv = newenvp;
    while (*currentenv != NULL){
        DEBUGLOG("\t%s", *currentenv);
        currentenv++;
    }
#endif
    
    int origret;
    
#define FLAG_ATTRIBUTE_XPCPROXY (1 << 17)
    
    if (current_process == PROCESS_XPCPROXY) {
        // dont leak logging fd into execd process
#ifdef PSPAWN_PAYLOAD_DEBUG
        if (log_file != NULL) {
            fclose(log_file);
            log_file = NULL;
        }
#endif
    }
    origret = old(pid, path, file_actions, attrp, argv, newenvp);
    
    return origret;
}

static int fake_posix_spawn(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], const char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawn);
}

static int fake_posix_spawnp(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], const char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawnp);
}

struct mach_exception { int length; const char *prefix; };
#define DECL_EXCEPTION(s) { sizeof(s) - 1, s }
static struct mach_exception mach_lookup_exception_list[] = {
    // rbs
    DECL_EXCEPTION("com.apple.ReportCrash.SimulateCrash"),
    // lh
    DECL_EXCEPTION("lh:"),
    { 0, NULL },
};
#undef DECL_EXCEPTION

int sandbox_check_by_audit_token(audit_token_t, const char *operation, int sandbox_filter_type, ...);
static int (*old_sandbox_check_by_audit_token)(audit_token_t, const char *operation, int sandbox_filter_type, ...);
static int (*old_sandbox_check_by_audit_token_broken)(audit_token_t, const char *operation, int sandbox_filter_type, ...);
static int fake_sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...) {
    int retval;
    if (!strncmp(operation, "mach-", 5)) {
        va_list a;
        va_start(a, sandbox_filter_type);
        const char *name = va_arg(a, const char *);
        va_end(a);

        if (!name) {
            // sure, why not
            return 0;
        }

        if (strcmp(operation + 5, "lookup") != 0)
            goto passthru;

        for (struct mach_exception *ent = mach_lookup_exception_list; ent->length != 0; ++ent) {
            if (!strncmp((char *)name, ent->prefix, ent->length)) {
                DEBUGLOG("MACH: Passing for %s", name);
                return 0;
            }
        }

      passthru:
        retval = old_sandbox_check_by_audit_token(au, operation, sandbox_filter_type, name);
    } else {
        retval = old_sandbox_check_by_audit_token(au, operation, sandbox_filter_type, NULL);
    }
    return retval;
}

static void rebind_pspawns(void) {
    void *libsystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    old_pspawn = dlsym(libsystem, "posix_spawn");
    old_pspawnp = dlsym(libsystem, "posix_spawnp");
    old_sandbox_check_by_audit_token = dlsym(libsystem, "sandbox_check_by_audit_token");
    struct rebinding rebindings[] = {
        {"posix_spawn", (void *)fake_posix_spawn, (void **)&old_pspawn_broken},
        {"posix_spawnp", (void *)fake_posix_spawnp, (void **)&old_pspawnp_broken},
        {"sandbox_check_by_audit_token", (void *)fake_sandbox_check_by_audit_token, (void **)&old_sandbox_check_by_audit_token_broken}
    };
    
    rebind_symbols(rebindings, 3);
}

static void* thd_func(void* arg){
    rebind_pspawns();
    return NULL;
}

__attribute__ ((constructor))
static void ctor(void) {
    if (getpid() == 1) {
        current_process = PROCESS_LAUNCHD;

        pthread_t thd;
        pthread_create(&thd, NULL, thd_func, NULL);
    } else {
        current_process = PROCESS_XPCPROXY;
    
        rebind_pspawns();
    }
}
