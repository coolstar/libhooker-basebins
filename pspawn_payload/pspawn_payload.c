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
#include "memDebug.h"

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

#define ENV_PREFIX "DYLD_INSERT_LIBRARIES="
#define ENV_NAME "DYLD_INSERT_LIBRARIES"

static const char *stringByAppendingString(const char *prefix, const char *suffix){
    unsigned long totalLen = strlen(prefix) + strlen(suffix) + 1;
    
    char *newStr = userland_alloc(totalLen * sizeof(char));
    bzero(newStr, totalLen);
    strncpy(newStr, prefix, strlen(prefix));
    strncpy(newStr + strlen(prefix), suffix, strlen(suffix));
    return newStr;
}

static bool stringStartsWith(const char *string, const char *startsWith){
    if (strlen(startsWith) > strlen(string)){
        return false;
    }
    return strncmp(startsWith, string, strlen(startsWith)) == 0;
}

static const char *dylibsToInject(const char *originalEnvVar, const char *dylibToInject){
    if (!originalEnvVar){
        return stringByAppendingString(ENV_PREFIX, dylibToInject);
    }
    
    char *envVar = (char *)userland_strdup(originalEnvVar);
    if (strlen(envVar) <= strlen(ENV_PREFIX)) {
        userland_free((void *)envVar);
        return stringByAppendingString(ENV_PREFIX, dylibToInject);
    }
    
    char *envContents = envVar + strlen(ENV_PREFIX);
    
    int estCount = 1;
    for (int i = 0; i < strlen(envContents); i++){
        if (envContents[i] == ':') {
            estCount++;
        }
    }
    
    const char **entries = userland_alloc(estCount * sizeof(char *));
    bzero(entries, estCount * sizeof(const char *));
    
    int totalLength = 0;
    
    int count = 0;
    char *pch;
    pch = strtok((char *)envContents, ":");
    while (pch != NULL){
        if (strcmp(pch, dylibToInject) != 0){
            entries[count] = userland_strdup(pch);
            totalLength += strlen(pch);
            count++;
        }
        pch = strtok(NULL, ":");
    }
    
    userland_free((void *)envVar);
    
    char *newStr = userland_alloc(strlen(dylibToInject) + totalLength + count + 1);
    bzero(newStr, strlen(dylibToInject) + totalLength + count + 1);
    
    size_t filledSize = strlen(dylibToInject);
    strncpy(newStr, dylibToInject, filledSize);
    
    for (int i = 0; i < count; i++){
        strncpy(newStr + filledSize, ":", 1);
        filledSize++;
        
        strncpy(newStr + filledSize, entries[i], strlen(entries[i]));
        filledSize += strlen(entries[i]);
        userland_free((void *)entries[i]);
    }
    userland_free(entries);
    
    const char *newEnvVar = stringByAppendingString(ENV_PREFIX, newStr);
    userland_free(newStr);
    
    return newEnvVar;
}

static const char **copyEnvArrList(const char **env){
    int envCount = 0;
    if (env){
        for (int i = 0; env[i]; i++){
            envCount++;
        }
    }
    
    const char **newEnv = userland_alloc(sizeof(const char *) * (envCount + 1));
    bzero(newEnv, sizeof(const char *) * (envCount + 1));
    for (int i = 0; i < envCount; i++){
        newEnv[i] = userland_strdup(env[i]);
    }
    return newEnv;
}

static const char **popEnv(const char **env, const char *envName, const char **poppedEnvPtr){
    const char *poppedEnv = NULL;
    int newEnvCount = 0;
    
    const char *envPrefix = stringByAppendingString(envName, "=");
    for (int i = 0; env[i]; i++){
        if (stringStartsWith(env[i], envPrefix)){
            poppedEnv = env[i];
        } else {
            newEnvCount++;
        }
    }
    
    if (poppedEnvPtr){
        *poppedEnvPtr = poppedEnv;
    }
    
    const char **newEnv = userland_alloc(sizeof(const char *) * (newEnvCount + 1));
    bzero(newEnv, sizeof(const char *) * (newEnvCount + 1));
    int j = 0;
    for (int i = 0; env[i]; i++){
        if (!stringStartsWith(env[i], envPrefix)){
            newEnv[j] = env[i];
            j++;
        }
    }
    userland_free((void *)envPrefix);
    userland_free(env);
    
    return newEnv;
}

static const char **pushEnv(const char **env, const char *envVar){
    if (!envVar){
        return env;
    }
    
    int newEnvCount = 1;
    for (int i = 0; env[i]; i++){
        newEnvCount++;
    }
    
    const char **newEnv = userland_alloc(sizeof(const char *) * (newEnvCount + 1));
    bzero(newEnv, sizeof(const char *) * (newEnvCount + 1));
    for (int i = 0; env[i]; i++){
        newEnv[i] = env[i];
    }
    newEnv[newEnvCount - 1] = envVar;
    userland_free(env);
    return newEnv;
}

static void freeEnvArrList(const char **env){
    for (int i = 0; env[i]; i++){
        userland_free((void *)env[i]);
    }
    userland_free((void *)env);
}


typedef int (*pspawn_t)(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], const char* envp[]);

pspawn_t old_pspawn, old_pspawnp;
pspawn_t old_pspawn_broken, old_pspawnp_broken;

static int fake_posix_spawn_common(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], const char* envp[], pspawn_t old) {
    DEBUGLOG("We got called (fake_posix_spawn)! %s", path);

    const char *dylibToInject = NULL;
    
    if (current_process == PROCESS_LAUNCHD && strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        dylibToInject = PSPAWN_PAYLOAD_DYLIB;
        
        const char* startd = argv[1];
        if (startd != NULL) {
            DEBUGLOG("Starting xpcproxy service %s", startd);
            const char **blacklist = xpcproxy_blacklist;
        
            while (*blacklist) {
                if (strncmp(startd, *blacklist, strlen(*blacklist)) == 0) {
                    DEBUGLOG("xpcproxy for '%s' which is in blacklist, not injecting", startd);
                    dylibToInject = NULL;
                    break;
                }
                
                ++blacklist;
            }
        }
    } else if (current_process == PROCESS_LAUNCHD && strcmp(path, "/sbin/launchd") == 0){
        dylibToInject = PSPAWN_PAYLOAD_DYLIB;
    } else {
        dylibToInject = SBINJECT_PAYLOAD_DYLIB;
    }
    
    // XXX log different err on dylibToInject == NULL and nonexistent dylibToInject
    if (dylibToInject == NULL || !file_exist(dylibToInject)) {
        DEBUGLOG("Nothing to inject");
        return old(pid, path, file_actions, attrp, argv, envp);
    }
    
    DEBUGLOG("Injecting %s into %s", dylibToInject, path);
    
    
    const char **newEnvp = copyEnvArrList(envp);
    const char *rawDyldInsertLibraries = NULL;
    newEnvp = popEnv(newEnvp, ENV_NAME, &rawDyldInsertLibraries);
    
    const char *newDyldInsertLibraries = dylibsToInject(rawDyldInsertLibraries, dylibToInject);
    if (rawDyldInsertLibraries){
        userland_free((void *)rawDyldInsertLibraries);
    }
    rawDyldInsertLibraries = newDyldInsertLibraries;
    newEnvp = pushEnv(newEnvp, rawDyldInsertLibraries);
    
    if (current_process == PROCESS_XPCPROXY) {
        // dont leak logging fd into execd process
#ifdef PSPAWN_PAYLOAD_DEBUG
        if (log_file != NULL) {
            fclose(log_file);
            log_file = NULL;
        }
#endif
    }
    int origret = old(pid, path, file_actions, attrp, argv, newEnvp);
    freeEnvArrList(newEnvp);
    
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
