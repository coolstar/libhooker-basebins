#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#include <os/log.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#include <unistd.h>
#include <sandbox.h>
#include <mach-o/dyld.h>
#import <dlfcn.h>

#define PROC_PIDPATHINFO_MAXSIZE  (1024)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#define dylibDir @"/Library/TweakInject"

//libhooker options
static BOOL killBackBoarddWithSpringBoard = NO;

//process status
static BOOL isSpringBoard = NO;
static BOOL isBackboard = NO;
static pid_t backboarddPID = 0;
static NSString *processHash = @"";
static BOOL safeMode = false;

static NSArray *sbinjectGenerateDylibList(NSString *appPath) {
    NSString *processName = [[NSProcessInfo processInfo] processName];
    // Create an array containing all the filenames in dylibDir (/opt/simject)
    NSError *e = nil;
    NSArray *dylibDirContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dylibDir error:&e];
    if (e) {
        return nil;
    }
    // Read current bundle identifier
    //NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    // We're only interested in the plist files
    NSArray *plists = [dylibDirContents filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"SELF ENDSWITH %@", @"plist"]];
    // Create an empty mutable array that will contain a list of dylib paths to be injected into the target process
    NSMutableArray *dylibsToInject = [NSMutableArray array];
    // Loop through the list of plists
    for (NSString *plist in plists) {
        // We'll want to deal with absolute paths, so append the filename to dylibDir
        NSString *plistPath = [dylibDir stringByAppendingPathComponent:plist];
        NSDictionary *filter = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (![filter isKindOfClass:[NSDictionary class]]){
            continue;
        }

        // This boolean indicates whether or not the dylib has already been injected
        BOOL isInjected = NO;
        // If supported iOS versions are specified within the plist, we check those first
        NSArray *supportedVersions = filter[@"CoreFoundationVersion"];
        if ([supportedVersions isKindOfClass:[NSArray class]]) {
            if (supportedVersions.count != 1 && supportedVersions.count != 2) {
                continue; // Supported versions are in the wrong format, we should skip
            }
            if (supportedVersions.count == 1 && [supportedVersions[0] doubleValue] > kCFCoreFoundationVersionNumber) {
                continue; // Doesn't meet lower bound
            }
            if (supportedVersions.count == 2 && ([supportedVersions[0] doubleValue] > kCFCoreFoundationVersionNumber || [supportedVersions[1] doubleValue] <= kCFCoreFoundationVersionNumber)) {
                continue; // Outside bounds
            }
        }
        if ([filter[@"Filter"] isKindOfClass:[NSDictionary class]]){
            // Decide whether or not to load the dylib based on the Bundles values
            NSDictionary *rawFilter = filter[@"Filter"];
            if ([rawFilter[@"Bundles"] isKindOfClass:[NSArray class]]){
                for (NSString *entry in rawFilter[@"Bundles"]) {
                    // Check to see whether or not this bundle is actually loaded in this application or not
                    CFBundleRef loadedBundle = CFBundleGetBundleWithIdentifier((CFStringRef)entry);
                    if (!loadedBundle || !CFBundleIsExecutableLoaded(loadedBundle)) {
                        // If not, skip it
                        continue;
                    }
                    if (kCFCoreFoundationVersionNumber >= 1600){
                        if ([entry hasPrefix:@"com.apple.UIKit"] || [entry hasSuffix:@"UI"]|| [entry hasPrefix:@"com.apple.TextInput"] || [entry hasPrefix:@"com.apple.TextEntry"]){
                            if (![appPath hasPrefix:@"/Applications"] && ![appPath hasPrefix:@"/var/containers/Bundle/Application"] && ![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"]){
                                //Should not be injecting here. Skip it
                                continue;
                            }
                        }
                    }
                    [dylibsToInject addObject:[[plistPath stringByDeletingPathExtension] stringByAppendingString:@".dylib"]];
                    isInjected = YES;
                    break;
                }
            }
            if (!isInjected && [rawFilter[@"Executables"] isKindOfClass:[NSArray class]]) {
                // Decide whether or not to load the dylib based on the Executables values
                for (NSString *process in rawFilter[@"Executables"]) {
                    if ([process isKindOfClass:[NSString class]] && [process isEqualToString:processName]) {
                        [dylibsToInject addObject:[[plistPath stringByDeletingPathExtension] stringByAppendingString:@".dylib"]];
                        isInjected = YES;
                        break;
                    }
                }
            }
            if (!isInjected && [rawFilter[@"Classes"] isKindOfClass:[NSArray class]]) {
                // Decide whether or not to load the dylib based on the Classes values
                for (NSString *clazz in rawFilter[@"Classes"]) {
                    // Also check if this class is loaded in this application or not
                    if (![clazz isKindOfClass:[NSString class]] || !NSClassFromString(clazz)) {
                        // This class couldn't be loaded, skip
                        continue;
                    }
                    // It's fine to add this dylib at this point
                    [dylibsToInject addObject:[[plistPath stringByDeletingPathExtension] stringByAppendingString:@".dylib"]];
                    isInjected = YES;
                    break;
                }
            }
        }
        if (isInjected){
            NSDictionary *libhookerOptions = filter[@"LHOptions"];
            if ([libhookerOptions isKindOfClass:[NSDictionary class]]){
                NSNumber *killBackBoarddWithSpringBoardNum = libhookerOptions[@"KillbackboarddOnSpringBoardCrash"];
                if ([killBackBoarddWithSpringBoardNum boolValue]){
                    killBackBoarddWithSpringBoard = YES;                }
            }
        }
    }
    [dylibsToInject sortUsingSelector:@selector(caseInsensitiveCompare:)];
    return dylibsToInject;
}

int file_exist(char *filename) {
    struct stat buffer;
    int r = stat(filename, &buffer);
    return (r == 0);
}

@interface SpringBoard : UIApplication
- (BOOL)launchApplicationWithIdentifier:(NSString *)identifier suspended:(BOOL)suspended;
@end

static NSString *LHTemporaryDirectory(){
    char buf[MAXPATHLEN];
    bzero(buf, MAXPATHLEN);

    char *env = getenv("TMPDIR");
    if (issetugid()){
        strncpy(buf, P_tmpdir, MAXPATHLEN);
    } else if (env) {
        strncpy(buf, env, MAXPATHLEN);
    } else {
        confstr(_CS_DARWIN_USER_TEMP_DIR, buf, MAXPATHLEN); //This shit can break sandbox
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    return [[fm stringWithFileSystemRepresentation:buf length:strlen(buf)] stringByStandardizingPath];
}

%group SafeMode
%hook FBApplicationInfo
- (NSDictionary *)environmentVariables {
    NSDictionary *originalVariables = %orig;
    NSMutableDictionary *newVariables = [originalVariables mutableCopy];
    [newVariables setObject:@1 forKey:@"_SafeMode"];
    return [newVariables autorelease];
}
%end

%hook FBSApplicationInfo
- (NSDictionary *)environmentVariables {
    NSDictionary *originalVariables = %orig;
    NSMutableDictionary *newVariables = [originalVariables mutableCopy];
    [newVariables setObject:@1 forKey:@"_SafeMode"];
    return [newVariables autorelease];
}
%end

%hook SBLockScreenManager
-(BOOL)_finishUIUnlockFromSource:(int)arg1 withOptions:(id)arg2 {
    BOOL ret = %orig;
    [(SpringBoard *)[%c(UIApplication) sharedApplication] launchApplicationWithIdentifier:@"org.coolstar.SafeMode" suspended:NO];
    return ret;
}

// Necessary on iPhone X to show after swipe unlock gesture
-(void)lockScreenViewControllerDidDismiss {
    %orig;
    [(SpringBoard *)[%c(UIApplication) sharedApplication] launchApplicationWithIdentifier:@"org.coolstar.SafeMode" suspended:NO];
}
%end
%end

static void SigHandler(int signo, siginfo_t *info, void *uap){
    if (isSpringBoard || isBackboard){
        FILE *f = fopen("/var/mobile/Library/.sbinjectSafeMode", "w");
        if (f){
            fprintf(f, "Hello World\n");
            fclose(f);
        }
    }
    if (processHash){
        FILE *f = fopen([[NSString stringWithFormat:@"%@/.safeMode-%@", LHTemporaryDirectory(), processHash] UTF8String], "w");
        if (f){
            fprintf(f, "Hello World!\n");
            fclose(f);
        }
    }

    if (isSpringBoard && killBackBoarddWithSpringBoard){
        mkdir("/var/tmp/com.apple.backboardd/", 0700);
        FILE *f = fopen("/var/tmp/com.apple.backboardd/.bbSafeMode", "w");
        if (f){
            fprintf(f, "Hello World!\n");
            fclose(f);
        }

        kill(backboarddPID, SIGKILL);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);

    sigaction(signo, &action, NULL);

    raise(signo);
}

#import "xpc.h"

static xpc_object_t xpc_bootstrap_pipe(void) {
    struct xpc_global_data *xpc_gd = _os_alloc_once_table[1].ptr;
    return xpc_gd->xpc_bootstrap_pipe;
}

static int queryDaemon(char *daemonLabel){
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, "subsystem", 3); // subsystem (3)
    xpc_dictionary_set_uint64(dict, "handle", HANDLE_SYSTEM);
    xpc_dictionary_set_uint64(dict, "routine", ROUTINE_LIST);
    xpc_dictionary_set_uint64(dict, "type", 1); // set to 1
    xpc_dictionary_set_bool(dict, "legacy", 1); // mandatory

    xpc_object_t    outDict = NULL;

    __block int queriedPid = 0;

    int rc = xpc_pipe_routine (xpc_bootstrap_pipe(), dict, &outDict);
    if (rc == 0) {
        int err = xpc_dictionary_get_int64 (outDict, "error");
        if (!err){
            // We actually got a reply!
            xpc_object_t svcs = xpc_dictionary_get_value(outDict, "services");
            if (!svcs)
            {
                return -1;
            }

            xpc_type_t  svcsType = xpc_get_type(svcs);
            if (svcsType != XPC_TYPE_DICTIONARY)
            {
                return -2;
            }

            xpc_dictionary_apply(svcs, ^bool (const char *label, xpc_object_t svc) 
            {
                int64_t pid = xpc_dictionary_get_int64(svc, "pid");
                if (pid != 0){
                    if (strcmp(label, daemonLabel) == 0){
                        queriedPid = pid;
                    }
                }
                return 1;
            });
        }
    }
    return queriedPid;
}

bool linksSymbol(const void *hdr,
    uintptr_t slide,
    const char *symbolName);

static void LHLog(os_log_type_t type, NSString *format, ...){
    va_list args;
    va_start(args, format);
    NSString *str = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    if (sandbox_check(getpid(), "mach-lookup", SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_GLOBAL_NAME, "com.apple.system.logger") == 0 && 
        sandbox_check(getpid(), "mach-lookup", SANDBOX_CHECK_NO_REPORT | SANDBOX_FILTER_LOCAL_NAME, "com.apple.system.logger") == 0){
        if (!linksSymbol(_dyld_get_image_header(0),
                        _dyld_get_image_vmaddr_slide(0),
                        "_os_log_set_client_type")){
            os_log_with_type(OS_LOG_DEFAULT, type, "%{public}@\n", str);
        }
    } else {
        fprintf(stderr, "%s\n", [str UTF8String]);
    }
    [str release];
}

NSDictionary *preferencesForExecutable(NSDictionary *preferences){
    NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    NSString *pathStr = nil;

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int ret = proc_pidpath(getpid(), pathbuf, sizeof(pathbuf));
    if (ret > 0){
        pathStr = [NSString stringWithUTF8String:pathbuf];
    }

    NSDictionary *tweakConfigs = [preferences objectForKey:@"tweakconfigs"];
    if (!tweakConfigs || ![tweakConfigs isKindOfClass:[NSDictionary class]]){
        return nil;
    }

    if (bundleIdentifier){
        NSDictionary *bundles = [tweakConfigs objectForKey:@"bundles"];
        if ([bundles isKindOfClass:[NSDictionary class]]){
            NSDictionary *config = [bundles objectForKey:bundleIdentifier];
            if (config && [config isKindOfClass:[NSDictionary class]]){
                return config;
            }
        }
    }
    if (pathStr){
        NSDictionary *paths = [tweakConfigs objectForKey:@"paths"];
        if ([paths isKindOfClass:[NSDictionary class]]){
            NSDictionary *config = [paths objectForKey:pathStr];
            if (config && [config isKindOfClass:[NSDictionary class]]){
                return config;
            }
        }
    }
    NSDictionary *config = [tweakConfigs objectForKey:@"default"];
    if (config && [config isKindOfClass:[NSDictionary class]]){
        return config;
    }
    return nil;
}

__attribute__ ((constructor))
static void ctor(void) {
    NSArray *dylibInjectList = nil;
    NSDictionary *preferences = [[NSDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/org.coolstar.libhooker.plist"];

    @autoreleasepool {
        unsetenv("DYLD_INSERT_LIBRARIES");

        NSDictionary *executablePreferences = preferencesForExecutable(preferences);
        if (NSBundle.mainBundle.bundleIdentifier == nil || ![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"org.coolstar.SafeMode"]){
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
            int ret = proc_pidpath(getpid(), pathbuf, sizeof(pathbuf));
            if (ret > 0){
                NSString *pathStr = [[NSString stringWithUTF8String:pathbuf] stringByResolvingSymlinksInPath];
                LHLog(OS_LOG_TYPE_ERROR, @"libhooker: Loading for binary %@", pathStr.lastPathComponent);

                if ([pathStr isEqualToString:@"/usr/bin/powerlogHelperd"]){
                    LHLog(OS_LOG_TYPE_ERROR, @"libhooker: Injection is not permitted in this binary");
                    return;
                }

                if ([pathStr hasPrefix:@"/Applications"] || [pathStr hasPrefix:@"/var/containers/Bundle/Application"]){
                    processHash = nil;
                } else {
                    uint8_t digest[CC_SHA1_DIGEST_LENGTH];

                    CC_SHA1(pathbuf, ret, digest);

                    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];

                    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
                    {
                        [output appendFormat:@"%02x", digest[i]];
                    }
                    processHash = [[NSString alloc] initWithString:output];
                }

                safeMode = false;
                NSString *processName = [[NSProcessInfo processInfo] processName];

                struct sigaction action;
                memset(&action, 0, sizeof(action));
                action.sa_sigaction = &SigHandler;
                action.sa_flags = SA_SIGINFO | SA_RESETHAND;
                sigemptyset(&action.sa_mask);

                sigaction(SIGQUIT, &action, NULL);
                sigaction(SIGILL, &action, NULL);
                sigaction(SIGTRAP, &action, NULL);
                sigaction(SIGABRT, &action, NULL);
                sigaction(SIGEMT, &action, NULL);
                sigaction(SIGFPE, &action, NULL);
                sigaction(SIGBUS, &action, NULL);
                sigaction(SIGSEGV, &action, NULL);
                sigaction(SIGSYS, &action, NULL);

                if ([processName isEqualToString:@"backboardd"] || [NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"]){
                    if (file_exist("/var/mobile/Library/.sbinjectSafeMode")){
                        safeMode = true;
                        if ([NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"]){
                            if (!file_exist("/var/tmp/com.apple.backboardd/.bbSafeMode")){
                                unlink("/var/mobile/Library/.sbinjectSafeMode");
                            }
                            LHLog(OS_LOG_TYPE_FAULT, @"Entering Safe Mode!");
                            %init(SafeMode);
                        } else {
                            isBackboard = YES;
                        }
                    }
                }

                if ([processName isEqualToString:@"backboardd"]){
                    if (file_exist("/var/tmp/com.apple.backboardd/.bbSafeMode")){
                        unlink("/var/tmp/com.apple.backboardd/.bbSafeMode");
                        safeMode = true;
                    }
                }

                if ([NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"]){
                    isBackboard = NO;
                    isSpringBoard = YES;
                    pid_t pid = queryDaemon("com.apple.TextInput.kbd");
                    if (pid != 0){
                        kill(pid, SIGKILL);
                    }

                    backboarddPID = queryDaemon("com.apple.backboardd");
                }

                if (processHash){
                    const char *safeModeByProcPath = [[NSString stringWithFormat:@"%@/.safeMode-%@", LHTemporaryDirectory(), processHash] UTF8String];
                    if (file_exist((char *)safeModeByProcPath)){
                        safeMode = true;
                        unlink(safeModeByProcPath);
                    }
                }

                if (getenv("_MSSafeMode")){
                    if (strcmp(getenv("_MSSafeMode"),"1") == 0){
                        safeMode = true;
                    }
                }
                if (getenv("_SafeMode")){
                    if (strcmp(getenv("_SafeMode"),"1") == 0){
                        safeMode = true;
                    }
                }

                BOOL tweaksEnabled = YES;
                if ([[executablePreferences objectForKey:@"enableTweaks"] isKindOfClass:[NSNumber class]]){
                    tweaksEnabled = [[executablePreferences objectForKey:@"enableTweaks"] boolValue];
                }

                if ([pathStr hasPrefix:@"/System/Library/Frameworks/WebKit.framework"] || [pathStr isEqualToString:@"/usr/libexec/nsurlsessiond"]){
                    if ([[preferences objectForKey:@"webProcessTweaks"] isKindOfClass:[NSNumber class]] && tweaksEnabled){
                        tweaksEnabled = [[preferences objectForKey:@"webProcessTweaks"] boolValue];
                    }
                }

                if (safeMode && getenv("DYLD_INSERT_OTHER_LIBRARIES") && tweaksEnabled) {
                    NSArray *array = [@(getenv("DYLD_INSERT_OTHER_LIBRARIES")) componentsSeparatedByString:@":"];

                    dylibInjectList = [array retain];
                    unsetenv("DYLD_INSERT_OTHER_LIBRARIES");
                } else if (!safeMode && tweaksEnabled){
                    BOOL configDeny = YES;
                    if ([[executablePreferences objectForKey:@"allowDeny"] isKindOfClass:[NSNumber class]]){
                        configDeny = ([[executablePreferences objectForKey:@"allowDeny"] intValue] == 1);
                    }

                    BOOL customConfig = NO;
                    if ([[executablePreferences objectForKey:@"customConfig"] isKindOfClass:[NSNumber class]]){
                        customConfig = [[executablePreferences objectForKey:@"customConfig"] boolValue];
                    }

                    NSDictionary *tweakConfigs = nil;
                    if ([[executablePreferences objectForKey:@"tweakConfigs"] isKindOfClass:[NSDictionary class]]){
                        tweakConfigs = [executablePreferences objectForKey:@"tweakConfigs"];
                    }

                    NSArray *rawDylibInjectList = sbinjectGenerateDylibList(pathStr);

                    if (customConfig){
                        NSMutableArray *customInjectList = [NSMutableArray array];
                        for (NSString *dylibPath in rawDylibInjectList){
                            NSString *dylibName = [dylibPath lastPathComponent];

                            BOOL tweakState = NO;
                            if ([[tweakConfigs objectForKey:dylibName] isKindOfClass:[NSNumber class]]){
                                tweakState = [[tweakConfigs objectForKey:dylibName] boolValue];
                            }
                            //deny (true) && state (true) = block
                            //deny (true) && not state (false) == allow
                            //allow (false) && state (true) == allow
                            //allow (false) && not state (false) = block
                            if (configDeny != tweakState){
                                [customInjectList addObject:dylibPath];
                            }
                        }
                        dylibInjectList = [customInjectList retain];
                    } else {
                        dylibInjectList = [rawDylibInjectList retain];
                    }
                } else if (safeMode) {
                    LHLog(OS_LOG_TYPE_FAULT, @"libhooker: Entering Safe Mode!");
                } else {
                    LHLog(OS_LOG_TYPE_FAULT, @"libhooker: Tweaks Disabled!");
                }
            }
        }
    }

    NSDictionary *memPrefs = [preferences objectForKey:@"memPrefs"];
    if (![memPrefs isKindOfClass:[NSDictionary class]]){
        memPrefs = nil;
    }

    for (NSString *dylib in dylibInjectList) {
        if (!safeMode){
            LHLog(OS_LOG_TYPE_ERROR, @"Injecting %@", dylib);
        } else {
            LHLog(OS_LOG_TYPE_ERROR, @"Injecting %@ in Safe Mode!", dylib);
        }

        NSString *dylibname = [dylib lastPathComponent];

        if ([[memPrefs objectForKey:dylibname] isKindOfClass:[NSNumber class]] && ![[memPrefs objectForKey:dylibname] boolValue]){
            void *dl = dlopen([dylib UTF8String], RTLD_LAZY | RTLD_GLOBAL);
            
            if (dl == NULL) {
                LHLog(OS_LOG_TYPE_FAULT, @"Injection failed: '%s'", dlerror());
            }
        } else {
            @autoreleasepool {
                void *dl = dlopen([dylib UTF8String], RTLD_LAZY | RTLD_GLOBAL);
                
                if (dl == NULL) {
                    LHLog(OS_LOG_TYPE_FAULT, @"Injection failed: '%s'", dlerror());
                }
            }
        }   
    }
    [dylibInjectList release];
    [preferences release];
}
