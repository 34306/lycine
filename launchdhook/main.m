//
//  main.m
//  launchdhook
//
//  Launchd hook for roothide jailbreak
//  Based on Serotonin's launchdhook but adapted for roothide paths
//

#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <Foundation/Foundation.h>
#include <bsm/audit.h>
#include <xpc/xpc.h>
#include <stdio.h>
#include "fishhook.h"
#include <spawn.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/stat.h>

#define __probable(x)   __builtin_expect(!!(x), 1)
#define __improbable(x) __builtin_expect(!!(x), 0)
#define SPRINGBOARD_PATH    "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
#define XPCPROXY_PATH       "/usr/libexec/xpcproxy"

// Roothide path constants
#define JB_ROOT_PREFIX ".jbroot-"
#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)

int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attr, uint8_t launch_type);

// Function pointers for hooked functions
int (*orig_csops)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int (*orig_csops_audittoken)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);
int (*orig_posix_spawn)(pid_t *restrict pid, const char *restrict path,
                        const posix_spawn_file_actions_t *file_actions,
                        const posix_spawnattr_t *restrict attrp,
                        char *const argv[restrict], char *const envp[restrict]);
int (*orig_posix_spawnp)(pid_t *restrict pid, const char *restrict path,
                         const posix_spawn_file_actions_t *restrict file_actions,
                         const posix_spawnattr_t *restrict attrp,
                         char *const argv[restrict], char *const envp[restrict]);
xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t xdict, const char *key);
int (*memorystatus_control_orig)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
bool (*xpc_dictionary_get_bool_orig)(xpc_object_t dictionary, const char *key);

// Global variables
static char g_jbroot_path[PATH_MAX] = {0};
static bool g_jbroot_found = false;

#pragma mark - Roothide Path Functions

static int is_jbrand_value(uint64_t value) {
    uint8_t check = value>>8 ^ value>>16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
    return check == (uint8_t)value;
}

static int is_jbroot_name(const char* name) {
    if (strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if (strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp = NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if (!endp || *endp != '\0')
        return 0;
    
    if (!is_jbrand_value(value))
        return 0;
    
    return 1;
}

static void find_jbroot(void) {
    if (g_jbroot_found) return;
    
    DIR *dir = opendir("/var/containers/Bundle/Application/");
    if (!dir) return;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (is_jbroot_name(entry->d_name)) {
            snprintf(g_jbroot_path, sizeof(g_jbroot_path), 
                    "/var/containers/Bundle/Application/%s", entry->d_name);
            g_jbroot_found = true;
            break;
        }
    }
    closedir(dir);
}

static char* jbroot(const char* path) {
    static char result[PATH_MAX];
    
    if (!g_jbroot_found) {
        find_jbroot();
    }
    
    if (!g_jbroot_found) {
        return (char*)path;
    }
    
    result[0] = '\0';
    strncpy(result, g_jbroot_path, sizeof(result) - 1);
    result[sizeof(result) - 1] = '\0';
    
    size_t remaining = sizeof(result) - strlen(result) - 1;
    if (path[0] != '/' && remaining > 0) {
        strncat(result, "/", remaining);
        remaining--;
    }
    strncat(result, path, remaining);
    return result;
}

static NSString* jbrootobjc(NSString *path) {
    if (!g_jbroot_found) {
        find_jbroot();
    }
    
    if (!g_jbroot_found) {
        return path;
    }
    
    return [@(g_jbroot_path) stringByAppendingPathComponent:path];
}

#pragma mark - Hooked Functions

int hooked_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int result = orig_csops(pid, ops, useraddr, usersize);
    if (result != 0) return result;
    if (ops == 0) { // CS_OPS_STATUS
       *((uint32_t *)useraddr) |= 0x4000001; // CS_PLATFORM_BINARY
    }
    return result;
}

int hooked_csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token) {
    int result = orig_csops_audittoken(pid, ops, useraddr, usersize, token);
    if (result != 0) return result;
    if (ops == 0) { // CS_OPS_STATUS
       *((uint32_t *)useraddr) |= 0x4000001; // CS_PLATFORM_BINARY
    }
    return result;
}

void change_launchtype(const posix_spawnattr_t *attrp, const char *restrict path) {
    if (!g_jbroot_found) {
        find_jbroot();
    }
    
    const char *prefixes[] = {
        "/private/preboot",
        g_jbroot_found ? g_jbroot_path : "/nonexistent",
    };

    if (__builtin_available(macOS 13.0, iOS 16.0, tvOS 16.0, watchOS 9.0, *)) {
        for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
            size_t prefix_len = strlen(prefixes[i]);
            if (strncmp(path, prefixes[i], prefix_len) == 0) {
                if (attrp != 0) {
                    posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
                }
                break;
            }
        }
    }
}

int hooked_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
                       posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {
    change_launchtype(attrp, path);
    return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

int hooked_posix_spawnp(pid_t *restrict pid, const char *restrict path,
                        const posix_spawn_file_actions_t *restrict file_actions,
                        posix_spawnattr_t *attrp, char *argv[restrict], char *const envp[restrict]) {
    
    // Hook SpringBoard to use roothide version
    if (!strncmp(path, SPRINGBOARD_PATH, strlen(SPRINGBOARD_PATH))) {
        char* jb_path = jbroot(SPRINGBOARD_PATH);
        // Check if jbroot SpringBoard exists
        struct stat st;
        if (stat(jb_path, &st) == 0) {
            path = jb_path;
            argv[0] = (char *)path;
            if (__builtin_available(iOS 16.0, *)) {
                posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
            }
        }
    }
    // Hook xpcproxy to use roothide version
    else if (__probable(!strncmp(path, XPCPROXY_PATH, strlen(XPCPROXY_PATH)))) {
        char* jb_path = jbroot(XPCPROXY_PATH);
        struct stat st;
        if (stat(jb_path, &st) == 0) {
            path = jb_path;
            argv[0] = (char *)path;
            if (__builtin_available(iOS 16.0, *)) {
                posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
            }
        }
    }
    
    change_launchtype(attrp, path);
    return orig_posix_spawnp(pid, path, file_actions, (posix_spawnattr_t *)attrp, argv, envp);
}

bool hook_xpc_dictionary_get_bool(xpc_object_t dictionary, const char *key) {
    if (!strcmp(key, "LogPerformanceStatistics")) return true;
    return xpc_dictionary_get_bool_orig(dictionary, key);
}

xpc_object_t hook_xpc_dictionary_get_value(xpc_object_t dict, const char *key) {
    xpc_object_t retval = xpc_dictionary_get_value_orig(dict, key);

    if (!strcmp(key, "Paths")) {
        if (!g_jbroot_found) {
            find_jbroot();
        }
        
        if (g_jbroot_found && retval && xpc_get_type(retval) == XPC_TYPE_ARRAY) {
            // Add roothide LaunchDaemon paths
            const char *paths[] = {
                "/Library/LaunchDaemons",
                "/System/Library/LaunchDaemons",
                "/Library/LaunchAgents",
                "/System/Library/LaunchAgents",
            };

            for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
                char* jb_path = jbroot(paths[i]);
                struct stat st;
                if (stat(jb_path, &st) == 0) {
                    xpc_array_append_value(retval, xpc_string_create(jb_path));
                }
            }
        }
    }

    return retval;
}

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6

int memorystatus_control_hook(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize) {
    if (command == MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT) {
        return 0;
    }
    return memorystatus_control_orig(command, pid, flags, buffer, buffersize);
}

#pragma mark - Constructor

__attribute__((constructor)) static void init(int argc, char **argv) {
    NSLog(@"[launchdhook] Initializing roothide launchd hook...");
    
    // Find jbroot path
    find_jbroot();
    if (g_jbroot_found) {
        NSLog(@"[launchdhook] Found jbroot at: %s", g_jbroot_path);
    } else {
        NSLog(@"[launchdhook] WARNING: jbroot not found!");
    }
    
    // Set environment variables
    if (g_jbroot_found) {
        char hook_path[PATH_MAX];
        snprintf(hook_path, sizeof(hook_path), "%s/basebin/launchdhook.dylib", g_jbroot_path);
        setenv("DYLD_INSERT_LIBRARIES", hook_path, 1);
    }
    setenv("LAUNCHD_UUID", [NSUUID UUID].UUIDString.UTF8String, 1);

    // Stock bug fix: These prefs wipe themselves after a reboot
    // On userspace reboots, they do not get wiped as boot time doesn't change
    // This fixes nano launch daemons not being loaded after userspace reboot
    if (__probable(!access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist", W_OK))) {
        remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRRootCommander.volatile.plist");
    }
    if (__probable(!access("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist", W_OK))) {
        remove("/var/mobile/Library/Preferences/com.apple.NanoRegistry.NRLaunchNotificationController.volatile.plist");
    }
    
    // Apply hooks using fishhook
    struct rebinding rebindings[] = {
        {"csops", hooked_csops, (void *)&orig_csops},
        {"csops_audittoken", hooked_csops_audittoken, (void *)&orig_csops_audittoken},
        {"posix_spawn", hooked_posix_spawn, (void *)&orig_posix_spawn},
        {"posix_spawnp", hooked_posix_spawnp, (void *)&orig_posix_spawnp},
        {"xpc_dictionary_get_bool", hook_xpc_dictionary_get_bool, (void *)&xpc_dictionary_get_bool_orig},
        {"xpc_dictionary_get_value", hook_xpc_dictionary_get_value, (void *)&xpc_dictionary_get_value_orig},
        {"memorystatus_control", memorystatus_control_hook, (void *)&memorystatus_control_orig},
    };
    rebind_symbols(rebindings, sizeof(rebindings)/sizeof(struct rebinding));
    
    NSLog(@"[launchdhook] Roothide launchd hook initialized successfully");
}

