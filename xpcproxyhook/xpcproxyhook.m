//
//  xpcproxyhook.m
//  xpcproxyhook
//
//  XPCProxy hook for roothide jailbreak
//  Based on Serotonin's xpcproxyhook but adapted for roothide paths
//

#include "fishhook.h"
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <Foundation/Foundation.h>
#include <bsm/audit.h>
#include <xpc/xpc.h>
#include <stdio.h>
#include <spawn.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/stat.h>

// Roothide path constants
#define JB_ROOT_PREFIX ".jbroot-"
#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)

#define INSTALLD_PATH       "/usr/libexec/installd"
#define NFCD_PATH           "/usr/libexec/nfcd"
#define CFPREFSD_PATH       "/usr/sbin/cfprefsd"
#define MEDIASERVERD_PATH   "/usr/sbin/mediaserverd"

int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attr, uint8_t launch_type);

// Function pointers for hooked functions
int (*orig_csops)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int (*orig_csops_audittoken)(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);
int (*orig_posix_spawnp)(pid_t *restrict pid, const char *restrict path,
                         const posix_spawn_file_actions_t *restrict file_actions,
                         const posix_spawnattr_t *restrict attrp,
                         char *const argv[restrict], char *const envp[restrict]);

// Global jbroot path
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

int hooked_posix_spawnp(pid_t *restrict pid, const char *restrict path,
                        const posix_spawn_file_actions_t *restrict file_actions,
                        posix_spawnattr_t *attrp, char *argv[restrict], char *envp[restrict]) {
    
    // Hook cfprefsd to use roothide version
    if (strncmp(path, CFPREFSD_PATH, strlen(CFPREFSD_PATH)) == 0) {
        char* jb_path = jbroot(CFPREFSD_PATH);
        struct stat st;
        if (stat(jb_path, &st) == 0) {
            path = jb_path;
            argv[0] = (char *)path;
            if (__builtin_available(iOS 16.0, *)) {
                posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
            }
        }
    }
    // Hook installd to use roothide version
    else if (strncmp(path, INSTALLD_PATH, strlen(INSTALLD_PATH)) == 0) {
        char* jb_path = jbroot(INSTALLD_PATH);
        struct stat st;
        if (stat(jb_path, &st) == 0) {
            path = jb_path;
            argv[0] = (char *)path;
            if (__builtin_available(iOS 16.0, *)) {
                posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
            }
        }
    }
    // Hook nfcd to use roothide version
    else if (strncmp(path, NFCD_PATH, strlen(NFCD_PATH)) == 0) {
        char* jb_path = jbroot(NFCD_PATH);
        struct stat st;
        if (stat(jb_path, &st) == 0) {
            path = jb_path;
            argv[0] = (char *)path;
            if (__builtin_available(iOS 16.0, *)) {
                posix_spawnattr_set_launch_type_np((posix_spawnattr_t *)attrp, 0);
            }
        }
    }
    
    return orig_posix_spawnp(pid, path, file_actions, attrp, argv, envp);
}

#pragma mark - Constructor

__attribute__((constructor)) static void init(int argc, char **argv) {
    // Find jbroot path
    find_jbroot();
    
    // Apply hooks using fishhook
    struct rebinding rebindings[] = {
        {"csops", hooked_csops, (void *)&orig_csops},
        {"csops_audittoken", hooked_csops_audittoken, (void *)&orig_csops_audittoken},
        {"posix_spawnp", hooked_posix_spawnp, (void *)&orig_posix_spawnp},
    };
    rebind_symbols(rebindings, sizeof(rebindings)/sizeof(struct rebinding));
}

