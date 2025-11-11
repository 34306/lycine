//
//  roothelper.m
//  TaskPortHaxxApp
//
//  Root helper that copies and patches launchd
//

@import Foundation;
@import Darwin;
#import <sys/stat.h>
#import <copyfile.h>
#import <fcntl.h>
#import <sys/mman.h>
#import <errno.h>
#import "coretrust_bug.h"
#import "TSUtil.h"

// Search and replace a string in a buffer
BOOL patch_binary_string(void *data, size_t size, const char *search_str, const char *replace_str) {
    size_t search_len = strlen(search_str);
    size_t replace_len = strlen(replace_str);
    
    if (replace_len > search_len) {
        fprintf(stderr, "[roothelper] Replacement string is longer than search string!\n");
        return NO;
    }
    
    BOOL found = NO;
    size_t count = 0;
    
    // Search for all occurrences
    for (size_t i = 0; i <= size - search_len; i++) {
        if (memcmp((char *)data + i, search_str, search_len) == 0) {
            found = YES;
            count++;
            printf("[roothelper] Found '%s' at offset 0x%zx\n", search_str, i);
            
            // Replace the string
            memset((char *)data + i, 0, search_len);
            memcpy((char *)data + i, replace_str, replace_len);
            
            printf("[roothelper] Replaced with '%s'\n", replace_str);
        }
    }
    
    if (found) {
        printf("[roothelper] Total replacements: %zu\n", count);
    } else {
        printf("[roothelper] WARNING: String '%s' not found in binary\n", search_str);
    }
    
    return found;
}

int roothelper_main(void) {
    printf("[roothelper] Starting as UID: %d, GID: %d\n", getuid(), getgid());
    
    // Verify we're running as root
    if (getuid() != 0) {
        fprintf(stderr, "[roothelper] ERROR: Not running as root!\n");
        return 1;
    }
    
    // Get boot manifest hash path
    char *preboot_path = return_boot_manifest_hash_main();
    printf("[roothelper] Preboot path: %s\n", preboot_path);
    
    // Build paths using preboot location
    char hax_dir[256];
    char dest[256];
    snprintf(hax_dir, sizeof(hax_dir), "%s/hax", preboot_path);
    snprintf(dest, sizeof(dest), "%s/hax/launchd", preboot_path);
    
    const char *source = "/sbin/launchd";
    const char *symlink_path = "/var/.launchd";
    const char *search_str = "/sbin/launchd";
    const char *replace_str = "/var/.launchd";
    const char *amfi_str = "AMFI";
    const char *amfi_replace = "AAAA";
    
    const char *sourceTmp = "/var/tmp/launchd";
    // Remove sourceTmp if it exists
    if (access(sourceTmp, F_OK) == 0) {
        printf("[roothelper] sourceTmp exists, removing...\n");
        if (unlink(sourceTmp) != 0) {
            perror("[roothelper] Failed to remove existing sourceTmp\n");
            return 1;
        }
    }
    
    // copy to sourceTmp
    printf("[roothelper] copy to sourceTmp...\n");
    int result = copyfile(source, sourceTmp, NULL, COPYFILE_ALL);
    if (result != 0) {
        perror("[roothelper] Failed copy to sourceTmp");
        return 1;
    }
    
    // Get bundled insert_dylib path
    NSString *insertdylibPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"insert_dylib"];
    printf("[roothelper] insert_dylib binary: %s\n", insertdylibPath.UTF8String);
    
    // Prepare insert_dylib arguments
    char *argv1[] = {
        (char *)insertdylibPath.UTF8String,
        "--inplace",
        "--all-yes",
        "--overwrite",
        "--no-strip-codesig",
        "--weak",
        "@executable_path/launchdhook.dylib",
        (char *)sourceTmp,
        NULL
    };
    
    printf("[roothelper] Executing: %s %s\n", insertdylibPath.UTF8String, sourceTmp);
    
    // Spawn insert_dylib
    pid_t pid;
    int status;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    
    result = posix_spawn(&pid, insertdylibPath.UTF8String, NULL, &attr, argv1, NULL);
    posix_spawnattr_destroy(&attr);
    
    if (result != 0) {
        fprintf(stderr, "[roothelper] ✗ FAILED: Failed to spawn insert_dylib, error code: %d\n", result);
        fprintf(stderr, "[roothelper] Binary may not be properly signed\n");
        return 1;
    }
    
    // Wait for ldid to complete
    waitpid(pid, &status, 0);
    
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[roothelper] ✗ FAILED: insert_dylib exited with status: %d\n", WEXITSTATUS(status));
        fprintf(stderr, "[roothelper] Binary may not be properly signed\n");
        return 1;
    }
    
    printf("[roothelper] ✓ SUCCESS: insert_dylib completed successfully\n");
    
    // Create hax directory if it doesn't exist
    printf("[roothelper] Creating directory %s\n", hax_dir);
    if (mkdir(hax_dir, 0755) != 0 && errno != EEXIST) {
        perror("[roothelper] Failed to create hax directory");
        return 1;
    }
    
    // copy to sourceTmp
    printf("[roothelper] copy launchdhook.dylib to hax...\n");
    NSString *launchdHookDylibPath = [[NSString stringWithUTF8String:hax_dir] stringByAppendingPathComponent:@"launchdhook.dylib"];
    unlink(launchdHookDylibPath.UTF8String);
    result = copyfile("/var/mobile/Media/launchdhook.dylib", launchdHookDylibPath.UTF8String, NULL, COPYFILE_ALL);
    if (result != 0) {
        perror("[roothelper] Failed copy to launchdhook.dylib");
        return 1;
    }
    
    printf("[roothelper] Reading %s\n", source);
    
    // Open and read the source file
    int fd = open(sourceTmp, O_RDONLY);
    if (fd < 0) {
        perror("[roothelper] Failed to open source file");
        return 1;
    }
    
    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror("[roothelper] Failed to stat source");
        close(fd);
        return 1;
    }
    
    printf("[roothelper] Source file size: %lld bytes\n", st.st_size);
    
    // Map the file into memory
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("[roothelper] Failed to mmap source");
        close(fd);
        return 1;
    }
    close(fd);
    
    // Allocate a writable buffer for patching
    void *data = malloc(st.st_size);
    if (!data) {
        fprintf(stderr, "[roothelper] Failed to allocate memory\n");
        munmap(map, st.st_size);
        return 1;
    }
    
    // Copy data to writable buffer
    memcpy(data, map, st.st_size);
    munmap(map, st.st_size);
    
    printf("[roothelper] Patching binary...\n");
    
    // Patch the launchd path string
    BOOL patched_path = patch_binary_string(data, st.st_size, search_str, replace_str);
    
    // Patch the AMFI string (for launch constraint bypass on iOS 17.0)
    BOOL patched_amfi = patch_binary_string(data, st.st_size, amfi_str, amfi_replace);
    
    if (!patched_path) {
        fprintf(stderr, "[roothelper] WARNING: Failed to patch launchd path string\n");
    }
    
    if (!patched_amfi) {
        printf("[roothelper] Note: AMFI string not found (may not be needed on this iOS version)\n");
    }
    
    // Remove destination if it exists
    if (access(dest, F_OK) == 0) {
        printf("[roothelper] Destination exists, removing...\n");
        if (unlink(dest) != 0) {
            perror("[roothelper] Failed to remove existing destination");
            free(data);
            return 1;
        }
    }
    
    printf("[roothelper] Writing patched binary to %s\n", dest);
    
    // Write the patched data to destination
    int out_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) {
        perror("[roothelper] Failed to create destination file");
        free(data);
        return 1;
    }
    
    ssize_t written = write(out_fd, data, st.st_size);
    if (written != st.st_size) {
        perror("[roothelper] Failed to write complete data");
        close(out_fd);
        free(data);
        return 1;
    }
    
    close(out_fd);
    free(data);
    
    printf("[roothelper] Patched binary written successfully\n");
    
    // Verify the destination file
    struct stat st_dest;
    if (stat(dest, &st_dest) != 0) {
        perror("[roothelper] Failed to stat destination");
        return 1;
    }
    
    printf("[roothelper] Destination file size: %lld bytes\n", st_dest.st_size);
    printf("[roothelper] Destination permissions: 0%o\n", st_dest.st_mode & 0777);
    
    // Step 1: Sign with ldid using entitlements
    printf("\n[roothelper] ========================================\n");
    printf("[roothelper] Step 1: ldid signing with entitlements\n");
    printf("[roothelper] ========================================\n");
    printf("[roothelper] Target: %s\n", dest);
    
    // Get bundled ldid path
    NSString *ldidPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"ldid"];
    printf("[roothelper] ldid binary: %s\n", ldidPath.UTF8String);
    
    // Get entitlements path from app bundle
    NSString *entPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"launchd_ent.plist"];
    printf("[roothelper] Entitlements: %s\n", entPath.UTF8String);
    
    // Prepare ldid arguments
    NSString *entArg = [NSString stringWithFormat:@"-S%@", entPath];
    char *argv[] = {
        (char *)ldidPath.UTF8String,
        (char *)entArg.UTF8String,
        dest,
        NULL
    };
    
    printf("[roothelper] Executing: %s %s %s\n", ldidPath.UTF8String, entArg.UTF8String, dest);
    
    // Spawn ldid
    posix_spawnattr_init(&attr);
    
    int sign_result = posix_spawn(&pid, ldidPath.UTF8String, NULL, &attr, argv, NULL);
    posix_spawnattr_destroy(&attr);
    
    if (sign_result != 0) {
        fprintf(stderr, "[roothelper] ✗ FAILED: Failed to spawn ldid, error code: %d\n", sign_result);
        fprintf(stderr, "[roothelper] Binary may not be properly signed\n");
        return 1;
    }
    
    // Wait for ldid to complete
    waitpid(pid, &status, 0);
    
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[roothelper] ✗ FAILED: ldid exited with status: %d\n", WEXITSTATUS(status));
        fprintf(stderr, "[roothelper] Binary may not be properly signed\n");
        return 1;
    }
    
    printf("[roothelper] ✓ SUCCESS: ldid signing completed successfully\n");
    
    // Verify the signed binary
    struct stat st_signed;
    if (stat(dest, &st_signed) == 0) {
        printf("[roothelper] Signed binary size: %lld bytes\n", st_signed.st_size);
    }
    
    // Step 2: Apply CoreTrust bypass
    printf("\n[roothelper] ========================================\n");
    printf("[roothelper] Step 2: CoreTrust Bypass\n");
    printf("[roothelper] ========================================\n");
    printf("[roothelper] Target: %s\n", dest);
    printf("[roothelper] Applying CoreTrust bypass...\n");
    
    int bypass_result = apply_coretrust_bypass(dest);
    if (bypass_result != 0) {
        fprintf(stderr, "[roothelper] ✗ FAILED: CoreTrust bypass failed with error code: %d\n", bypass_result);
        fprintf(stderr, "[roothelper] Binary may not pass signature validation\n");
        return 1;
    }
    printf("[roothelper] ✓ SUCCESS: CoreTrust bypass applied successfully\n");
    
    bypass_result = apply_coretrust_bypass(launchdHookDylibPath.UTF8String);
    if (bypass_result != 0) {
        fprintf(stderr, "[roothelper] ✗ FAILED: CoreTrust bypass failed with error code: %d\n", bypass_result);
        fprintf(stderr, "[roothelper] Binary may not pass signature validation\n");
        return 1;
    }
    printf("[roothelper] ✓ SUCCESS: CoreTrust bypass applied successfully\n");
    
    // Verify the bypassed binary
    struct stat st_bypassed;
    if (stat(dest, &st_bypassed) == 0) {
        printf("[roothelper] Final binary size: %lld bytes\n", st_bypassed.st_size);
    }
    printf("[roothelper] ========================================\n\n");
    
    // Remove old symlink if it exists
    if (lstat(symlink_path, &st_dest) == 0) {
        printf("[roothelper] Removing existing symlink at %s\n", symlink_path);
        if (unlink(symlink_path) != 0) {
            perror("[roothelper] Failed to remove existing symlink");
            return 1;
        }
    }
    
    // Create symlink from /var/.launchd to the patched binary
    printf("[roothelper] Creating symlink %s -> %s\n", symlink_path, dest);
    if (symlink(dest, symlink_path) != 0) {
        perror("[roothelper] Failed to create symlink");
        return 1;
    }
    
    // Verify symlink
    char link_target[1024];
    ssize_t len = readlink(symlink_path, link_target, sizeof(link_target) - 1);
    if (len != -1) {
        link_target[len] = '\0';
        printf("[roothelper] Verified symlink: %s -> %s\n", symlink_path, link_target);
    }
    
    printf("[roothelper] ✓ Success! Patched launchd setup complete!\n");
    printf("[roothelper] Binary location: %s\n", dest);
    printf("[roothelper] Symlink: %s -> %s\n", symlink_path, dest);
    printf("[roothelper] Changes made:\n");
    printf("[roothelper]   - Replaced '%s' with '%s'\n", search_str, replace_str);
    if (patched_amfi) {
        printf("[roothelper]   - Replaced '%s' with '%s' (launch constraint bypass)\n", amfi_str, amfi_replace);
    }
    printf("[roothelper]   - ✓ Signed with ldid + entitlements\n");
    printf("[roothelper]   - ✓ CoreTrust bypass applied\n");
    
    return 0;
}

