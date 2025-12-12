//
//  jbroot.m
//  TaskPortHaxxApp
//
//  Roothide jailbreak root path management
//  Based on Bootstrap's roothide implementation
//

#import "jbroot.h"
#import <sys/stat.h>
#import <sys/sysctl.h>

uint64_t jbrand_new(void)
{
    uint64_t value = ((uint64_t)arc4random()) | ((uint64_t)arc4random())<<32;
    uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
    return (value & ~0xFF) | check;
}

int is_jbrand_value(uint64_t value)
{
   uint8_t check = value>>8 ^ value >> 16 ^ value>>24 ^ value>>32 ^ value>>40 ^ value>>48 ^ value>>56;
   return check == (uint8_t)value;
}

int is_jbroot_name(const char* name)
{
    if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp=NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if(!endp || *endp!='\0')
        return 0;
    
    if(!is_jbrand_value(value))
        return 0;
    
    return 1;
}

uint64_t resolve_jbrand_value(const char* name)
{
    if(strlen(name) != (sizeof(JB_ROOT_PREFIX)-1+JB_RAND_LENGTH))
        return 0;
    
    if(strncmp(name, JB_ROOT_PREFIX, sizeof(JB_ROOT_PREFIX)-1) != 0)
        return 0;
    
    char* endp=NULL;
    uint64_t value = strtoull(name+sizeof(JB_ROOT_PREFIX)-1, &endp, 16);
    if(!endp || *endp!='\0')
        return 0;
    
    if(!is_jbrand_value(value))
        return 0;
    
    return value;
}

NSString* find_jbroot(BOOL force)
{
    static NSString* cached_jbroot = nil;
    if(!force && cached_jbroot) {
        return cached_jbroot;
    }
    @synchronized(@"find_jbroot_lock")
    {
        // jbroot path may change when re-randomize it
        NSString * jbrootPath = nil;
        NSArray *subItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/containers/Bundle/Application/" error:nil];
        for (NSString *subItem in subItems) {
            if (is_jbroot_name(subItem.UTF8String))
            {
                NSString* path = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:subItem];
                    
                jbrootPath = path;
                break;
            }
        }
        cached_jbroot = jbrootPath;
    }
    return cached_jbroot;
}

NSString* jbroot(NSString *path)
{
    NSString* jbrootPath = find_jbroot(NO);
    if (jbrootPath == nil) {
        NSLog(@"[jbroot] ERROR: jbroot not found!");
        return nil;
    }
    return [jbrootPath stringByAppendingPathComponent:path];
}

char* jbrootc(const char* path) {
    static char result[1024];
    NSString* jbrootPath = find_jbroot(NO);
    if (jbrootPath == nil) {
        return NULL;
    }
    result[0] = '\0';
    strncpy(result, jbrootPath.UTF8String, sizeof(result) - 1);
    result[sizeof(result) - 1] = '\0';
    size_t remaining = sizeof(result) - strlen(result) - 1;
    if (path[0] != '/' && remaining > 0) {
        strncat(result, "/", remaining);
        remaining--;
    }
    strncat(result, path, remaining);
    return result;
}

uint64_t jbrand(void)
{
    NSString* jbrootPath = find_jbroot(NO);
    if (jbrootPath == nil) return 0;
    return resolve_jbrand_value([jbrootPath lastPathComponent].UTF8String);
}

NSString* rootfsPrefix(NSString* path)
{
    return [@"/rootfs/" stringByAppendingPathComponent:path];
}

int create_jbroot(void)
{
    // Check if jbroot already exists
    if (find_jbroot(YES) != nil) {
        NSLog(@"[jbroot] jbroot already exists at %@", find_jbroot(NO));
        return 0;
    }
    
    // Generate new jbrand
    uint64_t rand = jbrand_new();
    char jbroot_name[64];
    snprintf(jbroot_name, sizeof(jbroot_name), "%s%016llX", JB_ROOT_PREFIX, rand);
    
    NSString* jbrootPath = [@"/var/containers/Bundle/Application/" stringByAppendingPathComponent:@(jbroot_name)];
    
    NSError *error = nil;
    BOOL success = [[NSFileManager defaultManager] createDirectoryAtPath:jbrootPath
                                             withIntermediateDirectories:YES
                                                              attributes:@{
                                                                  NSFileOwnerAccountID: @(0),
                                                                  NSFileGroupOwnerAccountID: @(0),
                                                                  NSFilePosixPermissions: @(0755)
                                                              }
                                                                   error:&error];
    if (!success) {
        NSLog(@"[jbroot] Failed to create jbroot directory: %@", error);
        return -1;
    }
    
    NSLog(@"[jbroot] Created jbroot at %@", jbrootPath);
    
    // Force refresh the cached path
    find_jbroot(YES);
    
    return 0;
}

BOOL jbroot_exists(void)
{
    return find_jbroot(YES) != nil;
}

NSString* getBootSession(void)
{
    const size_t maxUUIDLength = 37;
    char uuid[maxUUIDLength];
    memset(uuid, 0, sizeof(uuid));
    size_t uuidLength = maxUUIDLength;
    sysctlbyname("kern.bootsessionuuid", uuid, &uuidLength, NULL, 0);
    
    return @(uuid);
}

