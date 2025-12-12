//
//  jbroot.h
//  TaskPortHaxxApp
//
//  Roothide jailbreak root path management
//  Based on Bootstrap's roothide implementation
//

#ifndef jbroot_h
#define jbroot_h

#import <Foundation/Foundation.h>

// Constants for roothide path
#define JB_ROOT_PREFIX ".jbroot-"
#define JB_RAND_LENGTH  (sizeof(uint64_t)*sizeof(char)*2)

// Generate a new random jbrand value
uint64_t jbrand_new(void);

// Check if a value is a valid jbrand
int is_jbrand_value(uint64_t value);

// Check if a name is a valid jbroot name
int is_jbroot_name(const char* name);

// Resolve the jbrand value from a jbroot name
uint64_t resolve_jbrand_value(const char* name);

// Find the jbroot path
// force: if YES, will re-search even if cached
NSString* find_jbroot(BOOL force);

// Get full path with jbroot prefix
NSString* jbroot(NSString *path);

// Get jbroot as C string
char* jbrootc(const char* path);

// Get the current jbrand value
uint64_t jbrand(void);

// Get the rootfs prefix path
NSString* rootfsPrefix(NSString* path);

// Create jbroot directory
int create_jbroot(void);

// Check if jbroot exists
BOOL jbroot_exists(void);

// Get boot session UUID
NSString* getBootSession(void);

#endif /* jbroot_h */

