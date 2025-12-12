//
//  bootstrap.h
//  TaskPortHaxxApp
//
//  Bootstrap extraction and setup for roothide jailbreak
//

#ifndef bootstrap_h
#define bootstrap_h

#import <Foundation/Foundation.h>

// Error domain and codes
extern NSString *const BootstrapErrorDomain;
typedef NS_ENUM(NSInteger, BootstrapErrorCode) {
    BootstrapErrorCodeFailedToGetURL            = -1,
    BootstrapErrorCodeFailedToDownload          = -2,
    BootstrapErrorCodeFailedDecompressing       = -3,
    BootstrapErrorCodeFailedExtracting          = -4,
    BootstrapErrorCodeFailedRemount             = -5,
    BootstrapErrorCodeFailedFinalising          = -6,
    BootstrapErrorCodeFailedReplacing           = -7,
    BootstrapErrorCodeJBRootNotFound            = -8,
};

// Decompress a zstd file to tar
NSError* decompressZstd(NSString *zstdPath, NSString *tarPath);

// Extract a tar archive to destination path
NSError* extractTar(NSString *tarPath, NSString *destinationPath);

// Extract bootstrap from bundled zst file to jbroot
int extractBootstrap(NSString *zstPath);

// Initialize bootstrap environment (install base packages, create symlinks, etc.)
int initializeBootstrap(void);

// Check if bootstrap is already installed
BOOL isBootstrapInstalled(void);

// Remove bootstrap
int removeBootstrap(void);

// Spawn a command in bootstrap environment
int spawnBootstrap(NSArray *args, NSString **stdOut, NSString **stdErr);

#endif /* bootstrap_h */

