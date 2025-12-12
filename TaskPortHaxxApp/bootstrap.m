//
//  bootstrap.m
//  TaskPortHaxxApp
//
//  Bootstrap extraction and setup for roothide jailbreak
//  Based on nathanlr and Bootstrap implementations
//

#import "bootstrap.h"
#import "jbroot.h"
#import "TSUtil.h"
#import "archive.h"
#import "archive_entry.h"

// You'll need to add zstd library or use system decompression
// For now, we'll use libarchive which can handle zstd if compiled with support

NSString *const BootstrapErrorDomain = @"BootstrapErrorDomain";

#define BUFFER_SIZE 8192

#pragma mark - Archive Helpers

static int copy_data(struct archive *ar, struct archive *aw) {
    int r;
    const void *buff;
    size_t size;
    la_int64_t offset;

    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return (ARCHIVE_OK);
        if (r < ARCHIVE_OK)
            return (r);
        r = archive_write_data_block(aw, buff, size, offset);
        if (r < ARCHIVE_OK) {
            fprintf(stderr, "[bootstrap] %s\n", archive_error_string(aw));
            return (r);
        }
    }
}

int libarchive_unarchive(const char *fileToExtract, const char *extractionPath) {
    struct archive *a;
    struct archive *ext;
    struct archive_entry *entry;
    int flags;
    int r;

    // Select which attributes we want to restore
    flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
    flags |= ARCHIVE_EXTRACT_OWNER;

    a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);
    
    if ((r = archive_read_open_filename(a, fileToExtract, 10240))) {
        fprintf(stderr, "[bootstrap] Failed to open archive: %s\n", archive_error_string(a));
        return 1;
    }
    
    for (;;) {
        r = archive_read_next_header(a, &entry);
        if (r == ARCHIVE_EOF)
            break;
        if (r < ARCHIVE_OK)
            fprintf(stderr, "[bootstrap] %s\n", archive_error_string(a));
        if (r < ARCHIVE_WARN)
            return 1;

        const char *currentFile = archive_entry_pathname(entry);
        char outputPath[PATH_MAX];
        strlcpy(outputPath, extractionPath, PATH_MAX);
        strlcat(outputPath, "/", PATH_MAX);
        strlcat(outputPath, currentFile, PATH_MAX);

        archive_entry_set_pathname(entry, outputPath);
        
        r = archive_write_header(ext, entry);
        if (r < ARCHIVE_OK)
            fprintf(stderr, "[bootstrap] %s\n", archive_error_string(ext));
        else if (archive_entry_size(entry) > 0) {
            r = copy_data(a, ext);
            if (r < ARCHIVE_OK)
                fprintf(stderr, "[bootstrap] %s\n", archive_error_string(ext));
            if (r < ARCHIVE_WARN)
                return 1;
        }
        r = archive_write_finish_entry(ext);
        if (r < ARCHIVE_OK)
            fprintf(stderr, "[bootstrap] %s\n", archive_error_string(ext));
        if (r < ARCHIVE_WARN)
            return 1;
    }
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    
    return 0;
}

#pragma mark - Bootstrap Functions

NSError* extractTar(NSString *tarPath, NSString *destinationPath) {
    printf("[bootstrap] Extracting %s to %s\n", tarPath.UTF8String, destinationPath.UTF8String);
    
    int r = libarchive_unarchive(tarPath.fileSystemRepresentation, destinationPath.fileSystemRepresentation);
    if (r != 0) {
        return [NSError errorWithDomain:BootstrapErrorDomain 
                                   code:BootstrapErrorCodeFailedExtracting 
                               userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"libarchive returned %d", r]}];
    }
    return nil;
}

int extractBootstrap(NSString *zstPath) {
    NSString *jbrootPath = find_jbroot(NO);
    if (!jbrootPath) {
        fprintf(stderr, "[bootstrap] ERROR: jbroot not found!\n");
        return BootstrapErrorCodeJBRootNotFound;
    }
    
    printf("[bootstrap] Extracting bootstrap to %s\n", jbrootPath.UTF8String);
    
    // libarchive with zstd support can extract directly
    NSError *error = extractTar(zstPath, jbrootPath);
    if (error) {
        fprintf(stderr, "[bootstrap] Extraction failed: %s\n", error.localizedDescription.UTF8String);
        return (int)error.code;
    }
    
    printf("[bootstrap] ✓ Bootstrap extracted successfully\n");
    return 0;
}

BOOL isBootstrapInstalled(void) {
    NSString *jbrootPath = find_jbroot(NO);
    if (!jbrootPath) return NO;
    
    NSString *marker = [jbrootPath stringByAppendingPathComponent:@".installed_roothide"];
    return [[NSFileManager defaultManager] fileExistsAtPath:marker];
}

int initializeBootstrap(void) {
    NSString *jbrootPath = find_jbroot(NO);
    if (!jbrootPath) {
        fprintf(stderr, "[bootstrap] ERROR: jbroot not found!\n");
        return -1;
    }
    
    printf("[bootstrap] Initializing bootstrap environment...\n");
    
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Create necessary symlinks
    NSString *varJb = @"/var/jb";
    
    // Remove existing /var/jb if it's not our jbroot
    NSError *error = nil;
    NSDictionary *attrs = [fm attributesOfItemAtPath:varJb error:nil];
    if (attrs && [attrs[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) {
        NSString *dest = [fm destinationOfSymbolicLinkAtPath:varJb error:nil];
        if (![dest isEqualToString:jbrootPath]) {
            [fm removeItemAtPath:varJb error:nil];
        }
    } else if ([fm fileExistsAtPath:varJb]) {
        [fm removeItemAtPath:varJb error:nil];
    }
    
    // Create symlink /var/jb -> jbroot (for compatibility)
    if (![fm fileExistsAtPath:varJb]) {
        if ([fm createSymbolicLinkAtPath:varJb withDestinationPath:jbrootPath error:&error]) {
            printf("[bootstrap] Created symlink: /var/jb -> %s\n", jbrootPath.UTF8String);
            // Set proper ownership
            lchown("/var/jb", 0, 0);
        } else {
            printf("[bootstrap] Note: Could not create /var/jb symlink: %s\n", error.localizedDescription.UTF8String);
        }
    }
    
    // Create default sources.list.d content for roothide
    NSString *sourcesDir = [jbrootPath stringByAppendingPathComponent:@"etc/apt/sources.list.d"];
    [fm createDirectoryAtPath:sourcesDir withIntermediateDirectories:YES attributes:nil error:nil];
    
    NSString *defaultSources = @"Types: deb\n"
        @"URIs: https://repo.chariz.com/\n"
        @"Suites: ./\n"
        @"Components:\n"
        @"\n"
        @"Types: deb\n"
        @"URIs: https://havoc.app/\n"
        @"Suites: ./\n"
        @"Components:\n"
        @"\n"
        @"Types: deb\n"
        @"URIs: http://apt.thebigboss.org/repofiles/cydia/\n"
        @"Suites: stable\n"
        @"Components: main\n"
        @"\n"
        @"Types: deb\n"
        @"URIs: https://ellekit.space/\n"
        @"Suites: ./\n"
        @"Components:\n";
    
    NSString *sourcesFile = [sourcesDir stringByAppendingPathComponent:@"default.sources"];
    [defaultSources writeToFile:sourcesFile atomically:NO encoding:NSUTF8StringEncoding error:nil];
    
    // Create roothide-specific source
    NSString *roothideSources = @"Types: deb\n"
        @"URIs: https://roothide.github.io/\n"
        @"Suites: ./\n"
        @"Components:\n";
    
    NSString *roothideSourcesFile = [sourcesDir stringByAppendingPathComponent:@"roothide.sources"];
    [roothideSources writeToFile:roothideSourcesFile atomically:NO encoding:NSUTF8StringEncoding error:nil];
    
    // Run prep_bootstrap.sh if it exists
    NSString *prepScript = [jbrootPath stringByAppendingPathComponent:@"prep_bootstrap.sh"];
    if ([fm fileExistsAtPath:prepScript]) {
        NSString *shPath = [jbrootPath stringByAppendingPathComponent:@"bin/sh"];
        if ([fm fileExistsAtPath:shPath]) {
            spawnRoot(shPath, @[prepScript], nil, nil);
        }
    }
    
    // Create marker file
    NSString *marker = [jbrootPath stringByAppendingPathComponent:@".installed_roothide"];
    [@"" writeToFile:marker atomically:NO encoding:NSUTF8StringEncoding error:nil];
    
    printf("[bootstrap] ✓ Bootstrap initialization complete\n");
    return 0;
}

int removeBootstrap(void) {
    NSString *jbrootPath = find_jbroot(YES);
    if (!jbrootPath) {
        printf("[bootstrap] No jbroot found to remove\n");
        return 0;
    }
    
    printf("[bootstrap] Removing bootstrap at %s\n", jbrootPath.UTF8String);
    
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error = nil;
    
    // Remove /var/jb symlink
    [fm removeItemAtPath:@"/var/jb" error:nil];
    
    // Remove jbroot directory
    if ([fm removeItemAtPath:jbrootPath error:&error]) {
        printf("[bootstrap] ✓ Bootstrap removed successfully\n");
        return 0;
    } else {
        fprintf(stderr, "[bootstrap] Failed to remove bootstrap: %s\n", error.localizedDescription.UTF8String);
        return -1;
    }
}

int spawnBootstrap(NSArray *args, NSString **stdOut, NSString **stdErr) {
    NSString *jbrootPath = find_jbroot(NO);
    if (!jbrootPath) {
        fprintf(stderr, "[bootstrap] ERROR: jbroot not found!\n");
        return -1;
    }
    
    if (args.count == 0) {
        return -1;
    }
    
    NSString *cmd = args[0];
    NSString *fullPath = [jbrootPath stringByAppendingPathComponent:cmd];
    
    // Check if command exists
    if (![[NSFileManager defaultManager] fileExistsAtPath:fullPath]) {
        fprintf(stderr, "[bootstrap] Command not found: %s\n", fullPath.UTF8String);
        return -1;
    }
    
    NSMutableArray *fullArgs = [args mutableCopy];
    [fullArgs replaceObjectAtIndex:0 withObject:fullPath];
    
    return spawnRoot(fullPath, [fullArgs subarrayWithRange:NSMakeRange(1, fullArgs.count - 1)], stdOut, stdErr);
}

