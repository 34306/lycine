GO_EASY_ON_ME = 1

TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = TaskPortHaxxApp
ARCHS = arm64
PACKAGE_FORMAT = ipa
FINALPACKAGE = 1

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = TaskPortHaxxApp

TaskPortHaxxApp_FILES = \
	TaskPortHaxxApp/AppDelegate.m \
	TaskPortHaxxApp/SceneDelegate.m \
	TaskPortHaxxApp/ViewController.m \
	TaskPortHaxxApp/ProcessContext.m \
	TaskPortHaxxApp/main.m \
	TaskPortHaxxApp/fake_bootstrap_server.m \
	TaskPortHaxxApp/launch.m \
	TaskPortHaxxApp/troller.m \
	TaskPortHaxxApp/unarchive.m \
	TaskPortHaxxApp/NSUserDefaults+Pref.m \
	TaskPortHaxxApp/roothelper.m \
	TaskPortHaxxApp/coretrust_bug.c \
	TaskPortHaxxApp/TSUtil.m \
	TaskPortHaxxApp/jbroot.m \
	TaskPortHaxxApp/bootstrap.m \
	TaskPortHaxxApp/codesign.m
TaskPortHaxxApp_FRAMEWORKS = UIKit CoreGraphics CoreServices IOKit Security
TaskPortHaxxApp_LIBRARIES = archive
TaskPortHaxxApp_CFLAGS = -fobjc-arc -ITaskPortHaxxApp -IfastPathSign/src/external/include
TaskPortHaxxApp_LDFLAGS = fastPathSign/src/external/lib/libchoma.a fastPathSign/src/external/lib/libcrypto.a
TaskPortHaxxApp_CODESIGN_FLAGS = -S./TaskPortHaxxApp/TaskPortHaxxApp.ent

include $(THEOS_MAKE_PATH)/application.mk

# Build launchdhook.dylib
launchdhook/launchdhook.dylib:
	@echo "Building launchdhook.dylib..."
	$(MAKE) -C launchdhook
	@echo "Signing launchdhook.dylib..."
	ldid -S launchdhook/launchdhook.dylib || true

# Build xpcproxyhook.dylib
xpcproxyhook/xpcproxyhook.dylib:
	@echo "Building xpcproxyhook.dylib..."
	$(MAKE) -C xpcproxyhook
	@echo "Signing xpcproxyhook.dylib..."
	ldid -S xpcproxyhook/xpcproxyhook.dylib || true

# Build all hooks
hooks: launchdhook/launchdhook.dylib xpcproxyhook/xpcproxyhook.dylib

# Build hooks before the main build starts
before-all:: hooks

after-stage::
	@echo "Copying resources to app bundle..."
	$(ECHO_NOTHING)cp Resources/launchd_ent.plist $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/launchd_ent.plist$(ECHO_END)
	$(ECHO_NOTHING)cp Resources/ldid $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/ldid$(ECHO_END)
	$(ECHO_NOTHING)chmod +x $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/ldid$(ECHO_END)
	$(ECHO_NOTHING)cp Resources/insert_dylib $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/insert_dylib$(ECHO_END)
	$(ECHO_NOTHING)chmod +x $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/insert_dylib$(ECHO_END)
	@echo "Copying bootstrap..."
	$(ECHO_NOTHING)cp Resources/bootstrap.tar.zst $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/bootstrap.tar.zst$(ECHO_END)
	@echo "Copying hooks..."
	$(ECHO_NOTHING)cp launchdhook/launchdhook.dylib $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/launchdhook.dylib$(ECHO_END)
	$(ECHO_NOTHING)cp xpcproxyhook/xpcproxyhook.dylib $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/xpcproxyhook.dylib$(ECHO_END)
	@echo "Build complete!"

clean-hooks:
	$(MAKE) -C launchdhook clean
	$(MAKE) -C xpcproxyhook clean

#SUBPROJECTS += opainject
#include $(THEOS_MAKE_PATH)/aggregate.mk
