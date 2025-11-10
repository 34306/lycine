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
	TaskPortHaxxApp/TSUtil.m
TaskPortHaxxApp_FRAMEWORKS = UIKit CoreGraphics CoreServices IOKit Security
TaskPortHaxxApp_LIBRARIES = archive
TaskPortHaxxApp_CFLAGS = -fobjc-arc -ITaskPortHaxxApp -IfastPathSign/src/external/include
TaskPortHaxxApp_LDFLAGS = fastPathSign/src/external/lib/libchoma.a fastPathSign/src/external/lib/libcrypto.a
TaskPortHaxxApp_CODESIGN_FLAGS = -S./TaskPortHaxxApp/TaskPortHaxxApp.ent

include $(THEOS_MAKE_PATH)/application.mk

after-stage::
	$(ECHO_NOTHING)cp TaskPortHaxxApp/launchd_ent.plist $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/launchd_ent.plist$(ECHO_END)
	$(ECHO_NOTHING)cp TaskPortHaxxApp/ldid $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/ldid$(ECHO_END)
	$(ECHO_NOTHING)chmod +x $(THEOS_STAGING_DIR)/Applications/TaskPortHaxxApp.app/ldid$(ECHO_END)

#SUBPROJECTS += opainject
#include $(THEOS_MAKE_PATH)/aggregate.mk
