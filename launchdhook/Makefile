# Makefile for launchdhook.dylib
# Roothide launchd hook

CC = xcrun -sdk iphoneos clang
LDID = ldid
CODESIGN = codesign

TARGET = launchdhook.dylib

CFLAGS = -arch arm64 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
         -miphoneos-version-min=15.0 \
         -fmodules -fobjc-arc \
         -Wall -Wextra

LDFLAGS = -dynamiclib \
          -framework Foundation \
          -framework IOKit

SRCS = main.m fishhook.c
OBJS = $(SRCS:.m=.o)
OBJS := $(OBJS:.c=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

sign: $(TARGET)
	$(LDID) -S $<

ct_bypass: $(TARGET)
	../fastPathSign/src/ct_bypass $(TARGET) $(TARGET)

clean:
	rm -f $(TARGET) *.o

.PHONY: all sign ct_bypass clean

