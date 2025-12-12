# Makefile for xpcproxyhook.dylib
# Roothide xpcproxy hook

CC = xcrun -sdk iphoneos clang
LDID = ldid

TARGET = xpcproxyhook.dylib

CFLAGS = -arch arm64 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) \
         -miphoneos-version-min=15.0 \
         -fmodules -fobjc-arc \
         -Wall -Wextra

LDFLAGS = -dynamiclib \
          -framework Foundation

SRCS = xpcproxyhook.m fishhook.c
OBJS = $(SRCS:.m=.o)
OBJS := $(OBJS:.c=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

sign: $(TARGET)
	$(LDID) -S $<

clean:
	rm -f $(TARGET) *.o

.PHONY: all sign clean

