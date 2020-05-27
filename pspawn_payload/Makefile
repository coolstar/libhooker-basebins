TARGET  = pspawn_payload.dylib
OUTDIR ?= bin

TARGET_OS_TV ?= 0
ifeq ($(TARGET_OS_TV), 1)
CC      = xcrun -sdk appletvos cc -arch arm64
else
CC      = xcrun -sdk iphoneos cc -arch arm64 -arch arm64e
endif

# it is injected into trust cache by code
# which only supports sha-256 signatures
LDID    = ldid2
CFLAGS  = -Wall -I./apple_include

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DPSPAWN_PAYLOAD_DEBUG
else
    CFLAGS += -O2
endif

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): pspawn_payload.c fishhook.c | $(OUTDIR)
	$(CC) -dynamiclib -o $@ $^ $(CFLAGS)
	strip -x $@
	$(LDID) -S $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
