TARGET  = libhooker
OUTDIR ?= bin

TARGET_OS_TV ?= 0
ifeq ($(TARGET_OS_TV), 1)
CC      = xcrun -sdk appletvos clang -arch $(ARCH)
else
CC      = xcrun -sdk iphoneos clang -arch arm64
endif

# it is injected into trust cache by code
# which only supports sha-256 signatures
LDID    = ldid2
CFLAGS  = -Wall

.PHONY: all clean

DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -DINJECT_CRITICALD_DEBUG
else
    CFLAGS += -O2
endif

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.c | $(OUTDIR)
	$(CC) -o $@ $^ $(CFLAGS)
	strip $@
	$(LDID) -SEnt.plist $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
