prefix ?= /usr

INSTALL=install

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

CPPFLAGS ?=

override CPPFLAGS += \
	-D_GNU_SOURCE \
	-D__SANE_USERSPACE_TYPES__ \
	-I../src/include/ \
	-include ../config-host.h

CFLAGS ?= -g -O2 -Wall -Wextra
XCFLAGS = -Wno-unused-parameter -Wno-sign-compare

ifdef CONFIG_HAVE_STRINGOP_OVERFLOW
	XCFLAGS += -Wstringop-overflow=0
endif

ifdef CONFIG_HAVE_ARRAY_BOUNDS
	XCFLAGS += -Warray-bounds=0
endif

CXXFLAGS ?= $(CFLAGS)
override CFLAGS += $(XCFLAGS) -DLIBURING_BUILD_TEST
override CXXFLAGS += $(XCFLAGS) -std=c++11 -DLIBURING_BUILD_TEST

LDFLAGS ?=
override LDFLAGS += -L../src/ -luring -lpthread

# Please keep this list sorted alphabetically.
bench_srcs := \
	nop.c \
	poll.c \
	reg.c \
	tw.c \
	recvmsg.c \
	# EOL

all_targets :=
include ../Makefile.quiet

bench_targets := $(patsubst %.c,%,$(bench_srcs))
bench_targets := $(patsubst %.cc,%,$(bench_targets))
bench_targets := $(patsubst %,%.b,$(bench_targets))
all_targets += $(bench_targets)

helpers = helpers.o ../test/helpers.o

all: $(bench_targets)

../test/helpers.o: ../test/helpers.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

../src/syscall.o: ../src/syscall.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

helpers.o: helpers.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

%.b: %.c $(helpers) helpers.h ../src/liburing.a
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(helpers) $(LDFLAGS)

%.b: %.cc $(helpers) helpers.h ../src/liburing.a
	$(QUIET_CXX)$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< $(helpers) $(LDFLAGS)

clean:
	@rm -f $(all_targets) helpers.o

.PHONY: all clean
