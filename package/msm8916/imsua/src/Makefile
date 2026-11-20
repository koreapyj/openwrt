# SPDX-License-Identifier: GPL-2.0-only
CC ?= cc
CFLAGS ?= -O2
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -std=gnu11
SRCS = util.c sip.c dialog.c aka.c ipsec.c rtp.c
OBJS = $(SRCS:.c=.o)

all: imsua

imsua: $(OBJS) aka_ubus.o imsua.o
	$(CC) $(LDFLAGS) -o $@ $^ -lubus -lubox

# host unit tests (no libubus needed)
test: test/test_imsua
	./test/test_imsua

test/test_imsua: test/test_imsua.c $(SRCS) $(wildcard *.h)
	$(HOSTCC) -g -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE -std=gnu11 -DIMSUA_NO_UBUS -I. -o $@ test/test_imsua.c $(SRCS)

HOSTCC ?= cc

clean:
	rm -f imsua *.o test/test_imsua
