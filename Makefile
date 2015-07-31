CFLAGS  = -std=gnu99 -fPIC -O0 -ggdb3 -Wall -Wextra -fvisibility=hidden
CPPFLAGS= -Iinclude -Isd-include -I/usr/include/systemd
UNAME   = $(shell uname -s)
PREFIX	= /usr/local

ifeq ($(UNAME), Linux)
	LDLIBS += -ldl
endif

.PHONY: clean install

all: log.so

log.so: log.o
	$(CC) $(LDFLAGS) $(CFLAGS) -shared -o $@ $^ 

clean:
	rm -f log.so *.o

install: log.so
	#install .sh $(PREFIX)/bin
	install log.so $(PREFIX)/lib
