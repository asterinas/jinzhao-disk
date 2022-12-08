CFLAGS=-ldevmapper
LDFLAGS=-shared

src = $(wildcard *.c)
objs = $(patsubst %.c,%.o, $(src))

all: libdm
	cp libdm_jindisk.so ../
	cp libdm_jindisk.so ../../rust/

libdm: libdm_jindisk.so

libdm_jindisk.so: $(objs)
	$(CC) $^ $(LDFLAGS) $(CFLAGS) -o $@

%.o: %.c
	$(CC) -c $^ $(CFLAGS) -o $@


clean:
	rm -f *.o libdm_jindisk.so
	rm -f ../libdm_jindisk.so

