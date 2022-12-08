BackendLib=./backendlib

CRYPT_FLAGS=-lssl -lcrypto

DM_FLAGS=-ldevmapper

INC=-I$(BackendLib)


all: jindisksetup

jindisksetup: jindisksetup.c libdm_jindisk.so
	$(CC) $^ $(INC) $(DM_FLAGS) $(CRYPT_FLAGS) -o $@

libdm_jindisk.so:
	make -C $(BackendLib)

install: libdm_jindisk.so jindisksetup
	sudo cp ./jindisksetup /usr/bin/
	sudo cp ./libdm_jindisk.so /usr/lib/x86_64-linux-gnu/

clean:
	make -C $(BackendLib) clean
	rm -f *.o libdm_jindisk.so jindisksetup

