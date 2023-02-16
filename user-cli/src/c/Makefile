CRYPT_FLAGS=-lssl -lcrypto

DM_FLAGS=-ldevmapper 

all: jindisksetup

jindisksetup: *.c
	$(CC) $^ $(DM_FLAGS) $(CRYPT_FLAGS) -o $@

install: jindisksetup
	sudo cp ./jindisksetup /sbin/

clean:
	rm -f *.o jindisksetup

