Setup_Lib_Path=../c/backendlib

all: libdm_jindisk.so
	cargo build

libdm_jindisk.so:
	make -C $(Setup_Lib_Path)
	sudo cp $(Setup_Lib_Path)/libdm_jindisk.h /usr/include/
	sudo cp $@ /usr/lib/x86_64-linux-gnu/

install: libdm_jindisk.so target/debug/jindisksetup-rust
	sudo cp target/debug/jindisksetup-rust /usr/bin/
	sudo cp ./libdm_jindisk.so /usr/lib/x86_64-linux-gnu/

clean:
	cargo clean
	make -C $(Setup_Lib_Path) clean
	rm -f *.o libdm_jindisk.so main
	# Be careful with the following commands!
	# sudo rm -f /usr/lib/x86_64-linux-gnu/libdm_jindisk.so
	# sudo rm -f /usr/include/libdm_jindisk.h
	# sudo rm -f /usr/bin/jindisksetup-rust