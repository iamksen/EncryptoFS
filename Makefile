ROOTDIR = rootdir
MOUNTPOINT = mountpoint
EXE = encryptofs
PASSWORD = abc

all: encryptofs.o util.o
	gcc -o $(EXE) encryptofs.o util.o `pkg-config fuse --cflags --libs` -lcrypto

encryptofs.o: src/encryptofs.c
	gcc -c src/encryptofs.c `pkg-config fuse --cflags --libs` `pkg-config --libs fuse openssl` -lcrypto

util.o: src/util.c src/util.h
	gcc -c src/util.c
mount:
	./$(EXE) $(ROOTDIR) $(MOUNTPOINT)

unmount:
	fusermount -u $(MOUNTPOINT)

clean:
	rm *.o $(EXE)
