ROOTDIR = rootdir
MOUNTPOINT = mountpoint
EXE = encryptofs
PASSWORD = abc
FUSEFLAGS = `pkg-config fuse --cflags --libs`
OPENSSLFLAGS = `pkg-config --libs fuse openssl` -lcrypto

all: encryptofs.o util.o crypto.o
	gcc -o $(EXE) encryptofs.o util.o crypto.o $(FUSEFLAGS) $(OPENSSLFLAGS)

encryptofs.o: src/encryptofs.c
	gcc -c src/encryptofs.c $(FUSEFLAGS) $(OPENSSLFLAGS)

util.o: src/util.c src/util.h
	gcc -c src/util.c $(OPENSSLFLAGS)

crypto.o: src/crypto.c src/crypto.h
	gcc -c src/crypto.c $(OPENSSLFLAGS)

mount:
	./$(EXE) $(ROOTDIR) $(MOUNTPOINT)

unmount:
	fusermount -u $(MOUNTPOINT)

install:
	sudo cp $(EXE) /usr/bin

clean:
	rm *.o $(EXE)
