ROOTDIR = rootdir
MOUNTPOINT = mountpoint
EXE = encryptofs
PASSWORD = abc

all: encryptofs.o util.o
	gcc -o $(EXE) encryptofs.o util.o `pkg-config fuse --cflags --libs`

encryptofs.o: src/encryptofs.c
	gcc -c src/encryptofs.c `pkg-config fuse --cflags --libs`

util.o: src/util.c src/util.h
	gcc -c src/util.c
mount:
	./$(EXE) $(ROOTDIR) $(MOUNTPOINT)

unmount:
	fusermount -u $(MOUNTPOINT)

clean:
	rm *.o $(EXE)
