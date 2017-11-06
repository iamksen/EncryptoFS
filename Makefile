ROOTDIR = rootdir
MOUNTPOINT = mountpoint
EXE = encryptofs
PASSWORD = abc

all: encryptofs.o
	gcc -o $(EXE) encryptofs.o `pkg-config fuse --cflags --libs`

encryptofs.o: src/encryptofs.c
	gcc -c src/encryptofs.c `pkg-config fuse --cflags --libs`
	
mount:
	./$(EXE) $(PASSWORD) $(ROOTDIR) $(MOUNTPOINT)

unmount:
	fusermount -u $(MOUNTPOINT)

clean:
	rm *.o
