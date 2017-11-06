#define FUSE_USE_VERSION 30
#define PATH_MAX 1024

#include <fuse.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

typedef struct {
	char *rootdir;
	char *key;
	char keys[32];
} en_state;

void fullpath(char fpath[PATH_MAX], const char *path)
{
	en_state *state = (en_state *)(fuse_get_context()->private_data);
	strcpy(fpath, state->rootdir);
	strncat(fpath, path, PATH_MAX);
}

int en_getattr(const char *path, struct stat *stbuf)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	int result = lstat(fpath, stbuf);
	
	if( result == -1)
		return -errno;
	return 0;
}

int en_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	dp = opendir(fpath);
	if( dp == NULL )
		return -errno;

	while( (de = readdir(dp)) != NULL ){
		struct stat st;
		st.st_ino = de->d_ino;
		if( filler(buffer, de->d_name, &st, 0) )
			break;
	}
	
	closedir(dp);
	return 0;
}

int en_mknod(const char *path, mode_t mode, dev_t dev)
{
	int result;
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	if( S_ISREG(mode) ){
		result = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if( result >= 0 )
			result = close(result);
	} else if ( S_ISFIFO(mode) )
		result = mkfifo(path, mode);
	else
		result = mknod(path, mode, dev);
	
	if( result == -1 )
		return -errno;
	return 0;
}

int en_mkdir(const char *path, mode_t mode)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	int result = mkdir(fpath, mode);

	if( result == -1 )
		return -errno;
	return 0;
}

int en_rmdir(const char *path)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	int result = rmdir(fpath);
	if( result == -1)
		return -errno;
	return 0;
}

int en_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	int fd = open(fpath, O_RDONLY);
	return read(fd, buffer, size);
}

int en_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	return pwrite(fi->fh, buffer, size, offset);
}

int en_unlink(const char *path)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	
	int result = unlink(fpath);
	
	if( result == -1 )
		return -errno;
	
	return 0;
}

int en_access(const char *path, int mask)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	int result = access(fpath, mask);
	if( result == -1 )
		return -errno;
	return 0;
}

int en_rename(const char *from , const char *to)
{
	char fpathfrom[PATH_MAX], fpathto[PATH_MAX];
	fullpath(fpathfrom, from);
	fullpath(fpathto, to);

	int result = rename(from, to);
	if( result == -1)
		return -errno;
	return 0;
}

struct fuse_operations en_operations = {
	.getattr = en_getattr,
	.readdir = en_readdir,
	.read    = en_read,
	.write   = en_write,
	.unlink  = en_unlink,
	.mkdir   = en_mkdir,
	.rmdir   = en_rmdir,
	.mknod   = en_mknod,
	.access  = en_access,
	.rename  = en_rename,
};


int main(int argc, char *argv[])
{
	en_state *en_data;
	en_data = (en_state *)malloc(sizeof(en_state));
	if( en_data == NULL )
		abort();
	
	en_data->key     = argv[argc-3];
	en_data->rootdir = realpath(argv[argc-2], NULL);
	argv[argc-3] = argv[argc-1];
	
	argv[argc-1] = NULL;
	argv[argc-2] = NULL;
	argc = argc-2;
	
	printf("Rootdir %s\n", en_data->rootdir);
	
	return fuse_main(argc, argv, &en_operations, en_data);
}
