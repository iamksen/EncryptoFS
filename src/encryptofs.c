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
#include <openssl/evp.h>
#include "util.h"
#include "crypto.h"

void fullpath(char fpath[PATH_MAX], const char *path)
{
	en_state *state = (en_state *)(fuse_get_context()->private_data);
	strcpy(fpath, state->rootdir);
	char epath[200];
	encrypt(epath, path);
	strncat(fpath, epath, PATH_MAX);
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

	seekdir(dp, offset);
	while( (de = readdir(dp)) != NULL ){
		struct stat st;
		memset(&st, 0, sizeof(st));
		char dname[200];
		strcpy(dname, de->d_name);
		if(!strcmp(dname,"/") || !strcmp(dname,".") || !strcmp(dname,".."))
			strcpy(dname, de->d_name);
		else
			decrypt(dname, de->d_name);
		st.st_ino = de->d_ino;
		if( filler(buffer, dname, &st, telldir(dp)) )
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
	en_state *en_data = (en_state *)(fuse_get_context()->private_data);
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	FILE *f, *memstream;
	char *membuf;
	size_t memsize;

	f = fopen(fpath, "rb");
	memstream = open_memstream(&membuf, &memsize);
	if (f == NULL || memstream == NULL)
		return -errno;

	do_crypt(f, memstream, 0, en_data->key);
	fflush(memstream);
	fseek(memstream, offset, SEEK_SET);
	int result = fread(buffer, 1, size, memstream);
	fclose(memstream);

	if (result == -1)
		result = -errno;

	fclose(f);
	return result;
}

int en_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	en_state *en_data = (en_state *)(fuse_get_context()->private_data);
	FILE *fp, *memstream;
	char fpath[PATH_MAX];
	char *membuf;
	size_t memsize;

	fullpath(fpath, path);

	fp = fopen(fpath, "rb");
	memstream = open_memstream(&membuf, &memsize);

	if ( fp == NULL || memstream == NULL)
		return -errno;

	do_crypt(fp, memstream, 0 , en_data->key);
	fclose(fp);

	fseek(memstream, offset, SEEK_SET);
	int result = fwrite(buffer, 1, size, memstream);
	fflush(memstream);

	fp = fopen(fpath, "w");
	fseek(memstream, 0, SEEK_SET);
	do_crypt(memstream, fp, 1, en_data->key);
	fclose(memstream);
	fclose(fp);

	if (result == -1)
		return -errno;
	return result;
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

	int result = rename(fpathfrom, fpathto);
	if( result == -1)
		return -errno;
	return 0;
}

int en_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	FILE *fp;
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	fp = fopen(fpath, "wb");
	fclose(fp);
	return 0;
}

int en_open(const char *path, struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	int result = open(fpath, fi->flags);
	if( result == -1 )
		return -errno;
	close(result);
	return 0;
}

int en_truncate(const char *path, off_t size)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	int result = truncate(fpath, size);
	if( result == -1 )
		return -errno;
	return 0;
}

int en_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	(void)path;
	(void)isdatasync;
	(void)fi;
	return 0;
}

int en_release(const char *path, struct fuse_file_info *fi)
{
	(void)path;
	(void)fi;
	return 0;
}

struct fuse_operations en_operations = {
	.getattr  = en_getattr,
	.readdir  = en_readdir,
	.read     = en_read,
	.write    = en_write,
	.unlink   = en_unlink,
	.mkdir    = en_mkdir,
	.rmdir    = en_rmdir,
	.mknod    = en_mknod,
	.access   = en_access,
	.rename   = en_rename,
	.create   = en_create,
	.open     = en_open,
	.truncate = en_truncate,
	.release  = en_release,
	.fsync    = en_fsync,
};


int main(int argc, char *argv[])
{
	en_state *en_data;
	en_data = (en_state *)malloc(sizeof(en_state));
	if( en_data == NULL )
		abort();
	if( argc != 3 ){
		//.encryptofs <rootdir> <mountpoint or some option>
		//abort();
	}

	en_data->rootdir = realpath(argv[1], NULL);
	check_authentication(en_data);
	
	if( !strcmp(argv[2], "e") ){
		encrypt_filesystem(en_data->rootdir, NULL, en_data->key, 1);
	} else if (!strcmp(argv[2], "d")) {
		encrypt_filesystem(en_data->rootdir, NULL, en_data->key, 0);
	} else if (!strcmp(argv[2], "c")) {
		change_password(en_data);
	} else {
		argv[1] = argv[2];
		argv[2] = NULL;
		argc = 2;
		return fuse_main(argc, argv, &en_operations, en_data);
	}
	return 0;
}
