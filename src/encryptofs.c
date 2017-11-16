#define FUSE_USE_VERSION 30
#define PATH_MAX 1024

#include <fuse.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

typedef struct {
	char *rootdir;
	char *key;
} en_state;


void encrypt(char *epath, const char *path)
{
	strcpy(epath, path);
	if(!strcmp(path,"/") || !strcmp(path,".") || !strcmp(path,".."))
		return;

	int i, j = 0;
	for(i = 0 ; i < strlen(path); i++){
		if( path[i] == '.' || path[i] == '/')
			epath[j++] = path[i];
		else
			epath[j++] = path[i] + 1;
	}
}

void decrypt(char *path, char *epath)
{
	strcpy(path, epath);
	if(!strcmp(path,"/") || !strcmp(path,".") || !strcmp(path,".."))
		return;

	int i, j = 0;
	for(i = 0 ; i < strlen(epath); i++){
		if( epath[i] == '.' || epath[i] == '/')
			path[j++] = epath[i];
		else
			path[j++] = epath[i]-1;
	}
}

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
	
	FILE *fp, *memstream;
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	fp = fopen(fpath, "rb");
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *temp = malloc(fsize + 1);
	fseek(fp, offset, SEEK_SET);
	int i, result = fread(temp, 1, size, fp);

	for(i = 0 ; i < size; i++)
		buffer[i] = temp[i]^(en_data->key[i%strlen(en_data->key)]);
	fclose(fp);

	if( result == -1 )
		return -errno; 
	return result; 
}

int en_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{

	en_state *en_data = (en_state *)(fuse_get_context()->private_data);
	FILE *fp;
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	
	fp = fopen(fpath, "wb");
	fseek(fp, offset, SEEK_SET);
	int i, len = strlen(buffer);
	char *temp = malloc(len+1);
	for(i = 0 ; i < len ; i++)
		temp[i] = buffer[i]^(en_data->key[i%strlen(en_data->key)]);

	int result = fwrite(temp, 1, len, fp);
	fclose(fp);
	free(temp);
	if( result == -1 )
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
	.create  = en_create,
	.open    = en_open,
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

	en_data->key     = argv[argc-3];
	en_data->rootdir = realpath(argv[argc-2], NULL);
	argv[argc-3] = argv[argc-1];

	argv[argc-1] = NULL;
	argv[argc-2] = NULL;
	argc = argc-2;

	return fuse_main(argc, argv, &en_operations, en_data);
}
