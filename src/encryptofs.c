#define FUSE_USE_VERSION 30
#define PATH_MAX 1024
#define BLOCKSIZE 1024
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

void do_crypt(FILE *ifp, FILE *ofp, int should_encrypt, unsigned char *ckey) {
	unsigned char *ivec = "def";
	const unsigned BUFSIZE = 1;
	unsigned char *read_buf = malloc(BUFSIZE);
	unsigned char *cipher_buf;
	unsigned blocksize;
	int out_len;
	EVP_CIPHER_CTX ctx;

	EVP_CipherInit(&ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt);
	blocksize = EVP_CIPHER_CTX_block_size(&ctx);
	cipher_buf = malloc(BUFSIZE + blocksize);

	int calculate_size = 0;
	while (1) {

		// Read in data in blocks until EOF. Update the ciphering with each read.
		int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
		EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
		fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
		if (numRead < BUFSIZE) { // EOF
			break;
		}
	}

	// Now cipher the final block and write it out.
	EVP_CipherFinal(&ctx, cipher_buf, &out_len);
	fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

	free(cipher_buf);
	free(read_buf);
}


void encrypt(char *epath, const char *path)
{
	strcpy(epath, path);
	if(!strcmp(path,"/") || !strcmp(path,".") || !strcmp(path,".."))
		return;

	// hidden file
	if( strlen(path) >= 2 && path[0] == '/' && path[1] == '.' )
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

	// hidden file
	if( strlen(path) >= 2 && path[0] == '/' && path[1] == '.')
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
	char fpath[PATH_MAX], fpath2[PATH_MAX];
	fullpath(fpath, path);

	FILE *f, *fout, *memstream;
	int res;
	char *membuf;
	size_t memsize;

	(void) fi;
	f = fopen(fpath, "rb");
	memstream = open_memstream(&membuf, &memsize);
	if (f == NULL || memstream == NULL)
		return -errno;
	fout = fopen("tmp", "wb");

	do_crypt(f, fout, 0, en_data->key);

	fflush(fout);
	fseek(fout, offset, SEEK_SET);
	res = fread(buffer, 1, size, fout);
	fclose(fout);

	if (res == -1)
		res = -errno;

	fclose(f);
	return res;
}

int en_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{

	en_state *en_data = (en_state *)(fuse_get_context()->private_data);
	FILE *fp;
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	FILE *f, *memstream, *fout;
	int res;
	char *membuf;
	size_t memsize;

	(void) fi;
	f = fopen(fpath, "rb");
	fout = fopen("tt", "wb");

	memstream = open_memstream(&membuf, &memsize);

	if (memstream == NULL)
		return -errno;

	if(f != NULL){
		do_crypt(f, fout, 0 , en_data->key);
		fclose(f);
	}

	fseek(fout, offset, SEEK_SET);
	res = fwrite(buffer, 1, size, fout);
	fflush(fout);
	f = fopen(fpath, "w");


	fseek(fout, 0, SEEK_SET);
	do_crypt(fout, f, 1, en_data->key);
	fclose(fout);

	if (res == -1)
		res = -errno;

	fclose(f);
	return res;

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

	en_data->rootdir = realpath(argv[argc-2], NULL);
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc = argc-1;

	check_config_file(en_data);

	return fuse_main(argc, argv, &en_operations, en_data);
}
