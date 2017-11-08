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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

typedef struct {
	char *rootdir;
	char *key;
	char keys[32];
} en_state;


char* buf_crypt(const char* inbuf, int inlen, int* outlen, int action, char* key_str){
    	int tmplen;
    	unsigned char* tmpbuf = (unsigned char*) malloc(inlen + EVP_MAX_BLOCK_LENGTH);
   	char* outbuf = (char*) malloc(inlen + EVP_MAX_BLOCK_LENGTH);

    	/* OpenSSL libcrypto vars */
    	EVP_CIPHER_CTX ctx;
    	unsigned char key[32];
    	unsigned char iv[32];
    	int nrounds = 5;
    
    	/* tmp vars */
    	int i;

   	/* Setup Encryption Key and Cipher Engine */
	if(!key_str){
	    /* Error */
	    fprintf(stderr, "Key_str must not be NULL\n");
	    return 0;
	}
	
	/* Build Key from String */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL,
			   (unsigned char*)key_str, strlen(key_str), nrounds, key, iv);
	if (i != 32) {
	    /* Error */
	    fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
	    return 0;
	}
	
	/* Init Engine */
	EVP_CIPHER_CTX_init(&ctx);
	//Action 1 = encrypt, 0 = decrypt
	EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv, action);   
	
	
	/* perform cipher transform on block */
    	if(!EVP_CipherUpdate(&ctx, tmpbuf, &tmplen, (const unsigned char*) inbuf, inlen)){
	    /* Error */
	    EVP_CIPHER_CTX_cleanup(&ctx);
	    return 0;
	}
	
	
	/* Write Block */
	memcpy(outbuf, tmpbuf, tmplen);
	*outlen = tmplen;

	/* Handle remaining cipher block + padding */
	if(!EVP_CipherFinal_ex(&ctx, tmpbuf, &tmplen)){
		/* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	/* Write remainign cipher block + padding*/
	memcpy(outbuf + *outlen, tmpbuf, tmplen);
	*outlen += tmplen;

	
	//EVP_CIPHER_CTX_cleanup(&ctx);
	
    	/* Success */
    	return outbuf;
}

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
	
	char fpath[PATH_MAX];
	fullpath(fpath, path);

	//int fd = open(fpath, O_RDONLY);
	//return read(fd, buffer, size);
	//en_state *state = (en_state *)(fuse_get_context()->private_data);
	//strcpy(fpath, state->rootdir);
	//strncat(fpath, path, PATH_MAX); 

	
	char etext[PATH_MAX];
	FILE *fp = fopen(fpath, "r");
	fscanf(fp, "%s", etext);
	fclose(fp);
	
	int len;

	char *dtext = buf_crypt(etext, strlen(etext), &len, 0, "abc");
	memcpy(buffer, dtext + offset, size);
	return strlen(buffer) - offset;

}

int en_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];
	fullpath(fpath, path);
	
	int len; 

	char *encrypted_text = buf_crypt(buffer, strlen(buffer), &len, 1, "abc");
	
	/* Write Encrypted text to File */

	FILE *fp = fopen(fpath, "w");
	fprintf(fp, "%s", encrypted_text);
	fclose(fp);

	return 1;
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
