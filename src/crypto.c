#include <string.h>
#include <openssl/evp.h>
#include "crypto.h"

int do_crypt(FILE* in, FILE* out, int action, char* key_str){

	unsigned char inbuf[BLOCKSIZE], outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen, writelen;

	EVP_CIPHER_CTX ctx;
	unsigned char key[32], iv[32];
	int i, nrounds = 5;

	/* Setup Encryption Key and Cipher Engine if in cipher mode */
	if(action >= 0){
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
		EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv, action);
	}    
	
	while(1){
		inlen = fread(inbuf, sizeof(*inbuf), BLOCKSIZE, in);
		if(inlen <= 0)
			break;

		if(action >= 0){
			if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)){
				/* Error */
				EVP_CIPHER_CTX_cleanup(&ctx);
				return 0;
			}
		} else {
			memcpy(outbuf, inbuf, inlen);
			outlen = inlen;
		}

		writelen = fwrite(outbuf, sizeof(*outbuf), outlen, out);
		if(writelen != outlen){
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
	}

	/* If in cipher mode, handle necessary padding */
	if(action >= 0){
		/* Handle remaining cipher block + padding */
		if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
		{
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		/* Write remainign cipher block + padding*/
		fwrite(outbuf, sizeof(*inbuf), outlen, out);
		EVP_CIPHER_CTX_cleanup(&ctx);
	} 
	return 1;
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
