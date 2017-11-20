#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/sha.h>
#include "crypto.h"
#include "util.h"

void calculate_SHA1(char key[], char out[])
{
	size_t length = strlen(key);
	unsigned char hash[32];
	SHA1(key, length, hash);
	char array[35];
	int i;
	for( i = 0; i < SHA_DIGEST_LENGTH; i++ ){
		sprintf(array ,"%02x" , hash[i]);
		strcat(out,array);
	}
}

void calculate_fullpath(char *fpath, char *root, char *path)
{
	strcpy(fpath, root);
	strcat(fpath, "/");
	strcat(fpath, path);
}

// action 1-encrypt, 0-decrypt
void encrypt_filesystem(char *root, char *path, en_state *en_data, int action)
{
	char fpath[PATH_MAX];
	strcpy(fpath, root);
	if( path != NULL ){
		strcat(fpath, "/");
		strcat(fpath, path);
	}
	DIR *dp;
	struct dirent *entry;
	dp = opendir(fpath);
	while( (entry = readdir(dp)) != NULL ){
		char dname[256], encrypted_name[256];
		strcpy(dname, entry->d_name);
		if( !strcmp(dname, ".") || !strcmp(dname, "..") || !strcmp(dname, "/") || !strcmp(dname, ".config"))
			continue;
		if( entry->d_type == DT_DIR)
			encrypt_filesystem(fpath, dname, en_data, action);
			char filepath[PATH_MAX];
			strcpy(filepath, fpath);
			strcat(filepath, "/");
			strcat(filepath, dname);
		if( entry->d_type == DT_REG){	
			char *membuf;
			size_t memsize;
			FILE *fp, *memstream;
			
			fp = fopen(filepath, "rb");
			memstream = open_memstream(&membuf, &memsize);
			do_crypt(fp, memstream, action, en_data->key);
			fclose(fp);
			
			fp = fopen(filepath, "wb");
			fseek(memstream, 0, SEEK_SET);
			do_crypt(memstream, fp, -1, en_data->key);
			fclose(fp);
			fclose(memstream);
		}

		if( action == 1)
			encrypt(encrypted_name, dname);
		else
			decrypt(encrypted_name, dname);

		char from[PATH_MAX], to[PATH_MAX];
		calculate_fullpath(from, fpath, dname);
		calculate_fullpath(to, fpath, encrypted_name);
		rename(from, to);
	}
	closedir(dp);
}

void check_authentication(en_state *en_data)
{
	FILE *fp;
	int first_time = 0;
	char fpath[PATH_MAX], passkey[256], key[256], key2[256];
	strcpy(fpath, en_data->rootdir);
	strcat(fpath, "/.config");

	printf("Please enter password : ");
	scanf("%s", key);

	char output_of_key_sha[40];
	calculate_SHA1(key,output_of_key_sha);

	if( access(fpath, F_OK) != -1 ){
		fp = fopen(fpath, "r");
		fscanf(fp, "%s", passkey);
		if( strcmp(output_of_key_sha, passkey) ){
			printf("Password not matched!\n");
			abort();
		}
	} else {
		printf("Please confirm the password : ");
		scanf("%s", key2);

		char output_of_key2_sha[40];
		calculate_SHA1(key2,output_of_key2_sha);

		if( strcmp(output_of_key_sha, output_of_key2_sha) ){
			printf("Password not matched!\n");
			abort();
		}
		fp = fopen(fpath, "w");
		fprintf(fp, "%s", output_of_key2_sha);
		first_time = 1;
		fclose(fp);
	}
	en_data->key = malloc(strlen(output_of_key_sha)+1);
	strcpy(en_data->key, output_of_key_sha);
	if( first_time )
		encrypt_filesystem(en_data->rootdir, NULL, en_data, 1);
}
