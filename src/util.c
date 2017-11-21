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
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, key, strlen(key));
	SHA256_Final(hash, &sha256);

	int i,j;
	char array[3], temp[50];
	for(i = 0 ; i < SHA_DIGEST_LENGTH; i++){
		sprintf(array, "%02x", (int)hash[i]);
		strcat(temp, array);
	}
	for(i = strlen(temp)-1,j=0; j < 40; j++,i--)
		out[40-j-1] = temp[i];
	out[40] = '\0';
}

void calculate_fullpath(char *fpath, char *root, char *path) 
{
	strcpy(fpath, root);
	strcat(fpath, "/");
	strcat(fpath, path);
}

void helper() 
{
	char buff[100];
	FILE* fp = fopen("helper.txt","r");

	while(fgets(buff, sizeof(buff), fp) != 0){
		printf("%s",buff);
	}
	fclose(fp);
}


// action 1-encrypt, 0-decrypt
void encrypt_filesystem(char *root, char *path, char *key, int action) 
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
			encrypt_filesystem(fpath, dname, key, action);
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
			do_crypt(fp, memstream, action, key);
			fclose(fp);

			fp = fopen(filepath, "wb");
			fseek(memstream, 0, SEEK_SET);
			do_crypt(memstream, fp, -1, key);
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

void change_password(en_state *en_data) 
{
	FILE *fp;
	char oldkey[256], key1[256], key2[256], old_key[40], new_key[40], fpath[PATH_MAX];
	char is_encrypted[10], key[256];
	strcpy(fpath, en_data->rootdir);
	strcat(fpath, "/.config");

	printf("Please enter old password : ");
	scanf("%s", oldkey);
	calculate_SHA1(oldkey, old_key);

	fp = fopen(fpath, "r");
	fscanf(fp, "%s", key);
	fscanf(fp, "%s", is_encrypted);
	fclose(fp);	

	if( strcmp(key, old_key) ){
		printf("Password not matched!");
		abort();
	}

	printf("Please enter new password : ");
	scanf("%s", key1);
	printf("Please enter confirm password : ");
	scanf("%s", key2);

	if( strcmp(key1, key2) ){
		printf("Password not matched!");
		abort();
	}

	calculate_SHA1(key1, new_key);
	if( !strcmp(is_encrypted, "1") ){
		encrypt_filesystem(en_data->rootdir, NULL, old_key, 0);
		encrypt_filesystem(en_data->rootdir, NULL, new_key, 1);
		strcpy(en_data->key, new_key);
	}
	fp = fopen(fpath, "w");
	fprintf(fp, "%s", new_key);
	fprintf(fp, "\n%s", is_encrypted);
	fclose(fp);
}

void check_authentication(en_state *en_data) 
{
	FILE *fp;
	int first_time = 0;
	char fpath[PATH_MAX], passkey[256], key[256], key2[256];
	strcpy(fpath, en_data->rootdir);
	strcat(fpath, "/.config");

	printf("Please enter password for authentication: ");
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
		fprintf(fp, "\n%s", "1");
		first_time = 1;
		fclose(fp);
	}
	en_data->key = malloc(strlen(output_of_key_sha)+1);
	strcpy(en_data->key, output_of_key_sha);
	if( first_time )
		encrypt_filesystem(en_data->rootdir, NULL, en_data->key, 1);
}
