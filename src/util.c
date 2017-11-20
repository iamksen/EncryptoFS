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

void first_time_encryption(char *root, char *path)
{

	char fpath[PATH_MAX];
	strcpy(fpath, root);
	if(path != NULL){
		strcat(fpath, "/");
		strcat(fpath, path);
	}

	DIR *dp;
	struct dirent *de;


	dp = opendir(fpath);
	while( (de = readdir(dp)) != NULL ){
		char dname[200];

		if( !strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") || !strcmp(de->d_name, "/") || !strcmp(de->d_name, ".config"))
			continue;
		if( de->d_type == DT_DIR)
			first_time_encryption(fpath, de->d_name);

		encrypt(dname, de->d_name);
		char from[PATH_MAX], to[PATH_MAX];
		calculate_fullpath(from, fpath, de->d_name);
		calculate_fullpath(to, fpath, dname);
		rename(from, to);
	}
	closedir(dp);
}

void check_config_file(en_state *en_data)
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
		first_time_encryption(en_data->rootdir, NULL);
}