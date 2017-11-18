#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include "util.h"

void check_config_file(en_state *en_data)
{
	FILE *fp;
	char fpath[PATH_MAX], passkey[256], key[256], key2[256];
	strcpy(fpath, en_data->rootdir);
	strcat(fpath, "/.config");

	printf("Please enter password : ");
	scanf("%s", key);
	if( access(fpath, F_OK) != -1 ){
		fp = fopen(fpath, "r");
		fscanf(fp, "%s", passkey);
		if( strcmp(key, passkey) ){
			printf("Password not matched!\n");
			abort();
		}
	} else {
		printf("Please enter confirm password : ");
		scanf("%s", key2);
		if( strcmp(key, key2) ){
			printf("Password not matched!\n");
			abort();
		}
		fp = fopen(fpath, "w");
		fprintf(fp, "%s", key);
		first_time_encryption(en_data->rootdir, NULL);
	}
	en_data->key = malloc(strlen(key)+1);
	strcpy(en_data->key, key);
}

void cal_fpath(char *fpath, char *root, char *path)
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
		cal_fpath(from, fpath, de->d_name);
		cal_fpath(to, fpath, dname);
		rename(from, to);
	}
	closedir(dp);
}
