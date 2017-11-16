#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util.h"

#define PATH_MAX 1024

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
		printf("Please re-enter password : ");
		scanf("%s", key2);
		if( strcmp(key, key2) ){
			printf("Password not matched!\n");
			abort();
		}
		fp = fopen(fpath, "w");
		fprintf(fp, "%s", key);
	}
	en_data->key = malloc(strlen(key)+1);
	strcpy(en_data->key, key);
}
