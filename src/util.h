#ifndef UTIL_H
#define UTIL_H

typedef struct {
	char *rootdir;
	char *key;
} en_state;

void check_authentication(en_state *);
void first_time_encryption(char *, char *);
void encrypt_filesystem(char *root, char *path, char *key, int);
void change_password(en_state *);
void helper();

#endif
