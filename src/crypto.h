#ifndef CRYPTO_H
#define CRYPTO_H

#define BLOCKSIZE 1024
int do_crypt(FILE *input, FILE *out, int action, char *key);
void encrypt(char *encrypted_path, const char *path);
void decrypt(char *path, char *encrypted_path);

#endif
