#ifndef _SU_ENCRYPTOR_H_
#define _SU_ENCRYPTOR_H_
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
namespace {
static void rand_str(char* dest, int n) {
	int i, randno;
	char stardstring[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned)time(NULL));
	for (i = 0; i < n; i++) {
		randno = rand() % 62;
		*dest = stardstring[randno];
		dest++;
	}
}
}
#endif /* _SU_ENCRYPTOR_H_ */
