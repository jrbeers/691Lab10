// SimpleCrackMe.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <wincrypt.h>
#include <time.h>

#include <stdio.h>

#define DEBUGLINE fprintf(stderr, "DBG: %d\n", __LINE__)

BOOL doCheck(char user[], unsigned char* key);

#define JUNK_CODE_ONE        \
    __asm{push eax}            \
    __asm{xor eax, eax}        \
    __asm{setpo al}            \
    __asm{push edx}            \
    __asm{xor edx, eax}        \
    __asm{sal edx, 2}        \
    __asm{xchg eax, edx}    \
    __asm{pop edx}            \
    __asm{or eax, ecx}        \
    __asm{pop eax}

inline int AddSubOne(int One, int Two)
{
	JUNK_CODE_ONE
		return ((One + Two) - 1);
}
BOOL doCheckConvert(char user[], char keychars[]) {

	//DEBUGLINE;

	if (strlen(keychars) != 32) {
		return FALSE;
	}

	//DEBUGLINE;

	unsigned char key[16];

	char temp[3] = { 0 };
	char* check;
	for (int i = 0; i < 16; i++) {
		memcpy(temp, &keychars[2 * i], 2);
		key[i] = strtol(temp, &check, 16);
#ifdef _DEBUG
		fprintf(stderr, "key[%d] = %02hhx\n", i, key[i]);
#endif
		if (check != &temp[2]) {
			return FALSE;
		}
	}

	//DEBUGLINE;
	return doCheck(user, key);
}

BOOL doCheck(char user[], unsigned char* key) {
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BOOL bResult = FALSE;

	bResult = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (!bResult) {
		return FALSE;
	}

	//DEBUGLINE;

	bResult = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
	if (!bResult) {
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	//DEBUGLINE;

	bResult = CryptHashData(hHash, (const BYTE*)user, strlen(user), 0);
	if (!bResult) {
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return FALSE;
	}

	//DEBUGLINE;

	BYTE sha1Data[20] = { 0 };
	DWORD cbHash = sizeof(sha1Data);
	bResult = CryptGetHashParam(hHash, HP_HASHVAL, sha1Data, &cbHash, 0);
	if (!bResult) {
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return FALSE;
	}

	//DEBUGLINE;

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);

	//DEBUGLINE;

#if 0
	printf("SHA1(user) = ");
	for (int i = 0; i < cbHash; i++) {
		printf("%02hhx", sha1Data[i]);
	}
	printf("\n");
#endif

	WORD checkSHA1 = 0;

	for (int i = 0; i < cbHash; i++) {
		checkSHA1 *= 31;
		checkSHA1 += sha1Data[i];
	}

	WORD checkKey = 0;
	for (int i = 0; i < 16; i++) {
		checkKey *= 127;
		checkKey += key[i];
	}

#ifdef _DEBUG
	printf("checkSHA1 = %04x, checkKey = %04x\n", checkSHA1, checkKey);
#endif

	return checkSHA1 == checkKey;
}

int main(int argc, char* argv[])
{
/**
If program is compiled in debug mode, run this section

This segment generates a random key

**/

#ifdef _DEBUG
	//goto DEHBUGGEH;
	//DEHBUGGEH:
	if (argc == 2) {
		unsigned char key[16];
		srand(time(NULL));
		for (int i = 0; i < 16; i++) {
			key[i] = rand();
		}
		//LOOP_DA_WOOP:
		while (1) {
			printf("Key: ");
			for (int i = 0; i < 16; i++) {
				printf("%02hhx", key[i]);
			}
			printf(": ");
			if (doCheck(argv[1], key)) {
				break;
			}
			for (int i = 15; i >= 0; i--) {
				key[i]++;
				if (key[i] != 0) break;
			}
			/*for (int i = 0; i < 16; i++) {
				key[i] = rand();
			}*/
		}
		printf("Found key: ");
		for (int i = 0; i < 16; i++) {
			printf("%02hhx", key[i]);
		}
		printf("\n");
		goto LAME_EXIT;
	}
#endif
	goto ARG_CHECK;
	DO_MATHS:
	if (doCheckConvert(argv[1], argv[2])) {
		printf("You're winner!\n");
	}
	else {
		printf("You lose");
	}
	goto LAME_EXIT;
	ARG_CHECK:
	if (argc != 3) {
		fprintf(stderr, "Please provide a username and key");
		exit(-1);
	}
	goto DO_MATHS;

	LAME_EXIT:
	getc(stdin);
}

