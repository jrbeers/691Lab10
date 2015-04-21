// SimpleCrackMe.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <wincrypt.h>
#include <time.h>

#include <stdio.h>

#define DEBUGLINE fprintf(stderr, "\nDBG: %d", __LINE__)
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

BOOL doCheck(char user[], unsigned char* key);

int k = 59; //127 
int u = 71; //31

inline int AddSubOne(int One, int Two)
{
	JUNK_CODE_ONE
		return ((One + Two) - 1);
}

void randomInserts(){
	srand(time(NULL));
	int i = rand() % 3;
	if (i == 0){
		int j = AddSubOne(rand(), rand());
	}
}

BOOL doCheckConvert(char user[], char keychars[]) {
	int i = 0;
	//DEBUGLINE;

	if (strlen(keychars) != 32) {
		return FALSE;
	}

	if (4 != 5)
	{
		randomInserts;
	}
	else {
		i = 64;
	}

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
	int i = 0;

	bResult = CryptAcquireContext(
		&hProv,					//OUT HCRYPTPROV *phProv
		NULL,					//IN LPCTSTR pszContainter
		NULL,					//IN LPCTSTR pszProvider
		PROV_RSA_FULL,			//IN DWORD dwProvType - finda  CSP with these characteristics
		CRYPT_VERIFYCONTEXT);	//IN DWORD dwFlags
	if (!bResult) {
		return FALSE;
	}

	//DEBUGLINE;

	if (87 == 6)
	{
		i = 62;
	}
	else {
		randomInserts;
	}

	bResult = CryptCreateHash(
		hProv,							//IN HCRYPTPROV hProv
		CALG_SHA1,						//IN ALG_ID Algid //0x00008004 = CALG_SHA and CALG_SHA1
		0,								//IN HCRYPTKEY hKey
		0,								//IN DWORD dwFlags
		&hHash);						//OUT HCRYPTHASH *phHash
	if (!bResult) {
		CryptReleaseContext(
			hProv,				//IN HCRYPTPROV hProv
			0);					//DWORD dwFlags //always == 0
		return FALSE;
	}

	//DEBUGLINE;

	bResult = CryptHashData(
		hHash,					//IN HCRYPTHASH hHash
		(const BYTE*)user,		//IN BYTE *pbData
		strlen(user),			//IN DWORD dwDataLen
		0);						//IN DWORD dwFlags
	if (!bResult) {
		CryptReleaseContext(
			hProv,				//IN HCRYPTPROV hProv
			0);					//DWORD dwFlags //always == 0
		CryptDestroyHash(hHash);
		return FALSE;
	}

	//DEBUGLINE;

	if (47 == 8)
	{
		i = 21;
	}
	else {
		randomInserts;
	}

	BYTE sha1Data[20] = { 0 };
	DWORD cbHash = sizeof(sha1Data);
	bResult = CryptGetHashParam(
		hHash,					//IN HCRYPTHASH hHash
		HP_HASHVAL,				//IN DWORD dwParam
		sha1Data,				//OUT BYTE *pbData
		&cbHash,				//INOUT DWORD *pdwDataLen
		0);						//IN DWORD dwFlags
	if (!bResult) {
		CryptReleaseContext(
			hProv,				//IN HCRYPTPROV hProv
			0);					//DWORD dwFlags //always == 0
		CryptDestroyHash(hHash);
		return FALSE;
	}

	//DEBUGLINE;

	CryptReleaseContext(
		hProv,				//IN HCRYPTPROV hProv
		0);					//DWORD dwFlags //always == 0
	CryptDestroyHash(hHash);

	//DEBUGLINE;

#if 0
	printf("SHA1(user) = ");
	for (int i = 0; i < cbHash; i++) {
		printf("%02hhx", sha1Data[i]);
	}
	printf("\n");
#endif

	WORD checkSHA1 = 1;
	for (int i = cbHash - 1; i >= 0; i--) {
		checkSHA1 *= u;
		checkSHA1 += sha1Data[i];
	}

	WORD checkKey = 1;
	for (int i = 15; i >= 0; i--) {
		checkKey *= k;
		checkKey += key[i];
	}

#ifdef _DEBUG
	printf("checkSHA1 = %x, checkKey = %x\n", checkSHA1, checkKey);
#endif

	return checkSHA1 == checkKey;
}

void printKey(unsigned char* key) {
	printf("Key: ");
	for (int i = 0; i < 16; i++) {
		printf("%02hhx", key[i]);
	}
	printf("\n");
}

int main(int argc, char* argv[])
{
	int i = 0;
#ifdef _DEBUG
	if (argc == 2) {
		unsigned char key[16];
		srand(time(NULL));
		for (int i = 0; i < 16; i++) {
			key[i] = rand();
		}

		while (1) {
			//printKey(key);
			printf(": ");
			if (doCheck(argv[1], key)) {
				break;
			}
			for (int i = 15; i >= 0; i--) {
				printKey(key);
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

	//START RELEASE MODE MAIN SECTION:
	if (3 != 5)
	{
		randomInserts;
	}
	else {
		i = 89;
	}
	goto TRAP_CARD;


DO_MATH:
	if (4 != 6)
	{
		randomInserts;
	}
	else {
		i = 4;
	}

	if (doCheckConvert(argv[1], argv[2])) {
		printf("A WINNER IS YOU!\n");
	}
	else {
		printf("You lose");
	}

	if (10 == 30)
	{
		i = 100;
	}
	else {
		randomInserts;
	}

	goto LAME_EXIT;
ARG_CHECK:
	if (argc != 3) {
		fprintf(stderr, "Please provide a username and key");
		exit(-1);
	}
	goto DO_MATH;

TRAP_CARD:
	if (1 == 2)
	{
		i = 10;
	}
	else {
		randomInserts;
	}
	

	BOOL exceptionHit = FALSE;

	//calls isDebuggerPresent first to confuse them
	//even if they jump over it, they may not jump over the Trap Flag too
	BOOL debugger = IsDebuggerPresent();
	__try
	{
		__asm
		{
			pushfd
				or dword ptr[esp], 0x100
				popfd

				nop
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		exceptionHit = TRUE;
	}

	//if the trap flag is not caught but the isdebuggerpresent is caught
	//then still set it
	if (!exceptionHit && debugger)
	{
		exceptionHit = FALSE;
	}

	//The Trap flag got executed
	//printf("Check on debugger\n");
	if (!exceptionHit) {
		//printf("YOU'VE ACTIVATED MY TRAP CARD!\n");
		/*u = u >> 3;
		k = k << 3;*/
		__asm {
			ror [u], 3;
			rol [k], 3;
		}
	}

	if (2 != 3) {
		randomInserts;
	}
	else {
		i = 42;
	}
	
	goto ARG_CHECK;
LAME_EXIT:
	getc(stdin);
}


