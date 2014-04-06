#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>


#pragma comment(lib, "crypt32.lib")

#define snprintf _snprintf
#define MAX_BUF_SIZE 1024
#define VERSION "0.1"

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 



/*
 * Function forward declarations
 *
 */
void PrintHelp(char *pProgName);
void EncryptMyFile(char *pPassword, char *pFileName);
void DecryptMyFile(char *pPassword, char *pFileName);


/*
 * Program entry point
 *
 */
int main(int argc, char *argv[])
{
  int lRetVal = 0;
  char *lInputDataBuf = NULL;
  int lFileSize = 0;
  DWORD lReadCount = 0;
  HANDLE lReadFH = INVALID_HANDLE_VALUE;
  HANDLE lWriteFH = INVALID_HANDLE_VALUE;
  long lCryptedSize = 0;
  char lOutFile[MAX_BUF_SIZE + 1];

  if (argc == 4 && !strncmp(argv[1], "-e", 2))
    EncryptMyFile(argv[2], argv[3]);
  else if (argc == 4 && !strncmp(argv[1], "-d", 2))
    DecryptMyFile(argv[2], argv[3]);
  else
	PrintHelp(argv[0]);

  return(lRetVal);
}





/*
 *
 *
 */

void DecryptMyFile(char *pPassword, char *pFileName)
{
  HANDLE lReadFH = INVALID_HANDLE_VALUE;
  HANDLE lWriteFH = INVALID_HANDLE_VALUE;
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
  HCRYPTKEY hKey = NULL; 
  DWORD lBlockLen = 0;
  DWORD lBufferLen = 0;
  DWORD lReadCount = 0;
  BOOL fEOF = FALSE;
  BYTE *lDataBuf = NULL;

  int lFileSize = 0;
  DWORD lBytesRead = 0;
  DWORD lBytesWritten = 0;
  char lOutFile[MAX_BUF_SIZE + 1];

  /*
   * Open unencrypted input file
   */
  if ((lReadFH = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ,  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
  {
    ZeroMemory(lOutFile, sizeof(lOutFile));
    snprintf(lOutFile, sizeof(lOutFile)-1, "UnprotectedRC4_%s", pFileName);
    /*
     * Open encrypted output file
     */    
    if ((lWriteFH = CreateFile(lOutFile,  GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) 
    {
      if (CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	  {
        if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
		{
          if (CryptHashData(hHash, (BYTE *) pPassword, lstrlen(pPassword), 0)) 
		  {
            if (CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey))
            {             
              lBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 
              if(ENCRYPT_BLOCK_SIZE > 1)
                lBufferLen = lBlockLen + ENCRYPT_BLOCK_SIZE;
              else
                lBufferLen = lBlockLen;


              if ((lDataBuf = (BYTE *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lBufferLen)) != NULL)
			  {
                do
                {
                  if (!ReadFile(lReadFH, lDataBuf, lBlockLen, &lReadCount, NULL))
                    break;

                  if(lReadCount < lBlockLen)
                    fEOF = TRUE;

                  if (CryptDecrypt(hKey, 0, fEOF, 0, lDataBuf, &lReadCount))
				  {
                    WriteFile(lWriteFH, lDataBuf, lReadCount, &lReadCount, NULL);
				  } // if (CryptDecrypt...
				}
                while (!fEOF);

                HeapFree(GetProcessHeap(), 0, lDataBuf);
			  } // if ((lFileCont...
              CryptDestroyKey(hKey);
			} // if (CryptDeriveKey(hC...
		  } // if (CryptHashData(h....
          CryptDestroyHash(hHash);
		} // if (CryptCreateHas...
        CryptReleaseContext(hCryptProv, 0);
	  } // if (CryptAcquire...
      CloseHandle(lWriteFH);
    } // if ((lWrite...
    CloseHandle(lReadFH);
  } // if ((lReadFH = ...
}




/*
 *
 *
 */
void EncryptMyFile(char *pPassword, char *pFileName)
{
  HANDLE lReadFH = INVALID_HANDLE_VALUE;
  HANDLE lWriteFH = INVALID_HANDLE_VALUE;
  HCRYPTPROV hCryptProv;
  HCRYPTHASH hHash;
  HCRYPTKEY hKey = NULL; 
  DWORD dwBlockLen = 0;
  DWORD dwBufferLen = 0;
  DWORD lReadCount = 0;
  BOOL fEOF = FALSE;
  BYTE *lDataBuf = NULL;

  int lFileSize = 0;
  DWORD lBytesRead = 0;
  DWORD lBytesWritten = 0;
  char lOutFile[MAX_BUF_SIZE + 1];

  /*
   * Open unencrypted input file
   */
  if ((lReadFH = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ,  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
  {
    ZeroMemory(lOutFile, sizeof(lOutFile));
    snprintf(lOutFile, sizeof(lOutFile)-1, "ProtectedRC4_%s", pFileName);
    /*
     * Open encrypted output file
     */    
    if ((lWriteFH = CreateFile(lOutFile,  GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) 
    {
      if (CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	  {
        if (CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash))
		{
          if (CryptHashData(hHash, (BYTE *) pPassword, lstrlen(pPassword), 0)) 
		  {
            if (CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey))
            {             
              dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE; 
              if(ENCRYPT_BLOCK_SIZE > 1)
                dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
              else
                dwBufferLen = dwBlockLen;


              if ((lDataBuf = (BYTE *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferLen)) != NULL)
			  {
                do
                {
                  if (!ReadFile(lReadFH, lDataBuf, dwBlockLen, &lReadCount, NULL))
                    break;

                  if(lReadCount < dwBlockLen)
                    fEOF = TRUE;

                  if (CryptDecrypt(hKey, 0, fEOF,  0, lDataBuf, &lReadCount))
				  {
                    WriteFile(lWriteFH, lDataBuf, lReadCount, &lReadCount, NULL);				  
				  } // if (CryptDecrypt...
				}
                while (!fEOF);

                HeapFree(GetProcessHeap(), 0, lDataBuf);
			  } // if ((lFileCont...
              CryptDestroyKey(hKey);
			} // if (CryptDeriveKey(hC...
		  } // if (CryptHashData(h....
          CryptDestroyHash(hHash);
		} // if (CryptCreateHas...
        CryptReleaseContext(hCryptProv, 0);
	  } // if (CryptAcquire...
      CloseHandle(lWriteFH);
    } // if ((lWrite...
    CloseHandle(lReadFH);
  } // if ((lReadFH = ...
}





/*
 *
 *
 */
void PrintHelp(char *pProgName)
{
  int i = 0;
  char lTemp[MAX_BUF_SIZE + 1];
  int lTitleLen = 0;


  if (pProgName != NULL)
  {
    if (strstr(pProgName, ".exe"))
      *strstr(pProgName, ".exe") = 0;

    ZeroMemory(lTemp, sizeof(lTemp));
    snprintf(lTemp, sizeof(lTemp)-1, "%s %s", pProgName, VERSION);
    lTitleLen = strnlen(lTemp, sizeof(lTemp)-1);
  } // if (pProgN...

  system("cls");
  printf("\n%s\n", lTemp);
  for (; i < lTitleLen; i++)
    printf("-");

  printf("\n\nWeb\thttp://www.megapanzer.com\n");
  printf("Mail\tmegapanzer@gmail.com\n\n\n");
  printf("%s -e password filename\t: Encrypt file FILENAME\n", pProgName);
  printf("%s -d password filename\t: Decrypt file FILENAME\n", pProgName);
}

