#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>

#define MAX_BUF_SIZE 100024

#pragma comment(lib, "crypt32.lib")


/*
 * Function forward declarations
 */
void GenerateHash(DWORD dwBufferLen, BYTE *pbBuffer, int pHashType);
void DumpB64(DWORD bytes, BYTE *data);
void DumpHex(DWORD bytes, BYTE *data);



int main(int argc, char *argv[])
{
  int lRetVal = 0;
  char *lString2Hash = "Peter und der Wolf";

  GenerateHash(strlen(lString2Hash), (BYTE *) lString2Hash, CALG_SHA1);
  GenerateHash(strlen(lString2Hash), (BYTE *) lString2Hash, CALG_MD5);

  return(lRetVal);
}



void GenerateHash(DWORD pDataLen, BYTE *pData, int pHashType)
{
  HCRYPTPROV lCryptProvHandle;
  HCRYPTHASH lCryptHashHandle;
  BYTE *pbHash;
  BYTE *pbHashSize;
  DWORD lHashLen = sizeof(DWORD);



  if (CryptAcquireContext(&lCryptProvHandle, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) 
  {
    if (CryptCreateHash(lCryptProvHandle, pHashType, 0, 0, &lCryptHashHandle)) 
    {
      if (CryptHashData(lCryptHashHandle, pData, pDataLen, 0)) 
      {
        if ((pbHashSize = (BYTE*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lHashLen)) != NULL)
        {
          // Determine size of the hash data buffer
          if (CryptGetHashParam(lCryptHashHandle, HP_HASHVAL, NULL, &lHashLen, 0)) 
          {
            if ((pbHash = (BYTE*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lHashLen)) != NULL)
            {
              // Generate hash
              if (CryptGetHashParam(lCryptHashHandle, HP_HASHVAL, pbHash, &lHashLen, 0))
              {
                DumpB64(lHashLen, pbHash);
                DumpHex(lHashLen, pbHash);
              } // if(CryptGetHashParam(...
              HeapFree(GetProcessHeap(), 0, pbHash);
            } // if ((pbHash = (BYTE*) HeapAlloc(...
          } // if (CryptGetHashParam(...
          HeapFree(GetProcessHeap(), 0, pbHashSize);
        } // if ((pbHashSize = (BYTE*) HeapAlloc(...
      } // if (CryptHashData(...
      CryptDestroyHash(lCryptHashHandle);
    } // if (CryptCreateHash(...
    CryptReleaseContext(lCryptProvHandle, 0);
  } // if (CryptAcquireContext(...
}



void DumpB64(DWORD bytes, BYTE *data)
{
  DWORD lB64Len = sizeof(DWORD);
  PCHAR l64DataString = NULL;

  if (CryptBinaryToString(data, bytes, CRYPT_STRING_BASE64, NULL, &lB64Len))
  {
    if ((l64DataString = (char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lB64Len)) != NULL)
    {
      if (CryptBinaryToString(data, bytes, CRYPT_STRING_BASE64, l64DataString, &lB64Len))
      {
        printf("B64:  %s\n", l64DataString);
      } // if (CryptBinaryToString(...
      HeapFree(GetProcessHeap(), 0, l64DataString);
    } // if ((szB64str = (char *) HeapAlloc(...
  } // if (CryptBinaryToString...
}



void DumpHex(DWORD bytes, BYTE *pData) 
{
  int lCounter;

  printf("Hex:  ");
  for (lCounter = 0 ; lCounter < bytes ; lCounter++)
  {
    if (lCounter%16 == 0)
      printf("\n");
    else if (lCounter%8 == 0)
      printf("   ");

    printf("%2.2X ", *pData++);
  } // for (lCounter...

}
