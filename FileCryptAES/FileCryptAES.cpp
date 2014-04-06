#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>


#pragma comment(lib, "crypt32.lib")

#define snprintf _snprintf
#define MAX_BUF_SIZE 1024
#define VERSION "0.1"



/*
 * Function forward declarations
 *
 */
void PrintHelp(char *pProgName);
BOOL AESEncrypt(char *pPassword, char **pData, DWORD pDataSize, long *pOutputSize);
BOOL AESDecrypt(char *password,char *buffer,DWORD size,DWORD *out_size);


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
  {
    if ((lReadFH = CreateFile(argv[3], GENERIC_READ, FILE_SHARE_READ,  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
      lFileSize = GetFileSize(lReadFH, 0);
      if ((lInputDataBuf = (char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lFileSize)) != NULL)
      {
        if (ReadFile(lReadFH, lInputDataBuf, lFileSize, &lReadCount, NULL))
        {
          if (AESEncrypt(argv[2], &lInputDataBuf, (long) lReadCount, &lCryptedSize))
    		    {
            ZeroMemory(lOutFile, sizeof(lOutFile));
            snprintf(lOutFile, sizeof(lOutFile)-1, "ProtectedAES_%s", argv[3]);
            if ((lWriteFH = CreateFile(lOutFile,  GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
			         {
              WriteFile(lWriteFH, lInputDataBuf, lCryptedSize, (DWORD *) &lCryptedSize, NULL);
			         }
		        }
		      }		
      }
	  else
		  printf("Encrypt(3.1) : NOK %d\n", GetLastError());
	}

//    EncryptMyFile(argv[2], argv[3]);
  }
  else if (argc == 4 && !strncmp(argv[1], "-d", 2))
  {
    if ((lReadFH = CreateFile(argv[3], GENERIC_READ, FILE_SHARE_READ,  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
      lFileSize = GetFileSize(lReadFH, 0);
      if ((lInputDataBuf = (char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lFileSize)) != NULL)
      {
        if (ReadFile(lReadFH, lInputDataBuf, lFileSize, &lReadCount, NULL))
        {
          if (AESDecrypt(argv[2], lInputDataBuf, (long) lReadCount, &lCryptedSize))
		        {
            ZeroMemory(lOutFile, sizeof(lOutFile));
            snprintf(lOutFile, sizeof(lOutFile)-1, "UnprotectedAES_%s", argv[3]);
            if ((lWriteFH = CreateFile(lOutFile,  GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
          		{
              WriteFile(lWriteFH, lInputDataBuf, lCryptedSize, (DWORD *) &lCryptedSize, NULL);
			         }
		        }
		      }		
      }
	   }


//    DecryptMyFile(argv[2], argv[3]);
  }
  else
  {
  	 PrintHelp(argv[0]);
  }

  return(lRetVal);
}






BOOL AESEncrypt(char *pPassword, char **pData, DWORD pDataSize, long *pOutputSize)
{
  BOOL lRetVal = FALSE;
  HCRYPTPROV lCryptProvHandle = 0;
  HCRYPTKEY lKeyHandle = 0;
  HCRYPTHASH lHashHandle = 0;
  DWORD lDestBufSize;
  char *lTmp = NULL;

	       
  if (CryptAcquireContext(&lCryptProvHandle, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
  {
    if (CryptCreateHash(lCryptProvHandle, CALG_SHA_256, 0, 0, &lHashHandle))
    {
      if (CryptHashData(lHashHandle, (PBYTE) pPassword, (DWORD) strlen(pPassword), 0))
      {
        if (CryptDeriveKey(lCryptProvHandle, CALG_AES_256, lHashHandle, CRYPT_EXPORTABLE, &lKeyHandle))
        {
          lDestBufSize = pDataSize;
          if (CryptEncrypt(lKeyHandle, 0, TRUE, 0, NULL, &pDataSize, lDestBufSize))
          {
            if ((lTmp = (char*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pDataSize*sizeof(char))) != NULL)
			{
              CopyMemory(lTmp, *pData, lDestBufSize);              
              if (CryptEncrypt(lKeyHandle, 0, TRUE, 0, (BYTE *) lTmp, &lDestBufSize, pDataSize))
              {
                HeapFree(GetProcessHeap(), 0, *pData);

                *pOutputSize = lDestBufSize;
                *pData = lTmp;
                lRetVal = TRUE;
              } // if (CryptEncrypt...      
		        	 } // if ((lTmp = (char*) HeapAlloc(...
          } // if (CryptEncrypt(...
          CryptDestroyKey(lKeyHandle);
        } // if (CryptDeriveKey(...        
      }	// if (CryptHashData(...
      CryptDestroyHash(lHashHandle);
    } // if (CryptCreateHash(...
    CryptReleaseContext(lCryptProvHandle, 0);
  } // if (CryptAcquireContext(...
  
  return(lRetVal);
}
	



BOOL AESDecrypt(char *pPassword, char *pData, DWORD pDataLen, DWORD *pOutputDataLen)
{
  BOOL lRetVal = FALSE;
  HCRYPTPROV lCryptProvHandle = 0;
  HCRYPTKEY lKeyHandle = 0;
  HCRYPTHASH lHashHandle = 0;
	
  if (CryptAcquireContext(&lCryptProvHandle, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
  {
    if (CryptCreateHash(lCryptProvHandle, CALG_SHA_256, 0, 0, &lHashHandle))
    {
      if (CryptHashData(lHashHandle, (PBYTE) pPassword,(DWORD) strlen(pPassword), 0))
      {
        if (CryptDeriveKey(lCryptProvHandle, CALG_AES_256, lHashHandle, CRYPT_EXPORTABLE, &lKeyHandle))
        {	
          if (CryptDecrypt(lKeyHandle, 0, TRUE, 0, (BYTE *) pData, &pDataLen))
          {
            *pOutputDataLen = pDataLen;
            lRetVal = TRUE;
          }
		        else
            *pOutputDataLen = 0;
          
          CryptDestroyKey(lKeyHandle);
        } // if (CryptDeriveKey(...
      } // if (CryptHashData(...
      CryptDestroyHash(lHashHandle);
    } // if (CryptCreateHash(...
    CryptReleaseContext(lCryptProvHandle, 0);
  } // if (CryptAcquireContext(...

  return(lRetVal);
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

