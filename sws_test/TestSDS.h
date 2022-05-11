/*
* file: TestSDS.h
* Desc: swcsm test tool
* Copyright (c) SWXA
*
* Version     Date        By who     Desc
* ----------  ----------  ---------  -------------------------------
* v1.5.0000   2011.00.00  ......   ! Optimize source code
* v1.6.0000   2011.08.06  ......   ! Add 12 Card Supports 01、03、05、09版密码卡一次最大传输8192字节（2048 DWORDS）数据，12版密码卡一次最大传输16384字节（4096 DWORDS）数据
* v1.7.0000   2011.08.11  ......   ! Optimize source code about FunctionTest.c file
* v2.0.0000   2012.01.10  ......   ! Add SDF_GenerateKeyWithIPK_ECC\SDF_GenerateKeyWithEPK_ECC\SDF_ImportKeyWithISK_ECC\SDF_ExchangeDigitEnvelopeBaseOnECC functions test.
* v2.1.0000   2012.02.08  ......   ! Optimize The defination of ECCCipher struct according to GuoMi standard.
* v2.2.0000   2012.02.28  ......   ! Optimize The defination of ECCCipher struct so that absolutely follow the GuoMi standard.
* v2.4.0000   2012.03.12  ......   ! Optimize the defination of SDF_ImportKeyWithKEK funcitons about param data type.
* v2.6.0000   2012.04.09  ......   ! Add 16 card supports and optimize source codes.
* v2.8.0000   2012.07.23  ......   ! Optimize source code
* v3.0.0000   2014.01.26  ......   ! Optimize source codes.
* v3.1.0000   2014.10.11  ......   ! Press test symm key length modify to 16 so that adjust to CSM24 card's key check.
* v3.2.0000   2015.01.13  ......   ! Add SM7 algorithm support.
* v3.2.1000   2015.02.11  ......   ! Optimize source codes.
* v3.3.0000   2015.06.24  ......   ! Add SWCSM30 card supports.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#ifdef WIN32
#include <process.h>
#include <windows.h>
#include <io.h>
#include <conio.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <termios.h>
#endif

#include "swsds.h"

#ifdef WIN32
#define PUTCH(ch) _putch(ch)
#define GETCH() _getch()
#define GETANYKEY() _getch()
#define SLEEP(msec) Sleep(msec)
#define	THREAD_EXIT() _endthread() 
#define GETCURRENTTHREADID GetCurrentThreadId
#else
#define PUTCH(ch) putchar(ch)
//#define GETCH() getchar()
#define GETCH() getch_unix()
//#define GETANYKEY() getchar()
#define GETANYKEY() getch_unix()
#define SLEEP(msec) usleep(msec*1000)
#define	THREAD_EXIT() pthread_exit(NULL)
#define GETCURRENTTHREADID (int)pthread_self
#endif

#define OPT_EXIT        -1
#define OPT_RETURN      -2
#define OPT_PREVIOUS    -3
#define OPT_NEXT		-4
#define OPT_YES 		-5
#define OPT_CANCEL		-6

#define TESTSDS_VERSION  "v3.3"	//版本控制信息
#define _NOT_TEST_KEK_  1			//压力测试时不测试KEK功能
#define _NOT_USE_RANDOME_TEST_ 1	//性能测试时使用随机数据测试
#define MAX_SYMM_DATA_LENGTH		131072


extern SGD_HANDLE hDeviceHandle;	
extern unsigned int g_nTestRepeat;

//功能测试函数声明
int BasicFuncTest(int nMyPos, int nDefaultSelect);
int CreateFileTest(int nMyPos, SGD_HANDLE hSessionHandle);
int DeleteFileTest(int nMyPos,SGD_HANDLE hSessionHandle);
int DestroyKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *hKeyHandle);
int ECCStdDataVerifyTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ECCStdDataDecTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ECCTransEnvelopTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ECCAgreementTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ECCFuncTest(int nMyPos, int nDefaultSelect);
int ExportECCPukTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ExportRSAPukTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ExtECCOptTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ExtECCSignTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ExtRSAOptTest(int nMyPos, SGD_HANDLE hSessionHandle);
int FileFuncTest(int nMyPos, int nDefaultSelect);
int FunctionTest(int nMyPos, int nDefaultSelect);
int GenECCKeyPairTest(int nMyPos, SGD_HANDLE hSessionHandle);
int GenKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle);
int GenRandomTest(int nMyPos, SGD_HANDLE hSessionHandle);
int GenRSAKeyPairTest(int nMyPos, SGD_HANDLE hSessionHandle);
int GetDeviceInfoTest(int nMyPos, SGD_HANDLE hSessionHandle);
int HashFuncTest(int nMyPos, int nDefaultSelect);
int HashTest(int nMyPos, SGD_HANDLE hSessionHandle);
int HashCorrectnessTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ImportKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle);
int InSymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle);
int IntECCOptTest(int nMyPos, SGD_HANDLE hSessionHandle);
int IntECCSignTest(int nMyPos, SGD_HANDLE hSessionHandle);
int IntRSAOptTest(int nMyPos, SGD_HANDLE hSessionHandle);
int ReadFileTest(int nMyPos, SGD_HANDLE hSessionHandle);
int RSAFuncTest(int nMyPos, int nDefaultSelect);
int SymmCorrectnessTest(int nMyPos, SGD_HANDLE hSessionHandle);
int SymmCalculateMACTest(int nMyPos, SGD_HANDLE hSessionHandle);
int SymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle);
int SymmFuncTest(int nMyPos, int nDefaultSelect);
int TransEnvelopTest(int nMyPos, SGD_HANDLE hSessionHandle);
int WriteFileTest(int nMyPos, SGD_HANDLE hSessionHandle);

//辅助函数声明
#ifndef WIN32
int getch_unix(void);
#endif

int GetString(char *str, int maxSize);
int GetPasswd(char *buf, int maxSize);
int GetSelect(int nDefaultSelect, int nMaxSelect);
int GetInputLength(int nDefaultLength, int nMin, int nMax);
void GetAnyKey();
int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount);
unsigned int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size);
unsigned int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size);
