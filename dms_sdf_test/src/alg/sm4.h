#ifndef __SM4ENCRYPT_H__
#define __SM4ENCRYPT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#define LITTLE_ENDIAN     //定义小端字节序
//#define BIG_ENDIAN     	//定义大端字节序
#define ENCRYPT  0     		//定义加密标志
#define DECRYPT  1     		//定义解密标志

typedef unsigned char muint8;
typedef unsigned int muint32;

#define LITTLE_ENDIAN

#define SM4_L				(16)
#define NEXT_D(d, i, len)	(d + (len * i))		/* 获取第i个数据块（一个数据块长度为len字节） */
#define MAC_SIZE			(4)
#define MAC_RANDOM_SIZE		(8)

void SMS4Crypt(muint8 *Input, muint8 *Output, muint32 *rk);

void SMS4KeyExt(muint8 *Key, muint32 *rk, muint32 CryptFlag);

void SM4EnCrypt(muint8  *Input,muint8 *Output,muint8 *Key);

void SM4DeCrypt(muint8  *Input,muint8 *Output,muint8 *Key);

void SM4EnCryptnGroup(muint8  *Input, int len, muint8 *Output, muint8 *Key);

void SM4DeCryptnGroup(muint8  *Input, int len, muint8 *Output, muint8 *Key);

void ExclusiveOr(unsigned char *a,unsigned char *b,unsigned char *dst);

int MAC_SM4(muint8 *iv,muint8 *key, muint8 *sou, int nGroup,muint8 *src);

int MyMAC(muint8 *key,muint8 *pbRandom,int RanLen,muint8 *sou,int DataInLen,muint8 *src,int DataOutLen);





#endif