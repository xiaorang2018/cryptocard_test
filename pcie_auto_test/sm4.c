#include "sm4.h"

const muint8 Sbox[256] = {
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
const muint32 CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };

#define Rotl(_x, _y) (((_x) << (_y)) | ((_x) >> (32 - (_y))))

#define ByteSub(_A) (Sbox[(_A) >> 24 & 0xFF] << 24 ^ \
                     Sbox[(_A) >> 16 & 0xFF] << 16 ^ \
                     Sbox[(_A) >>  8 & 0xFF] <<  8 ^ \
                     Sbox[(_A) & 0xFF])

#define L1(_B) ((_B) ^ Rotl(_B, 2) ^ Rotl(_B, 10) ^ Rotl(_B, 18) ^ Rotl(_B, 24))
#define L2(_B) ((_B) ^ Rotl(_B, 13) ^ Rotl(_B, 23))

// SMS4的加解密函数
// 参数说明：Input为输入信息分组，Output为输出分组，rk为轮密钥
void SMS4Crypt(muint8 *Input, muint8 *Output, muint32 *rk)
{
	 muint32 r, mid, x0, x1, x2, x3, *p;
	 p = (muint32 *)Input;
	 x0 = p[0];
	 x1 = p[1];
	 x2 = p[2];
	 x3 = p[3];
#ifdef LITTLE_ENDIAN
	 x0 = Rotl(x0, 16); x0 = ((x0 & 0x00FF00FF) << 8) ^ ((x0 & 0xFF00FF00) >> 8);
	 x1 = Rotl(x1, 16); x1 = ((x1 & 0x00FF00FF) << 8) ^ ((x1 & 0xFF00FF00) >> 8);
	 x2 = Rotl(x2, 16); x2 = ((x2 & 0x00FF00FF) << 8) ^ ((x2 & 0xFF00FF00) >> 8);
	 x3 = Rotl(x3, 16); x3 = ((x3 & 0x00FF00FF) << 8) ^ ((x3 & 0xFF00FF00) >> 8);
#endif
	 for (r = 0; r < 32; r += 4)
	 {
		  mid = x1 ^ x2 ^ x3 ^ rk[r + 0];
		  mid = ByteSub(mid);
		  x0 ^= L1(mid);
		  mid = x2 ^ x3 ^ x0 ^ rk[r + 1];
		  mid = ByteSub(mid);
		  x1 ^= L1(mid);
		  mid = x3 ^ x0 ^ x1 ^ rk[r + 2];
		  mid = ByteSub(mid);
		  x2 ^= L1(mid);
		  mid = x0 ^ x1 ^ x2 ^ rk[r + 3];
		  mid = ByteSub(mid);
		  x3 ^= L1(mid);
	 }
#ifdef LITTLE_ENDIAN
	 x0 = Rotl(x0, 16); x0 = ((x0 & 0x00FF00FF) << 8) ^ ((x0 & 0xFF00FF00) >> 8);
	 x1 = Rotl(x1, 16); x1 = ((x1 & 0x00FF00FF) << 8) ^ ((x1 & 0xFF00FF00) >> 8);
	 x2 = Rotl(x2, 16); x2 = ((x2 & 0x00FF00FF) << 8) ^ ((x2 & 0xFF00FF00) >> 8);
	 x3 = Rotl(x3, 16); x3 = ((x3 & 0x00FF00FF) << 8) ^ ((x3 & 0xFF00FF00) >> 8);
#endif
	 p = (muint32 *)Output;
	 p[0] = x3;
	 p[1] = x2;
	 p[2] = x1;
	 p[3] = x0;
}

// SMS4的密钥扩展算法
// 参数说明：Key为加密密钥，rk为子密钥，CryptFlag为加解密标志
void SMS4KeyExt(muint8 *Key, muint32 *rk, muint32 CryptFlag)
{
	 muint32 r, mid, x0, x1, x2, x3, *p;
	 p = (muint32 *)Key;
	 x0 = p[0];
	 x1 = p[1];
	 x2 = p[2];
	 x3 = p[3];
#ifdef LITTLE_ENDIAN
	 x0 = Rotl(x0, 16); x0 = ((x0 & 0xFF00FF) << 8) ^ ((x0 & 0xFF00FF00) >> 8);
	 x1 = Rotl(x1, 16); x1 = ((x1 & 0xFF00FF) << 8) ^ ((x1 & 0xFF00FF00) >> 8);
	 x2 = Rotl(x2, 16); x2 = ((x2 & 0xFF00FF) << 8) ^ ((x2 & 0xFF00FF00) >> 8);
	 x3 = Rotl(x3, 16); x3 = ((x3 & 0xFF00FF) << 8) ^ ((x3 & 0xFF00FF00) >> 8);
#endif
	 x0 ^= 0xa3b1bac6;
	 x1 ^= 0x56aa3350;
	 x2 ^= 0x677d9197;
	 x3 ^= 0xb27022dc;
	 for (r = 0; r < 32; r += 4)
	 {
		  mid = x1 ^ x2 ^ x3 ^ CK[r + 0];
		  mid = ByteSub(mid);
		  rk[r + 0] = x0 ^= L2(mid);
		  mid = x2 ^ x3 ^ x0 ^ CK[r + 1];
		  mid = ByteSub(mid);
		  rk[r + 1] = x1 ^= L2(mid);
		  mid = x3 ^ x0 ^ x1 ^ CK[r + 2];
		  mid = ByteSub(mid);
		  rk[r + 2] = x2 ^= L2(mid);
		  mid = x0 ^ x1 ^ x2 ^ CK[r + 3];
		  mid = ByteSub(mid);
		  rk[r + 3] = x3 ^= L2(mid);
	 }
	 if (CryptFlag == DECRYPT)
	 {
	 	  for (r = 0; r < 16; r++)
	 	  	 mid = rk[r], rk[r] = rk[31 - r], rk[31 - r] = mid;
	 }
}
/*
 * 函数描述：	做一组的异或操作
 * 参数：	a	[IN]需要异或的参数a
 * 		b	[IN]需要异或的参数b
 *		dst	[OUT]异或后的输出
 */
void SM4EnCrypt(muint8  *Input,muint8 *Output,muint8 *Key)
{
	muint32 rk[32];
	SMS4KeyExt(Key,rk,ENCRYPT);
	SMS4Crypt(Input,Output,rk);
}

void SM4DeCrypt(muint8  *Input, muint8 *Output, muint8 *Key)
{
	muint32 rk[32];
	SMS4KeyExt(Key, rk, DECRYPT);
	SMS4Crypt(Input, Output, rk);
}

void SM4EnCryptnGroup(muint8  *Input, int len, muint8 *Output, muint8 *Key)
{
	muint32 group = 0;

	while (len > 0)
	{
		SM4EnCrypt(Input+16*group, Output+16*group, Key);
		len -= 16;
		group++;
	}
}

void SM4DeCryptnGroup(muint8  *Input, int len, muint8 *Output, muint8 *Key)
{
	muint32 group = 0;

	while (len > 0)
	{
		SM4DeCrypt(Input + 16 * group, Output + 16 * group, Key);
		len = len - 16;

		group++;
	}
}


void ExclusiveOr(unsigned char *a,unsigned char *b,unsigned char *dst)
{
	int i;
	for (i = 0; i < SM4_L; i++)
	{
		dst[i] = a[i] ^ b[i];
	}
}
/*
 * 函数描述：	做MAC运算但是此函数不对数据进行填充工作
 * 参数：	iv	[IN]初始化向量
 *		key	[IN]密钥
 * 		d	[IN]需要做MAC_SM4运算的数据缓冲区
 *		nGroup	[IN]数据的分组个数
 *		mac	[OUT]输出的MAC值
 */
int MAC_SM4(muint8 *iv,muint8 *key, muint8 *sou, int nGroup,muint8 *src)
{
	int i;

	muint8 ivt[SM4_L];
//	muint8 result[SM4_L];
	muint8 temp[SM4_L];

	memcpy(ivt, iv, SM4_L);


	for (i = 0; i < nGroup; i++)
	{
		/* 1. 异或 */
		ExclusiveOr(ivt, NEXT_D(sou, i, SM4_L), temp);
		/* 2. 加密 result为输出密文 */
		//if (SM4(ivt, key, result) != SUCCESS);
		//	return -2;
		SM4EnCrypt(temp,ivt,key);
		/* 3. 把加密后的数据作为下一组的初始化向量 */
		//memcpy(ivt, result, SM4_L);
	}
	memcpy(src, ivt, MAC_SIZE);
	return 0;
}

//秘钥  随机数  8   sou数据  len src数据 len
int MyMAC(muint8 *key,muint8 *pbRandom,int RanLen,muint8 *sou,int DataInLen,muint8 *src,int DataOutLen)
{
	muint8 random[SM4_L];
	int i;
	muint8 macbuf[4096];
	int nGroup;
	int tmpLen;

	memcpy(random,pbRandom,RanLen);
	for(i= RanLen; i<SM4_L-RanLen; i++)
	{
		random[i]=0x00;
	}
	
	tmpLen=DataInLen%SM4_L;
	memcpy(macbuf,sou,DataInLen);
	macbuf[DataInLen]=0x80;
	memset(macbuf+DataInLen+1,0x00,SM4_L-tmpLen-1);
	
	nGroup=DataInLen/SM4_L+1;

	if (MAC_SM4(random,key, macbuf, nGroup, src))
	{
		return -2;
	}

	return 0;
}

