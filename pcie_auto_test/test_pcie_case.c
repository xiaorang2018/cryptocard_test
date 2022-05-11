#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <sys/time.h>
#include "pcitesterrno.h"
#include "dms_sdf.h"
#include "dms_mgr_sdf.h"
#include "sm2.h"

typedef void *  HANDLE ;
typedef int8_t  BYTE ; 
typedef int16_t  WORD ;
typedef unsigned char		UINT8;
typedef unsigned short		UINT16;

#define RETEST_NUM	10000
#define RANDOM_SIZE 	32

const unsigned char allChar[63] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


 
void generateString(unsigned char * dest, const unsigned int len)
{
	unsigned int cnt, randNo;
	//srand((unsigned int)time(NULL));
 
	for (cnt = 0; cnt<len; cnt++)
	{
		randNo = rand() % 62;
		*(dest + cnt) = allChar[randNo];
	}
 
	*(dest + cnt) = '\0';
}



int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	
	if(itemName != NULL)
		printf("%s[%d]:\n", itemName, dataLength);
	
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		printf("%08x  ",i * rowCount);

		for(j=0; j<(int)rowCount; j++)
		{
			printf("%02x ", *(sourceData + i*rowCount + j));
		}

		printf("\n");
	}

	if (!(dataLength % rowCount))
		return 0;
	
	printf("%08x  ", (dataLength/rowCount) * rowCount);

	for(j=0; j<(int)(dataLength%rowCount); j++)
	{
		printf("%02x ",*(sourceData + (dataLength/rowCount)*rowCount + j));
	}

	printf("\n");

	return 0; 
}

static int16_t get_get_ab_gx_gy_length(void)
{
    return 32*4 ;
}

static void get_ab_gx_gy(int8_t *data,int16_t *length)
{
    if(data == NULL)
	{
        printf("data param error !\n");
        return;
    }
    UINT8 fix[]={
    /*a*/
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
    /*b*/
    0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
    0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
    0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
    0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
    /*gx*/
    0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
    0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
    0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
    0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7 ,
    /*gy*/
    0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
    0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
    0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
    0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
    };
    if(length != NULL)
	{
        *length = 128 ;
    }
    memcpy(data,fix,128);
}


unsigned int Get_ZA(unsigned char *id, unsigned int id_length, unsigned char *data, unsigned int data_length, unsigned char *za, unsigned int *za_length)
{ 
    unsigned int fix_data_length =  get_get_ab_gx_gy_length();                            
    unsigned int all_data_length = 2 + id_length + fix_data_length + data_length;
    unsigned char *all_data = NULL ;
	unsigned int HASH_LEN = 32;

    if(za == NULL)
	{
        printf("za param error !\n");
        return 1 ;
    }
    all_data = malloc(all_data_length);
    if(all_data == NULL)
	{
        printf("malloc space error !\n");
        return 1 ;
    }

	all_data[0] = (id_length * 8) >> 8;
	all_data[1] = id_length * 8;
	memcpy(all_data + 2, id, id_length);
	get_ab_gx_gy(all_data + 2 + id_length, NULL);
    memcpy(all_data + 2 + id_length + fix_data_length ,data, data_length);
    if(za_length)
	{
        *za_length = HASH_LEN ;
    }

	sm3(all_data, all_data_length, za);
    free(all_data);
	all_data = NULL;
    return 0 ;
	
}


unsigned int Get_e(unsigned char *za, unsigned char *xPA, unsigned char *yPA, unsigned char *m, unsigned int mLength, unsigned char *e, unsigned int* eLength)
{ 
                           
    unsigned int all_data_length = 32 + 32 + 32 + mLength;
    unsigned char *all_data = NULL;
	unsigned int HASH_LEN = 32;

    if((za==NULL) || (xPA==NULL) || (yPA==NULL) || (m==NULL))
	{
        printf("input param error !\n");
        return 1 ;
    }
    all_data = (unsigned char *)malloc(all_data_length);
    if(all_data == NULL)
	{
        printf("malloc space error !\n");
        return 1 ;
    }
    memcpy(all_data, za, 32);
	memcpy(all_data + 32, xPA, 32);
	memcpy(all_data + 64, yPA, 32);
	memcpy(all_data + 96, m, mLength);	
    if(eLength)
	{
        *eLength = HASH_LEN ;
    }
	sm3(all_data, all_data_length, e);
    free(all_data);
	all_data = NULL;
    return 0;
	
}


int test_OpenDevice(HANDLE *hd, HANDLE *hs)
{
	HANDLE sthd = NULL;
	HANDLE sths = NULL;
	int ret;

	if(sthd == NULL)
	{
		ret = SDF_OpenDevice(&sthd);
		if (SDR_OK != ret)
		{
			printf("open device error\n");
			return PCIERR_DM_OPENDEVICE;
		}
	}
	*hd = sthd;
	
	if(sths == NULL)
	{
		ret = SDF_OpenSession(sthd, &sths);
		if (SDR_OK != ret)
		{
			printf("open session error\n");
			SDF_CloseDevice(*hd);
			sthd = NULL;
			return PCIERR_DM_OPENSESSION;
		}
	}
	*hs = sths;	
	return 0;
}

int test_CloseDevice(HANDLE hd, HANDLE hs)
{
	int ret;

	ret = SDF_CloseSession(hs);
	if (SDR_OK != ret)
		return PCIERR_DM_CLOSESESSION;

	ret = SDF_CloseDevice(hd);
	if (SDR_OK != ret)
		return PCIERR_DM_CLOSEDEVICE;

	return 0;
}

int test_GenerateRandom(int numbers)
{
	HANDLE hd;
	HANDLE hs;
	int ret, logret = 0;
	int i;
	BYTE random[RETEST_NUM][RANDOM_SIZE];

	printf("[%s]\n", __FUNCTION__);
	ret = test_OpenDevice(&hd, &hs);
	if (ret != SDR_OK)
	{
		pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
		return ret;
	}

	for(i = 0; i < numbers; i++)
	{
		ret = SDF_GenerateRandom(hs, RANDOM_SIZE, random[i]);
		if (SDR_OK != ret) {
			logret = __LINE__;
			goto error;
		}

		if (i != 0)
		{
			if (!memcmp(random[i], random[i-1], RANDOM_SIZE))
			{
				logret = __LINE__;
				goto error;
			}
		}
	}

	ret = test_CloseDevice(hd, hs);
	if (ret != SDR_OK)
		return ret;
	return 0;

error:
	test_CloseDevice(hd, hs);
	pciCunitTestWriteLog(logret, ret, __FUNCTION__);
	return ret;
}

int test_GetDeviceInfo(int numbers)
{
	HANDLE hd;
	HANDLE hs;
	int ret, logret = 0;
	int i;

	DEVICEINFO dinfo;
	printf("[%s]\n", __FUNCTION__);

	ret = test_OpenDevice(&hd, &hs);
	if (ret != SDR_OK)
	{
		pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
		if (ret == PCIERR_DM_OPENDEVICE)
			exit(1);
		return ret;
	}

	for (i = 0; i < numbers; i++)
	{
		ret = SDF_GetDeviceInfo(hs, &dinfo);
		if (ret != SDR_OK)
		{
			logret = __LINE__;
			goto error;
		}
	}

	ret = test_CloseDevice(hd, hs);
	if (ret != SDR_OK)
		return ret;
	
	return 0;

error:
	test_CloseDevice(hd, hs);
	pciCunitTestWriteLog(logret, ret, __FUNCTION__);
	return ret;
}


int test_GetAndReleasePrivateKeyAccessRight(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	int uiKeyIndex = 1;
	unsigned char pucPassword[] = "dms123456";
	unsigned int uiPwdLength = 9;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_ReleasePrivateKeyAccessRight(hs, uiKeyIndex);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}



int test_ExportEncPublicKeyAndExportSignPublicKey(int numbers)
{
        HANDLE hd; 
        HANDLE hs; 
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
	ECCrefPublicKey pucPublicKeyRSA[2] = {0};
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {   
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }   

        for(i = 0; i < numbers; i++)
        {   
                ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, pucPublicKeyRSA);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }   
                ret = SDF_ExportSignPublicKey_ECC(hs, uiKeyIndex, &pucPublicKeyRSA[1]);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }   
        }   

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_GenerateKeyWithEPK_ECC(int numbers)
{
        HANDLE hd; 
        HANDLE hs; 
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
	unsigned int uiKeyBits = 128;
	unsigned int uiAlgId = SGD_SM2_3;
	//unsigned char publicKeyData[256] = {0x00};
	//ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
	ECCrefPublicKey pucPublicKey = {0};
	unsigned char cipherData[3092] = {0x00};
	ECCCipher *cipher = (ECCCipher *)cipherData;
	HANDLE phKeyHandle = NULL;
	printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {   
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }   

        for(i = 0; i < numbers; i++)
        { 
				ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, &pucPublicKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }  
				for(uiKeyBits= 128; uiKeyBits<=2048; uiKeyBits*=2){
					ret = SDF_GenerateKeyWithEPK_ECC(hs, uiKeyBits, uiAlgId, &pucPublicKey, cipher, &phKeyHandle);
					if (SDR_OK != ret) {
                        logret = __LINE__;
						
                        goto error;
					}  		
				}
                 
        }   

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}




int test_GenerateKeyWithIPK_ECC(int numbers)
{
        HANDLE hd; 
        HANDLE hs; 
        int ret, logret = 0;
        int i;
        unsigned int uiIPKIndex = 1;
        unsigned int uiKeyBits = 128;
        unsigned int uiAlgId = SGD_SM2_3;
        unsigned char publicKeyData[256] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char cipherData[3092] = {0x00};
        ECCCipher *cipher = (ECCCipher *)cipherData;
        HANDLE phKeyHandle = NULL;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {   
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }   

        for(i = 0; i < numbers; i++)
        {   
				for(uiKeyBits= 128; uiKeyBits<=2048; uiKeyBits*=2){
					ret = SDF_GenerateKeyWithIPK_ECC(hs, uiIPKIndex, uiKeyBits, cipher, &phKeyHandle);
					if (SDR_OK != ret){
                        logret = __LINE__;
                        goto error;
					}  
				}
               
        }   

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_ImportKeyWithISK_ECC(int numbers)
{
        HANDLE hd; 
        HANDLE hs; 
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
        unsigned int uiKeyBits = 128;
        unsigned char publicKeyData[256] = {0x00};
	unsigned char pucPassword[] = "dms123456";
	unsigned int uiPwdLength = 9; 
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char cipherData[3072] = {0x00};
        ECCCipher *cipher = (ECCCipher *)cipherData;
        HANDLE phKeyHandle = NULL;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {   
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }   

        for(i = 0; i < numbers; i++)
        {   
			for(uiKeyBits= 128; uiKeyBits<=2048; uiKeyBits*=2){
                ret = SDF_GenerateKeyWithIPK_ECC(hs, uiKeyIndex, uiKeyBits, cipher, &phKeyHandle);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
   
				ret = SDF_ImportKeyWithISK_ECC(hs, uiKeyIndex, cipher, &phKeyHandle);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
			}	
        }   

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_GenerateKeyAndImportKeyWithKEK(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiKEKIndex = 1;
        unsigned int uiKeyBits = 128;
        unsigned int KEKBitLen = 128;
        unsigned int uiAlgID = SGD_SM4_ECB;
        unsigned char pucKey[3078] = {0x00};
		unsigned int puiKeyLength = 0;
		HANDLE phKeyHandle = NULL;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
		ret = SDF_dmsPCI_GenerateKEK(hs, KEKBitLen, &uiKEKIndex);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				for(uiKeyBits= 128; uiKeyBits<=2048; uiKeyBits*=2){
					puiKeyLength = uiKeyBits / 8;
					ret = SDF_GenerateKeyWithKEK(hs, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, &puiKeyLength, &phKeyHandle);
					if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
					}
					ret = SDF_ImportKeyWithKEK(hs, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, &phKeyHandle);
					if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
					}
					
				}				
               
		ret = SDF_dmsPCI_DeleteKEK(hs, uiKEKIndex);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}




int test_ImportKey(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned char pucKey[3078] = {0};
        unsigned int puiKeyLength = 0;
        HANDLE phKeyHandle = NULL;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
			for(puiKeyLength= 128; puiKeyLength<=2048; puiKeyLength*=2){
				ret = SDF_GenerateRandom(hs, puiKeyLength, pucKey);
						if (SDR_OK != ret) {
							logret = __LINE__;
							goto error;
						}
                ret = SDF_ImportKey(hs, pucKey, puiKeyLength, &phKeyHandle);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
			}
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}



int test_KeyAgreement(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiISKIndex1 = 1;
		unsigned int uiISKIndex2 = 2;
        unsigned int uiKeyBits = 128;
		unsigned int uiAlgID = SGD_SM4_ECB;
		unsigned char pucIV[16] = {0x00};
	unsigned char pucPassword[] = "dms123456";
	unsigned int uiPwdLength = 9;
	unsigned char pucSponsorID[] = "12345678";
	unsigned int uiSponsorIDLength = 8;
	unsigned char pucResponseID[] = "12345678";
	unsigned int uiResponseIDLength = 8;
	unsigned char pucSponsorPublicKeyBuff[132] = {0x00};
	ECCrefPublicKey *pucSponsorPublicKey = (ECCrefPublicKey *)pucSponsorPublicKeyBuff;
	unsigned char pucSponsorTmpPublicKeyBuff[132] = {0x00};
	ECCrefPublicKey *pucSponsorTmpPublicKey = (ECCrefPublicKey *)pucSponsorTmpPublicKeyBuff;
	unsigned char pucResponsePublicKeyBuff[132] = {0x00};
	ECCrefPublicKey* pucResponsePublicKey = (ECCrefPublicKey *)pucResponsePublicKeyBuff;
        unsigned char pucResponseTmpPublicKeyBuff[132] = {0x00};
	ECCrefPublicKey* pucResponseTmpPublicKey = (ECCrefPublicKey *)pucResponseTmpPublicKeyBuff;
	unsigned int uiDataLength = 16 * 1024;
	unsigned int puiEncDataLength, puiDecDataLength;
	BYTE  *pucData;
        BYTE  *pucEncData;
        BYTE  *pucDecData;
	do {
        pucData = (BYTE *)malloc(uiDataLength + 1024);
		pucEncData = (BYTE *)malloc(uiDataLength + 1024);
		pucDecData = (BYTE *)malloc(uiDataLength + 1024);
        }while(!pucData && !pucEncData && !pucDecData);
	HANDLE phAgreementHandle = NULL;
	HANDLE phKeyHandle1 = NULL;
	HANDLE phKeyHandle2 = NULL;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
				ret = SDF_GetPrivateKeyAccessRight(hs, uiISKIndex1, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GetPrivateKeyAccessRight(hs, uiISKIndex2, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				for(uiKeyBits= 128; uiKeyBits<=2048; uiKeyBits*=2){
					ret = SDF_GenerateAgreementDataWithECC(hs, uiISKIndex1, uiKeyBits, pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey, &phAgreementHandle);
					if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
					}			
					ret = SDF_GenerateAgreementDataAndKeyWithECC(hs, uiISKIndex2, uiKeyBits, pucResponseID, uiResponseIDLength, pucSponsorID, uiSponsorIDLength, pucSponsorPublicKey, 
							pucSponsorTmpPublicKey, pucResponsePublicKey, pucResponseTmpPublicKey, &phKeyHandle1);
					if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
					}
					ret = SDF_GenerateKeyWithECC(hs, pucResponseID, uiResponseIDLength, pucResponsePublicKey, pucResponseTmpPublicKey, phAgreementHandle, &phKeyHandle2);
					if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
					}
					//采用协商密钥进行SM4加减密
					if(128 == uiKeyBits){
						ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
						if (SDR_OK != ret) {
							logret = __LINE__;
							goto error;
						}
						ret = SDF_Encrypt(hs, phKeyHandle1, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, &puiEncDataLength);
						if(SDR_OK != ret) {
							logret = __LINE__;
							goto error;
						}
						ret = SDF_Decrypt(hs, phKeyHandle2, uiAlgID, pucIV, pucEncData, puiEncDataLength, pucDecData, &puiDecDataLength);
						if(SDR_OK != ret) {
							logret = __LINE__;
							goto error;
						}
						if(memcmp(pucDecData, pucData, uiDataLength))
						{
							logret = __LINE__;
							goto error;
						}  															
						ret = SDF_DestroyKey(hs, phKeyHandle1);
						if (SDR_OK != ret) {
							logret = __LINE__;
							goto error;
						}
						ret = SDF_DestroyKey(hs, phKeyHandle2);
						if(SDR_OK != ret) {
							logret = __LINE__;
							goto error;
						}	
					}			
				}   
        }

		free(pucData);
		free(pucEncData);
		free(pucDecData);
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        free(pucData);
		free(pucEncData);
		free(pucDecData);
		test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}




int test_ExchangeDigitEnvelopeBaseOnECC(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
        unsigned int uiAlgID = SGD_SM2_3;
        unsigned int uiKeyBits = 128;
        unsigned int uiPwdLength = 9;
	unsigned char pucPassword[] = "dms123456";
        unsigned char publicKeyData[256] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char cipherIn[180] = {0x00};
        ECCCipher *pucEncDataIn = (ECCCipher *)cipherIn;
	unsigned char cipherOut[180] = {0x00};
        ECCCipher *pucEncDataOut = (ECCCipher *)cipherOut;
       	HANDLE phKeyHandle = NULL; 
	printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {  
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
		ret = SDF_GenerateKeyWithIPK_ECC(hs, uiKeyIndex, uiKeyBits, pucEncDataIn, &phKeyHandle);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }	
		ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, pucPublicKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }	
                ret = SDF_ExchangeDigitEnvelopeBaseOnECC(hs, uiKeyIndex, uiAlgID, pucPublicKey, pucEncDataIn, pucEncDataOut);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_InternalSignAndVerify(int numbers)
{       
        HANDLE hd; 
        HANDLE hs; 
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
        unsigned int uiKeyBits = 128;
        unsigned int uiAlgID = SGD_SM2_1;
	unsigned int uiPwdLength = 9;
        unsigned char pucPassword[] = "dms123456";
	unsigned int uiDataLength = 32;
	unsigned char pucData[32] = {0x00};
        unsigned char publicKeyData[256] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char signatureBuffer[256] = {0x00};
	ECCSignature *pucSignature = (ECCSignature *)signatureBuffer;
        
	printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {       
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }
        
        for(i = 0; i < numbers; i++)
        {    
		ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 
		ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }   
                ret = SDF_InternalSign_ECC(hs, uiKeyIndex, pucData, uiDataLength, pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_InternalVerify_ECC(hs, uiKeyIndex, pucData, uiDataLength, pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

        }
        
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:  
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}

int test_ExternalSignAndVerify(int numbers)
{       
        HANDLE hd; 
        HANDLE hs; 
        int ret, logret = 0;
        int i;
        unsigned int uiIPKIndex = 1;
        unsigned int uiKeyBits = 256;
        unsigned int uiAlgID = SGD_SM2;
		unsigned int uiDataLength = 32;
		unsigned char pucData[32] = {0x00};
        unsigned char publicKeyData[256] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char privateKeyData[256] = {0x00};
        ECCrefPrivateKey *pucPrivateKey = (ECCrefPrivateKey *)privateKeyData;
		unsigned char signatureBuffer[256] = {0x00};
		ECCSignature *pucSignature = (ECCSignature *)signatureBuffer;
        HANDLE phKeyHandle = NULL;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {       
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }
        
        for(i = 0; i < numbers; i++)
        {       
                ret = SDF_GenerateKeyPair_ECC(hs, uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 
				uiAlgID = SGD_SM2_1;
				ret = SDF_ExternalSign_ECC(hs, uiAlgID, pucPrivateKey, pucData, uiDataLength, pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_ExternalVerify_ECC(hs, uiAlgID, pucPublicKey, pucData, uiDataLength, pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }
        
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:  
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}

int test_ExternalEncryptAndDecrypt(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	unsigned int uiAlgID = SGD_SM2;
		unsigned int uiKeyBits = 256;
		unsigned char publicKeyData[256] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char privateKeyData[256] = {0x00};
        ECCrefPrivateKey *pucPrivateKey = (ECCrefPrivateKey *)privateKeyData;
        unsigned int uiDataLength = 32;
        unsigned char pucData[32] = {0x00};
		unsigned int uiDecDataLength = 32;
        unsigned char pucDecData[32] = {0x00};
		unsigned char cipherBuffer[1024] = {0x00};
        ECCCipher *pucEncData = (ECCCipher *)cipherBuffer;
	printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
				
                ret = SDF_GenerateKeyPair_ECC(hs, uiAlgID, uiKeyBits, pucPublicKey, pucPrivateKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				uiAlgID = SGD_SM2_3;
				ret = SDF_ExternalEncrypt_ECC(hs, uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_ExternalDecrypt_ECC(hs, uiAlgID, pucPrivateKey, pucEncData, pucDecData, &uiDecDataLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				if(memcmp(pucDecData, pucData, uiDecDataLength))
				{
					logret = __LINE__;
					goto error;
				}  
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_EncryptAndDecrypt(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i,j;
        unsigned int uiIPKIndex = 1;
        unsigned int uiKeyBits = 128;
        unsigned int uiAlgID[5]= {SGD_SM4_ECB, SGD_SM4_CBC, SGD_SM4_OFB, SGD_SM4_CFB, SGD_SM4_CTR};
	unsigned char pucIV[16] = {0x00};
        unsigned char cipherData[512] = {0x00};
        ECCCipher *cipher = (ECCCipher *)cipherData;
        HANDLE phKeyHandle = NULL;
	unsigned int uiDataLength = 32;
	unsigned int puiEncDataLength, puiDecDataLength;
	BYTE  *pucData;
        BYTE  *pucEncData;
        BYTE  *pucDecData;
	do {
                pucData = (BYTE *)malloc(uiDataLength + 1024);
		pucEncData = (BYTE *)malloc(uiDataLength + 1024);
		pucDecData = (BYTE *)malloc(uiDataLength + 1024);
        }while(!pucData && !pucEncData && !pucDecData);

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {		
			for(j = 0; j < 5; j++){
				ret = SDF_GenerateKeyWithIPK_ECC(hs, uiIPKIndex, uiKeyBits, cipher, &phKeyHandle);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_Encrypt(hs, phKeyHandle, uiAlgID[j], pucIV, pucData, uiDataLength, pucEncData, &puiEncDataLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_Decrypt(hs, phKeyHandle, uiAlgID[j], pucIV, pucEncData, puiEncDataLength, pucDecData, &puiDecDataLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				if(memcmp(pucDecData, pucData, uiDataLength))
				{
					logret = __LINE__;
					goto error;
				} 
			
			
			} 
		}
	free(pucData);
	free(pucEncData);
	free(pucDecData);
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
	free(pucData);
        free(pucEncData);
        free(pucDecData);
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_CalculateMAC(int numbers)
{
	HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiIPKIndex = 1;
        unsigned int uiKeyBits = 128;
        unsigned int uiAlgID = SGD_SM4_MAC;
        unsigned char pucIV[16] = {0x00};
	unsigned char cipherData[512] = {0x00};
        ECCCipher *cipher = (ECCCipher *)cipherData;
        HANDLE phKeyHandle = NULL;
        unsigned int uiDataLength = 16 * 1024;
        BYTE  *pucData;
        BYTE  pucMAC[4] = {0x00};
	unsigned int puiMACLength;
        do {
                pucData = (BYTE *)malloc(uiDataLength + 1024);
        }while(!pucData);

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }  

	for(i = 0; i < numbers; i++)
        {
                ret = SDF_GenerateKeyWithIPK_ECC(hs, uiIPKIndex, uiKeyBits, cipher, &phKeyHandle);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret =  SDF_CalculateMAC(hs, phKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucMAC, &puiMACLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

        }
        free(pucData);
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        free(pucData);
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;	
}


int test_Hash(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
        unsigned int uiAlgID = SGD_SM3;
        unsigned char pucID[] = "1234567812345678";
	unsigned int uiIDLength = 16;
	unsigned char publicKeyData[128] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char cipherData[512] = {0x00};
        ECCCipher *cipher = (ECCCipher *)cipherData;
        HANDLE phKeyHandle = NULL;
        unsigned int uiDataLength = 16 * 1024;
        BYTE  *pucData;
        BYTE  pucHash[32] = {0x00};
	unsigned int puiHashLength = 32;
        do {
                pucData = (BYTE *)malloc(uiDataLength + 1024);
        }while(!pucData);

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {   
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }   

        for(i = 0; i < numbers; i++)
        {
		ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, pucPublicKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }  
                ret = SDF_HashInit(hs, uiAlgID, pucPublicKey, pucID, uiIDLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }    
		ret =  SDF_HashUpdate(hs, pucData, uiDataLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret =  SDF_HashFinal(hs, pucHash, &puiHashLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }   

        }   
        free(pucData);
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        free(pucData);
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_WriteFileAndReadFile(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
        unsigned int uiAlgID = SGD_SM3;
        unsigned int uiDataLength = 32 * 1024;
        BYTE  *pucData;
        BYTE  *pucBuffer;
        unsigned char pucFileName[129] = {0} ;
        unsigned int uiNameLen = 0;
	unsigned int uiOffset = 0;
        unsigned int puiFileLength = 1024;
	char szFileList[1024] = {0x00};
        unsigned int pulSize = 32;
	unsigned int uiFileSize = 32 * 1024;
        do {
                pucData = (BYTE *)malloc(uiDataLength + 1024);
                pucBuffer = (BYTE *)malloc(uiDataLength + 1024);
        }while(!pucData&&!pucBuffer);

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
				generateString(pucFileName, 128);
		ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

		ret = SDF_CreateFile(hs, pucFileName, strlen(pucFileName), uiFileSize);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_EnumFiles(hs, szFileList, &pulSize);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		      
                ret = SDF_WriteFile(hs, pucFileName, strlen(pucFileName), uiOffset, puiFileLength, pucData);

                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_ReadFile(hs, pucFileName, strlen(pucFileName), uiOffset, &puiFileLength, pucBuffer);

                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = memcmp(pucData, pucBuffer, puiFileLength);
		if(0 != ret)
                {
                        logret = __LINE__;
                        goto error;
                }
		ret =   SDF_DeleteFile(hs, pucFileName, strlen(pucFileName));
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }


        }
        free(pucData);
        free(pucBuffer);
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        free(pucData);
        free(pucBuffer);
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_TestSelf(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_TestSelf(hs);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_SVSGetKeyPoolState(int numbers)
{
	HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	unsigned char buffer[1024] = {0x00};
	KeyPoolStateInfo keyPoolStInfo;
		memset(&keyPoolStInfo,0,sizeof(keyPoolStInfo));
		

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_GetKeyPoolState(hs, &keyPoolStInfo);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}

int test_GetKEKPoolStatus(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0; 
        int i;
        unsigned char pucKEKStatus[1024] = {0x00};
	unsigned int puiMaxSize = 300;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {    
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret; 
        }    

        for(i = 0; i < numbers; i++) 
        {    
                ret = SDF_dmsPCI_GetKEKPoolState(hs, pucKEKStatus,&puiMaxSize);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }    

        }    

        ret = test_CloseDevice(hd, hs); 
        if (ret != SDR_OK)
                return ret; 
        return 0;

error:
        test_CloseDevice(hd, hs); 
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret; 

}



int test_ChangeCardPIN(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	char szOldPin[] = "dms123456";
	char szNewPin[] = "dms123456";

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_ChangeCardPIN(hs, szOldPin, szNewPin);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 

        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}


int test_ChangeKeyPIN(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	unsigned int index = 1;
        char szOldPin[] = "dms123456";
        char szNewPin[] = "dms123456";

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_ChangeKeyPIN(hs, index, szOldPin, szNewPin);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 

        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}


int test_SVSClearContainer(int numbers)
{       
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int uiKeyIndex = 1;
        
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {       
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }
        
        for(i = 0; i < numbers; i++)
        {       
                ret = SDF_dmsPCI_SVSClearContainer(hs, uiKeyIndex);
                if (SDR_OK != ret)
				{
                        logret = __LINE__;
                        goto error;
                }
        }
        
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:  
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_DeleteKEKAndGenerateKEK(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int KEKindex;
	unsigned int index = 1;
	unsigned int KEKBitLen = 128;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_GenerateKEK(hs, KEKBitLen, &KEKindex);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_dmsPCI_DeleteKEK(hs, index);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_dmsPCI_GenerateKEK(hs, KEKBitLen, &KEKindex);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }


        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}



int test_ImportKeyWithECCKeyPair(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	unsigned int uiAlgID = SGD_SM2_3;
        unsigned int uiKeyIndex = 1;
	unsigned int KeyLen = 256;
	ECCrefPublicKey pucPublicKey[2] = {0x00};
	unsigned int region = 1;
	unsigned char identify[] = "abcd1234";
	unsigned int identifyLen = strlen(identifyLen);
	unsigned char licenceIssuingauthority[] = "abcd1234";
	unsigned int licenceIssuingauthorityLen = strlen(licenceIssuingauthority);
        unsigned char takeEffectDate[] = "2020-10-09";
	unsigned int takeEffectDateLen = 10;
        unsigned char loseEffectDate[] = "2020-10-09"; 
	unsigned int loseEffectDateLen = 10;
        unsigned char * pTmpSignPublicKey = &pucPublicKey[0];
	unsigned char * pTmpEncPublicKey = &pucPublicKey[1];
	unsigned char buffer1[1024] = {0};
	CkiEnvelope * pEnv = (CkiEnvelope *)buffer1;
	unsigned char buffer2[1024] = {0};	
	EnvelopedKeyBlob * pSke = (EnvelopedKeyBlob*)buffer2;
	

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
		uiKeyIndex = i + 1;
		//ret = SDF_dmsPCI_SVSClearContainer(hs, uiKeyIndex);
        //        if(SDR_OK != ret){
        //                logret = __LINE__;
        //                goto error;
        //        }
                ret = SDF_dmsPCI_GenECCKeyPair(hs, uiKeyIndex, &pucPublicKey[0], &pucPublicKey[1]);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_dmsPCI_CalculatePersonKey(hs, region, identify, 
						licenceIssuingauthority,
						takeEffectDate,
						loseEffectDate,
						pTmpSignPublicKey, pTmpEncPublicKey,
						pEnv, pSke);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        	ret = SDF_dmsPCI_ImportKeyWithECCKeyPair(hs, uiKeyIndex, pSke);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}


int test_CalculatePubKeyAndIdentifyECCSignForEnvelope(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;

        unsigned int region = 0;
        unsigned char identify[] = "abcd1234";
        unsigned int identifyLen = 8;
		
		unsigned int uiAlgID = SGD_SM3;
		
        unsigned char signID[] = "1234567812345678";
		unsigned int signIDLen = 16;
		
		unsigned char  pucHash[32] = {0x00};
		unsigned int puiHashLength =32;
		
		unsigned char publicKeyData[1024] = {0x00};
        //ECCrefPublicKey pucPublicKey = {0};
		ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
		
		unsigned char pucData[] = "abcd1234";
		unsigned int uiDataLength = strlen(pucData);
		
		unsigned char pucSignature[1024] = {0x00};
        ECCSignature Signature = {0};

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_CalculatePubKey(hs, region, identify, identifyLen, pucPublicKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

                ret = SDF_HashInit(hs, uiAlgID, pucPublicKey, signID, signIDLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
 
				ret =  SDF_HashUpdate(hs, pucData, uiDataLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret =  SDF_HashFinal(hs, pucHash, &puiHashLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }   
				//printf_buffer(pucHash, 32, "pucHash");
				ret = SDF_dmsPCI_IdentifyECCSignForEnvelope(hs, region, 
							identify, identifyLen,
							signID, signIDLen,
							pucData, uiDataLength,
							pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				uiAlgID = SGD_SM2_1;
				ret = SDF_ExternalVerify_ECC(hs, uiAlgID, 
							pucPublicKey,
							pucHash, puiHashLength,
							pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_CalculatePubKey_OptimizeAndIdentifyECCSignForEnvelope_Optimize(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;

        unsigned int region = 0;
        unsigned char identify[] = "abcd1234";
        unsigned int identifyLen = 8;
		
		unsigned int uiAlgID = SGD_SM3;
		
        unsigned char signID[] = "1234567812345678";
		unsigned int signIDLen = 16;
		
		unsigned char  pucHash[32] = {0x00};
		unsigned int puiHashLength =32;
		
		unsigned char publicKeyData[1024] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
		
		unsigned char pucData[] = "abcd1234";
		unsigned int uiDataLength = strlen(pucData);
		
		unsigned char pucSignature[1024] = {0x00};
        

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_CalculatePubKey_Optimize(hs, region, identify, identifyLen, pucPublicKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

                ret = SDF_HashInit(hs, uiAlgID, pucPublicKey, signID, signIDLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
 
				ret =  SDF_HashUpdate(hs, pucData, uiDataLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret =  SDF_HashFinal(hs, pucHash, &puiHashLength);
				//printf_buffer(pucHash, 32, "pucHash");
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }   
				ret = SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize(hs, region, 
							identify, identifyLen,
							signID, signIDLen,
							pucData, uiDataLength,
							pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				uiAlgID = SGD_SM2_1;
				ret = SDF_ExternalVerify_ECC(hs, uiAlgID, 
							pucPublicKey,
							pucHash, puiHashLength,
							pucSignature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}



int test_InitAndGenerateMatrix(int numbers)
{       
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	int pciCardType = 2;
	char pin[] = "dms123456";
	unsigned int pinLen = 9;
        
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {       
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }       
        
        for(i = 0; i < numbers; i++)                    
        {       
                ret = SDF_dmsPCICardInit(hs, pciCardType, pin, pinLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_dmsPCI_PCICardGenerateMatrix(hs);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }
        
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:  
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}


int test_ExportPubMatrixAndImportPubMatrix(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        int pciCardType = 2;
        char pin[] = "dms123456";
        unsigned int pinLen = 9;
        unsigned char pbPubMatrix[32788] = {0x00};
        unsigned int ulMatLen = 32788;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        { 
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
		ret = SDF_dmsPCICardInit(hs, pciCardType, pin, pinLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_dmsPCI_PCICardGenerateMatrix(hs);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_dmsPCI_ExportPubMatrix(hs, pbPubMatrix, &ulMatLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_dmsPCICardInit(hs, pciCardType, pin, pinLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		printf("ulMatLen is %d \n", ulMatLen);
		ret = SDF_dmsPCI_ImportPubMatrix(hs, pbPubMatrix, ulMatLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }

        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}


int test_Generate_PKIKeyPair(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
        unsigned int index = 1;
        unsigned int keyFlag = 3;
        unsigned char publicKeyData[132] = {0x00};
        ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)publicKeyData;
        unsigned char privateKeyData[68] = {0x00};
        ECCrefPrivateKey *pucPrivateKey = (ECCrefPrivateKey *)privateKeyData;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }
        
	for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsGenerate_PKIKeyPair(hs, i + 1, keyFlag);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_BackupAndRecovery(int numbers)
{       
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i,j,k;
	unsigned int pciCardType = 2;
	int sgmNum = 2;
	char pin[] = "dms123456";
	unsigned int pinLen = 9;
	unsigned char userPin[] = "abcd1234";
	unsigned int userPinLen = 8;
	unsigned int flag = 1;
	unsigned int index = 1;
	//unsigned char SegKey[2][102400] = {0};
	unsigned int SegKeyLen;
        
        unsigned char *SegKey = (unsigned char *)malloc(30*1024*1024*sgmNum);
        if(NULL == SegKey){
                return SDR_NOBUFFER;
        }

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if(ret != SDR_OK)
        {       
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                free(SegKey);
                return ret;
        }
        
        for(i = 0; i < numbers; i++)
        {       
		ret = SDF_dmsPCI_SegMentKeyInit(hs, sgmNum, pin, pinLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }    

		for(j = 0; j < sgmNum; j++)
		{
			ret = SDF_dmsPCI_GetSegMentKey(hs, userPin, userPinLen, &SegKeyLen, SegKey + j*30*1024*1024);
                	if (SDR_OK != ret) {
                        	logret = __LINE__;
                        	goto error;
                	}	
		}
		ret = SDF_dmsPCI_SegMentKeyFinal(hs);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }    
		ret =  SDF_dmsPCI_KeyRecoveryInit(hs);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		for(k = 0; k < sgmNum; k++)
		{
			ret = SDF_dmsPCI_ImportSegmentKey(hs, userPin, userPinLen,  SegKey + k*30*1024*1024 , SegKeyLen);
	                if (SDR_OK != ret) {
        	                logret = __LINE__;
                	        goto error;
                	}
		}
		ret = SDF_dmsPCICardInit(hs, pciCardType, pin, pinLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_dmsPCI_KeyRecovery(hs, sgmNum);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }
        
        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
        {
                free(SegKey);
                return ret;
        }
        free(SegKey);
        return 0;

error:  
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        free(SegKey);
        return ret;

}


int test_BackupAndRecoveryThreshold(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i,j,k,m;
	unsigned int uiAlgID = SGD_SM2_3;
	unsigned int uiKeyIndex = 1;
        ECCrefPublicKey pucPublicKey[1] = {0};
	ECCrefPublicKey pubKey[1] = {0};
	unsigned char pCipherKey[5][196] = {0};
	unsigned char pNewCipherKey[5][196] = {0};
	unsigned int pCipherKeyLen;
	unsigned int pNewCipherKeyLen;
        unsigned int pciCardType = 2;
        int sgmNum = 5;
	int recoverNum = 3;
        char pin[] = "dms123456";
        unsigned int pinLen = 9;
	unsigned char pucPassword[] = "dms123456";
	unsigned int uiPwdLength = 9;
        unsigned int index = 0;
        unsigned int puiPciDataLen = 0;

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if(ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }
		//获取全密钥的长度
		ret = SDF_dmsPCI_Backup_Threshold(hs, 0, 0, 0, NULL, NULL, &puiPciDataLen);
		if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
        }
		unsigned char *pucPciData = (unsigned char *)malloc(puiPciDataLen);
		

        for(i = 0; i < numbers; i++)
        {       
				ret = SDF_dmsPCI_Backup_Threshold(hs, sgmNum, recoverNum, pinLen, pin, pucPciData, &puiPciDataLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, pucPublicKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                for(j = 0; j < sgmNum; j++)
                {       
                        ret = SDF_dmsPCI_ExportSegmentKey_Threshold(hs, pucPublicKey, &pCipherKey[j], &pCipherKeyLen);
                        if (SDR_OK != ret) {
                                logret = __LINE__;
                                goto error;
                        }
                }
                ret =  SDF_dmsPCI_GetEncPubKey_Threshold(hs, pubKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
		for(k = 0; k < sgmNum; k++)
		{
                	ret = SDF_ExchangeDigitEnvelopeBaseOnECC(hs, uiKeyIndex, uiAlgID, pubKey, &pCipherKey[k], &pNewCipherKey[k]);
                	if (SDR_OK != ret) {
                        	logret = __LINE__;
                        	goto error;
                	}
		}
                for(m = 0; m < recoverNum; m++)
                {		
                        ret = SDF_dmsPCI_ImportSegmentKey_Threshold(hs, &pNewCipherKey[m], pCipherKeyLen);
                        if (SDR_OK != ret) {
                                logret = __LINE__;
                                goto error;
                        }
                }
                ret = SDF_dmsPCICardInit(hs, pciCardType, pin, pinLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
                ret = SDF_dmsPCI_Restore_Threshold(hs, recoverNum, pucPciData, puiPciDataLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}


int test_GetAndReleasePriMatrixAccessRight(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	int uiKeyIndex = 1;
	unsigned char pucPassword[] = "dms123456";
		char szOldPin[] = "dms123456";
		char szNewPin[] = "dms123456";
	unsigned int uiPwdLength = 9;
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
                ret = SDF_dmsPCI_GetPriMatrixAccessRight(hs, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_dmsPCI_ReleasePriMatrixAccessRight(hs);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret =  SDF_dmsPCI_ChangePriMatrixPIN(hs, szOldPin, szNewPin);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_NoCert(int numbers)
{
		HANDLE hd;
        HANDLE hs;
			
        int ret, logret = 0;
        int i;
		unsigned int uiAlgID = SGD_SM2;
		unsigned int uiKeyBits =256;
        unsigned int uiKeyIndex = 1;
		unsigned char pbPubMatrix[32788] = {0x00};
        unsigned int ulMatLen = 0;
		unsigned char Hiki[32] = {0};
		unsigned char ZA[32] = {0};
		unsigned int ZA_Len = 0;
		unsigned char random[25] = {0};
		unsigned char id[64] = {0};
		unsigned int id_len = 64;
		unsigned char temp_result[32] = {0};
		unsigned char buffer1[132] = {0};
		unsigned char buffer2[132] = {0};						  
		unsigned char buffer3[68] = {0};
		unsigned char buffer4[68] = {0};
		unsigned char buffer5[128] = {0};
		unsigned char buffer6[132] = {0};
		unsigned char buffer7[64] = {0};
		unsigned char buffer8[64] = {0};
		unsigned char buffer9[1024] = {0};
		unsigned char buffer10[68] = {0x00};
		unsigned char buffer11[64] = {0};
		EccPoint *pkxEccPoint = buffer7;
		EccPoint *pkyEccPoint = buffer8;

		ECCrefPublicKey *pkx = (ECCrefPublicKey *)buffer1;
		ECCrefPublicKey *pky = (ECCrefPublicKey *)buffer2;
		ECCrefPrivateKey *xID = (ECCrefPrivateKey *)buffer3;
		ECCrefPrivateKey *yID = (ECCrefPrivateKey *)buffer4;
		ECCSignature *signature = (ECCSignature *)buffer5;
		ECCrefPublicKey *pa = (ECCrefPublicKey *)buffer6;
		ECCrefPublicKey pkc;
		unsigned char pcbEncryptedPriKey[1024] = {0};	
		unsigned int pcbEncryptedPriKeyLen = 0;
		unsigned char sesskey[16] = {0};
		unsigned int len = 0;
		ECCrefPrivateKey *pkcID = (ECCrefPrivateKey *)buffer10;
		unsigned char ds1[32] = {0};
		unsigned char ds[32] = {0};
		unsigned char m[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
		unsigned char e[32] = {0};
		unsigned int eLength = 0;
		ECCCipher *pCipherKey = buffer9;
		unsigned char k[32] = {0};
		EccPoint *R = (EccPoint *)buffer11;
		unsigned char r[32] = {0};
		unsigned char a[32] = {0};
		unsigned temp_result1[32] = {0};
		unsigned char s[32] = {0};
		
		
        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {		
				//模拟用户端产生200bits随机数, 计算Pkx = [xID]G
				ret = SDF_GenerateRandom(hs, 25, random);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				memset(xID->K + 32, 0 ,7);
				memcpy(xID->K + 39, random, 25);
				ecc_k_mult_G(xID->K + 32, pkxEccPoint);
				pkx->bits = 256; 
				memcpy(pkx->x+32, pkxEccPoint->x, 32);
				memcpy(pkx->y+32, pkxEccPoint->y, 32);
				//PrintData("pkx.x", pkx->x, 64, 32);
				//PrintData("pkx.y", pkx->y, 64, 32);
								
				//随机产生64字节标识长度
				ret = SDF_GenerateRandom(hs, 64, id);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//模拟终端保护公钥pkc pkc = [pkcID]G
				ret = SDF_GenerateKeyPair_ECC(hs, SGD_SM2, uiKeyBits, &pkc, pkcID);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//(服务端)无证书合成并加密导出部分签名私钥，输出部分签名私钥密文pcbEncryptedPriKey，部分签名公钥pa
				ret = SDF_dmsPCI_GenPartSignPri_NoCert(hs, id, pkx, &pkc, pcbEncryptedPriKey, &pcbEncryptedPriKeyLen, pCipherKey, pa);
				//PrintData("pa.x", pa->x, 64, 32);
				//PrintData("pa.y", pa->y, 64, 32);
				//PrintData("pcbEncryptedPriKey", pcbEncryptedPriKey, pcbEncryptedPriKeyLen, 32);
                if (SDR_OK != ret) {
                        logret = __LINE__;
						PrintData("id", id, 64, 32);
                        goto error;
                } 
				//**********************(用户端)合成签名密钥************************
				// SM2解密得会话密钥明文
				ret = SDF_ExternalDecrypt_ECC(hs, SGD_SM2_3, pkcID, pCipherKey, sesskey, &len);
				//PrintData("sesskey", sesskey, 16, 16);
				if(SDR_OK != ret){
						logret = __LINE__;
                        goto error;
				} 
				//解密得服务端部分签名私钥ds1
				SM4DeCryptnGroup(pcbEncryptedPriKey, 32, ds1, sesskey);   
				//PrintData("ds1", ds1, 32, 32);
				//(用户端)模加合成签名私钥 ds = xID + ds'
				ecc_mod_add(ds, xID->K +32, ds1);
				
				//**********************用户端签名************************
				//计算ZA和e
                ret = SDF_dmsPCI_ExportPubMatrix(hs, pbPubMatrix, &ulMatLen);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				sm3(pbPubMatrix, ulMatLen, Hiki);
				//PrintData("Hiki", Hiki, 32, 32);
				if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = Get_ZA(id, strlen(id), Hiki, 32, ZA, &ZA_Len);
				//PrintData("ZA", ZA, 32, 32);
				if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				
				ret = Get_e(ZA, pa->x+32, pa->y+32, m, 8, e, &eLength);
				//PrintData("e", e, 32, 32);
				if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//终端无证书计算签名值r，s
				ret = SDF_GenerateRandom(hs, 32, k);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//R = [k]G = (xR, yR)
				ecc_k_mult_G(k, R);
				//计算签名分量r = (e + xR) mod q
				ecc_mod_add(r, e, R->x);
				//计算签名分量s = (ds + 1)^(-1)(k - r*ds) mod q
				
				memset(a+31, 1, 1);
				ecc_mod_add(temp_result, ds, a);
				ecc_mod_inv(temp_result, temp_result);
				ecc_mod_mult(temp_result1, r, ds);
				ecc_mod_sub(temp_result1, k, temp_result1);
				ecc_mod_mult(s, temp_result, temp_result1);
				//PrintData("r", r, 32, 32);
				//PrintData("s", s, 32, 32);
				//服务端验证无证书签名
				memcpy(signature->r + 32, r, 32);
				memcpy(signature->s + 32, s, 32);
				ret = SDF_dmsPCI_VerifySignedData_NoCert(hs, id, m, 8, pa, signature);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 

        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}



int test_MK(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
		unsigned int uiAlgID = SGD_SM2;
		unsigned int region = 1;
		unsigned int uiKeyIndex = 1;
		unsigned int uiKeyBits = 256;
		unsigned char pucPassword[] = "dms123456";
		unsigned int uiPwdLength = 9;
		const char pcIdentity[] = {"abcd1234"};
		const char pcLicenceIssuingAuthority[] = {"ahdms"};
		const char pcTakeEffectDate[] = {"20220209"};
		const char pcLoseEffectDate[] = {"20240209"};
		unsigned int uiDataLength = 32;
        unsigned char pucData[32] = {0x00};
		unsigned char cipherBuffer[1024] = {0x00};
        ECCCipher *pucEncData = (ECCCipher *)cipherBuffer;
		unsigned char publicKeyData1[256] = {0x00};
        ECCrefPublicKey *pks = (ECCrefPublicKey *)publicKeyData1;
		unsigned char publicKeyData2[256] = {0x00};
        ECCrefPublicKey *pkx = (ECCrefPublicKey *)publicKeyData2;
		unsigned char publicKeyData3[256] = {0x00};
        ECCrefPublicKey *pkxy = (ECCrefPublicKey *)publicKeyData3;
        unsigned char privateKeyData[256] = {0x00};
        ECCrefPrivateKey *xID = (ECCrefPrivateKey *)privateKeyData;
		unsigned char privateKeyData1[256] = {0x00};
        ECCrefPrivateKey *d1 = (ECCrefPrivateKey *)privateKeyData1;
		unsigned char buffer11[1024] = {0x00};
		EnvelopedKeyBlob *pEncY_By_Pks = buffer11;
		unsigned char buffer22[1024] = {0x00};
		EnvelopedKeyBlob *pOutEncD1ByPkx = buffer22;
		unsigned char buffer33[1024] = {0x00};
		EnvelopedKeyBlob *pOutEncD2ByPky = buffer33;
		unsigned char buffer44[1024] = {0x00};
		EnvelopedKeyBlob *pOutEncD2_By_Pks = buffer44;
		unsigned char buffer55[1024] = {0x00};
		EnvelopedKeyBlob *pOutEncD4_By_Pks = buffer55;
		CkiEnvelope pEnv;
		ECCrefPublicKey pOutd3G, pPubKey_c1, pOutPubKey_t1;	
		unsigned char buffer1[256] = {0x00};
		ECCrefPublicKey *pucPublicKey = (ECCrefPublicKey *)buffer1;
		unsigned char buffer2[32] = {0x00};
		unsigned char *e = buffer2; 
		unsigned int e_len = 32;
		unsigned char buffer3[256] = {0x00};
		ECCrefPublicKey *R1 = (ECCrefPublicKey *)buffer3;
		unsigned char buffer4[256] = {0x00};
		ECCrefPrivateKey *k1 = (ECCrefPrivateKey *)buffer4;
		unsigned char r[32] = {0x00};
		unsigned char s1[32] = {0x00};
		unsigned char s2[32] = {0x00};
		unsigned int r_len = 0, s1_len = 0, s2_len = 0;
		unsigned char sesskey[16] = {0};
		unsigned int len = 0;
		unsigned char random[32] = {0};
		unsigned char temp_result[32] = {0};
		ECCrefPrivateKey d3 = {.bits = 256};
		ECCSignature signature = {{0}, {0}};
		
		printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {
				ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, pks);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }  
                //产生(私钥xID,公钥pkx) pkx = [xID]G
				ret = SDF_GenerateKeyPair_ECC(hs, uiAlgID, uiKeyBits, pkx, xID);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//产生 yID、PKy(协同计算平台) pky = [yID]G, pkxy = [yID]pkx
				ret = SDF_dmsPCI_Generate_pky(hs, pks, pkx, pEncY_By_Pks, pkxy);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				
				/* 根据标识计算用户密钥对，并导出d1、d2分量(IKI平台)、pEnv证书结构(IKI信封数据结构)
				   1、pEncY_By_Pks为(yID, PKy)密钥对保护结构，其中pEncY_By_Pks.PubKey = pky, 用索引号1位置公钥进行加密保护； 
				   2、CkiEnvelope pEnv可信标识结构里面包含PKE, PKS；
				   3、pOutEncD1ByPkx，终端加密分量d1密钥对保护结构；(xID, pkx)
				   4、pOutEncD2ByPky，协端加密分量d2密钥对保护结构；(yID, pky)
				typedef struct DMS_ENVELOPEDKEYBLOB {
														unsigned long ulAsymmAlgID;				//保护对称密钥的非对称算法标识 SGD_SM2_3
														unsigned long ulSymmAlgID;				//对称算法标识 必须ECB模式
														ECCPUBLICKEYBLOB PubKey;                //加密密钥对 公钥
														unsigned char cbEncryptedPrivKey [64];  //加密密钥对 私钥密文
														ECCCipher ECCCipehrBlob;                //对称密钥 密文
													} EnvelopedKeyBlob, *PEnvelopedKeyBlob
					签名密钥SKS = d3*d4-1 mod n
					PKE = [SKE]G
					PKS = [d2]pkxy + [SKE]Pky - G
					SKE = d1*d2
					d3 = xID+d1    d4 = yID*d2
					d1:终端加密密钥分量, d2:云端加密密钥分量, d3:终端签名密钥分量, d4:云端签名密钥分量
				*/
				ret = SDF_dmsPCI_CalculateCooperateKey(hs, region, pcIdentity, pcLicenceIssuingAuthority, pcTakeEffectDate, pcLoseEffectDate,
													   pkx, pkxy, &(pEncY_By_Pks->PubKey), &pEnv, pOutEncD1ByPkx, pOutEncD2ByPky, &pOutd3G);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//由pky保护的d2密钥对保护结构转换成index对应的内部公钥保护结构 d4 = yID*d2
				ret = SDF_dmsPCI_CalculateD4(hs, uiKeyIndex, pEncY_By_Pks, pOutEncD2ByPky, pOutEncD2_By_Pks, pOutEncD4_By_Pks);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//产生随机加密数据
				ret = SDF_GenerateRandom(hs, uiDataLength, pucData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				uiAlgID = SGD_SM2_3;
				pucPublicKey->bits = 256;
				memcpy(pucPublicKey->x, (pEnv.enve.pke + 4), 64);
				memcpy(pucPublicKey->y, (pEnv.enve.pke + 68), 64);
				//采用IKI信封pEnv结构中的pke对产生的随机数据进行SM2加密 
				ret = SDF_ExternalEncrypt_ECC(hs, uiAlgID, pucPublicKey, pucData, uiDataLength, pucEncData);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				pPubKey_c1.bits = 256;
				memcpy(pPubKey_c1.x, pucEncData->x, 64);
				memcpy(pPubKey_c1.y, pucEncData->y, 64);
				//T1 = d2*C1
				ret = SDF_dmsPCI_CopDecrypt(hs, uiKeyIndex, pOutEncD2_By_Pks, &pPubKey_c1, &pOutPubKey_t1);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//PrintData("T1.X", pOutPubKey_t1.x, 64, 32);
				//PrintData("T1.Y", pOutPubKey_t1.y, 64, 32);
				// 解密得d1
				ret = SDF_ExternalDecrypt_ECC(hs, SGD_SM2_3, xID, &pOutEncD1ByPkx->ECCCipehrBlob, sesskey, &len);
				if(SDR_OK != ret){
						logret = __LINE__;
                        goto error;
				} 
				SM4DeCryptnGroup(pOutEncD1ByPkx->cbEncryptedPrivKey, 32, d1->K + 32, sesskey);   
				/* 外部私钥解密 */
				memcpy(pucEncData->x, pOutPubKey_t1.x, 64);
				memcpy(pucEncData->y, pOutPubKey_t1.y, 64);    
				memset(random, 0, 32);
				d1->bits = 256;
				//终端解密
				//PrintData("d1", d1->K, 64, 32);
				ret = SDF_ExternalDecrypt_ECC(hs, SGD_SM2_3, d1, pucEncData, random, &len);
				if(ret != SDR_OK){
						logret = __LINE__;
                        goto error;
				} 
				ret = memcmp(pucData, random, 32);
				if(0!=ret){
						printf("decrypt data is different from encrypt data!");
						logret = __LINE__;
                        goto error;
				}
				/***************************协同签名开始******************************/
				//产生随机签名数据
				ret = SDF_GenerateRandom(hs, e_len, e);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//终端产生临时公私钥对R1 = [k1]G
				ret = SDF_GenerateKeyPair_ECC(hs, SGD_SM2, uiKeyBits, R1, k1);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				/*协同端, 产生随机数k3, k4, R2=[k3k4]G
				  (x1,y1)=[k4]R1+R2, 
				  r=e+x1(mod n)
				  s1 = k4*d4^1(mod n)
				  s2 = k3*d3^1(mod n)
				  协同端返回r, s1, s2
				*/
				ret = SDF_dmsPCI_CopSign(hs, uiKeyIndex, e, e_len, R1, pOutEncD4_By_Pks,
										 r, &r_len, s1, &s1_len, s2, &s2_len);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				//解密得d1
				ret = SDF_ExternalDecrypt_ECC(hs, SGD_SM2_3, xID, &pOutEncD1ByPkx->ECCCipehrBlob, sesskey, &len);
				if(ret != SDR_OK){
						logret = __LINE__;
                        goto error;
				}
				SM4DeCryptnGroup(pOutEncD1ByPkx->cbEncryptedPrivKey, 32, d1->K + 32, sesskey); 
				//模加运算计算终端签名私钥分量d3 = xID+d1
				ecc_mod_add(d3.K + 32, d1->K + 32, xID->K + 32);
				//终端计算签名值, s = d3^(-1)*s1*(k1+s2) - r
				ecc_mod_add(temp_result, k1->K + 32, s2);
				ecc_mod_mult(temp_result, s1, temp_result);
				ecc_mod_inv(d3.K, d3.K + 32);
				ecc_mod_mult(temp_result, d3.K, temp_result);
				ecc_mod_sub(temp_result, temp_result, r);
				memcpy(signature.r + 32, r, 32);
				memcpy(signature.s + 32, temp_result, 32);
				
				//签名公钥验签, 提取pEnv.enve.pks对数据进行验签
				memcpy(pucPublicKey->x, (pEnv.enve.pks + 4), 64);
				memcpy(pucPublicKey->y, (pEnv.enve.pks + 68), 64);
				ret = SDF_ExternalVerify_ECC(hs, SGD_SM2_1, pucPublicKey, e, 32, &signature);
				if(ret != SDR_OK){
						logret = __LINE__;
                        goto error;
				}  
			
		}
		ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;
				

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;
}


int test_ExchangeDigitEnvelopeKeyBlob(int numbers)
{
        HANDLE hd;
        HANDLE hs;
        int ret, logret = 0;
        int i;
	unsigned int uiAlgID = SGD_SM2;
        unsigned int uiKeyIndex = 1;
	unsigned int KeyLen = 256;
	ECCrefPublicKey pucPublicKey[2] = {0x00};
	unsigned int region = 1;
	unsigned char identify[] = "abcd1234";
	unsigned int identifyLen = strlen(identifyLen);
	unsigned char licenceIssuingauthority[] = "abcd1234";
	unsigned int licenceIssuingauthorityLen = strlen(licenceIssuingauthority);
        unsigned char takeEffectDate[] = "2020-10-09";
	unsigned int takeEffectDateLen = 10;
        unsigned char loseEffectDate[] = "2020-10-09"; 
	unsigned int loseEffectDateLen = 10;
    unsigned char *pTmpSignPublicKey = &pucPublicKey[0];
	unsigned char *pTmpEncPublicKey = &pucPublicKey[1];
	unsigned char buffer1[1024] = {0};
	CkiEnvelope *pEnv = (CkiEnvelope *)buffer1;
	unsigned char buffer2[1024] = {0};	
	EnvelopedKeyBlob *pSke = (EnvelopedKeyBlob*)buffer2;
	EnvelopedKeyBlob pEncByExternalPk;
	ECCrefPublicKey pExternalPk;
	ECCrefPrivateKey pucPrivateKey;
	
	unsigned char pucPassword[] = "dms123456";
	unsigned int uiPwdLength = 9;
	

        printf("[%s]\n", __FUNCTION__);
        ret = test_OpenDevice(&hd, &hs);
        if (ret != SDR_OK)
        {
                pciCunitTestWriteLog(PCIERR_DM_OPENDEVICE, ret, __FUNCTION__);
                return ret;
        }

        for(i = 0; i < numbers; i++)
        {		
				  
                ret = SDF_ExportSignPublicKey_ECC(hs, uiKeyIndex, &pucPublicKey[0]);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }  
				ret = SDF_ExportEncPublicKey_ECC(hs, uiKeyIndex, &pucPublicKey[1]);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 
				ret = SDF_dmsPCI_CalculatePersonKey(hs, region, identify, 
						licenceIssuingauthority,takeEffectDate, loseEffectDate,
						pTmpSignPublicKey, pTmpEncPublicKey,
						pEnv, pSke);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GenerateKeyPair_ECC(hs, uiAlgID, 256, &pExternalPk, &pucPrivateKey);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret = SDF_GetPrivateKeyAccessRight(hs, uiKeyIndex, pucPassword, uiPwdLength);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                }
				ret =  SDF_dmsPCI_ExchangeDigitEnvelopeKeyBlob(hs, uiKeyIndex, pSke, &pExternalPk, &pEncByExternalPk);
                if (SDR_OK != ret) {
                        logret = __LINE__;
                        goto error;
                } 
        }

        ret = test_CloseDevice(hd, hs);
        if (ret != SDR_OK)
                return ret;
        return 0;

error:
        test_CloseDevice(hd, hs);
        pciCunitTestWriteLog(logret, ret, __FUNCTION__);
        return ret;

}