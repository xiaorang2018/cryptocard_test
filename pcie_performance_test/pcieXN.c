#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "libPciGUOMI.h"

//全局变量
void *hDeviceHandle = NULL;
void *hSessionHandle = NULL;
pthread_mutex_t mutex;

unsigned long getFileSize(const char *path)
{
	unsigned long filesize = 0;
	struct stat statbuff;
	if (stat(path, &statbuff) < 0)
	{
		return 0;
		 
	}
	else
	{
		filesize = statbuff.st_size;
	}

	dmsdebug("getFileSize:%lu\n", filesize);
	return filesize;
}

void tostr(unsigned char *source, char *result, unsigned int len)
{

	static char Tab[17] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	memset(result,0,len*2);
	unsigned int i=0;
	for( i=0;i<len;i++)
	{

		result[i*2] = Tab[ source[i]>>4 ];

		result[i*2+1] = Tab[source[i] & 0x0F ];

	}

}

void *sign(void *arg)
{
	pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
	unsigned int ulRes, j, resLen;
	unsigned int uiISKIndex = 1;
	unsigned int xnTime = 0;
	char data[1024*16]={0};
	unsigned int dataLen= 0;
	unsigned char Hash[32];
	memset(Hash,0x11,sizeof(Hash));
	unsigned char pucIV[16] = {0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00,0X00};
	unsigned char pucData[1024] = {0};
	unsigned char result[2048] = {0};
	unsigned char cipher[2048] =  {0};
	unsigned char pucPassword[]= "dms123456";
	ECCSignature pucSignature;
	ECCrefPublicKey testPubKey;
	struct timeval begin,end;
	unsigned char buff[64 * 1024];
	ulRes = SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, &testPubKey);
    	if(ulRes != SDR_OK)
    	{
        	printf("SDF_ExportSignPublicKey_ECC error, errno is %02x\n",ulRes);
    	}
	ulRes = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword, 9);
    	if(ulRes != SDR_OK)
    	{
        	printf("GetPrivateKeyAccessRight error, errno is %02x\n",ulRes);
    	}
    	for(j = 0; j < testnum; j++)
    	{
        	gettimeofday( &begin, NULL );
        	ulRes = SDF_InternalSign_ECC(hSessionHandle, 1, Hash, 32, &pucSignature);
        	gettimeofday( &end, NULL );
        	xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
					
        	if(ulRes != 0)
        	{
            		printf("SDF_InternalSign_ECC fail!ret = %02x\n", ulRes);
            		continue;
        	}

        	if (!(j % 100))
        	{
            		printf("·");
            		fflush(stdout);
        	} 
    	}

	printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
	xnTime = 0;
	pthread_mutex_unlock(&mutex);
    
}

void *verify(void *arg)
{
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
        unsigned int uiISKIndex = 1;
        unsigned int xnTime = 0;
        char data[1024*16]={0};
        unsigned int dataLen= 0;
        unsigned char Hash[32] = {0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                		  0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a};
        unsigned char pucPassword[]= "dms123456";
        ECCSignature pucSignature;
        ECCrefPublicKey testPubKey;
        struct timeval begin,end;
        
	ulRes = SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, &testPubKey);
        if(ulRes != SDR_OK)
        {
                printf("SDF_ExportSignPublicKey_ECC error, errno is %02x\n",ulRes);
        }
        ulRes = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword, 9);
        if(ulRes != SDR_OK)
        {
                printf("GetPrivateKeyAccessRight error, errno is %02x\n",ulRes);
        }
	ulRes = SDF_InternalSign_ECC(hSessionHandle, 1, Hash, 32, &pucSignature);
	if(ulRes != 0)
        {
                printf("SDF_InternalVerify_ECC fail!ret = %02x\n", ulRes);
        }
        for(j = 0; j < testnum; j++)
        {
                gettimeofday( &begin, NULL );
		ulRes = SDF_InternalVerify_ECC(hSessionHandle, uiISKIndex, Hash, 32, &pucSignature);
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;

                if(ulRes != 0)
                {
                        printf("SDF_InternalVerify_ECC fail!ret = %02x\n", ulRes);
                        continue;
                }

                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }

        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
}

void *calculatePersonKey(void *arg)
{
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned char identify[25] = "ahdms";
        unsigned int identifyLen = 20;
        unsigned char tmpidentify[20] = {0};
        unsigned int tmpidentifyLen = 20;
        char takeEffDate[20] = {0};
        char loseEffDate[20] = {0};
        char takeEffectDate[]="2020-3-9";
        char loseEffectDate[]="2020-3-9";
        unsigned int takeEffectDateLen = strlen(takeEffectDate);
        unsigned int loseEffectDateLen = strlen(loseEffectDate);
        char *licenceIssuingauthority="zhongguodimansen";
        unsigned int licenseIssuingauthorityLen=strlen(licenceIssuingauthority);

        unsigned char pke[1024*4];
        unsigned int pkeLen;
        unsigned char pks[1024*4];
        unsigned int pksLen;
        unsigned char ske[1024*4];
        unsigned int skeLen;
        unsigned int xnTime = 0;
        char data[1024*16]={0};
        ECCrefPublicKey testPubKey;
	ECCrefPublicKey pubs[5];
        struct timeval begin,end;

        ulRes = SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, &testPubKey);
        if(ulRes != SDR_OK)
        {       
                printf("SDF_ExportSignPublicKey_ECC error, errno is %02x\n",ulRes);
        }
	memcpy(&pubs[0], &testPubKey, sizeof(ECCrefPublicKey));
        memcpy(&pubs[1], &testPubKey, sizeof(ECCrefPublicKey));
        
	for(j = 0; j < testnum; j++)
        {
                ulRes = SDF_GenerateRandom(hSessionHandle, tmpidentifyLen, tmpidentify);
                if(ulRes != SDR_OK)
                {
                	dmsdebug("SDF_GenerateRandom, error is %02x\n", ulRes);
                        break;
                 }
		if(strlen(identify) == 0)
		{
			strcat(identify,tmpidentify);
		}

		gettimeofday( &begin, NULL );
                ulRes= dmsPCI_CalculatePersonKey(hSessionHandle, 0,
                                                identify, 25,
                                                licenceIssuingauthority, licenseIssuingauthorityLen,
                                                takeEffectDate, takeEffectDateLen,
                                                loseEffectDate, loseEffectDateLen,
                                                (unsigned char *)pubs, sizeof(ECCrefPublicKey)*2,
						pke, &pkeLen,
                                                pks, &pksLen,
                                                ske, &skeLen);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("CalculatePersonKey fail!ret = %02x\n", ulRes);
                        continue;
                }

                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }

        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
}

void *externalVerify(void *arg)
{
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
        unsigned int xnTime = 0;
        unsigned char Hash[32] = {0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                                  0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a};
        unsigned char pucPassword[]= "dms123456";
        ECCSignature pucSignature;
        ECCrefPublicKey testPubKey;
        struct timeval begin,end;

        ulRes = SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, &testPubKey);
        if(ulRes != SDR_OK)
        {
                printf("SDF_ExportSignPublicKey_ECC error, errno is %02x\n",ulRes);
        }
        ulRes = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword, 9);
        if(ulRes != SDR_OK)
        {
                printf("GetPrivateKeyAccessRight error, errno is %02x\n",ulRes);
        }
        ulRes = SDF_InternalSign_ECC(hSessionHandle, 1, Hash, 32, &pucSignature);
        if(ulRes != 0)
        {
                printf("SDF_InternalVerify_ECC fail!ret = %02x\n", ulRes);
        }
        for(j = 0; j < testnum; j++)
        {
                gettimeofday( &begin, NULL );
                ulRes = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &testPubKey, Hash, 32, &pucSignature);
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		if(ulRes != 0)
                {
                        printf("SDF_ExternalVerify_ECC fail!ret = %02x\n", ulRes);
                        continue;
                }

                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }

        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
}

void *externalEncrypt(void *arg)
{
        pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
        unsigned int ulRes, j;
        ECCrefPublicKey encPubKey;
	unsigned char encData[180] = {0};
	ECCCipher * pucEncData = encData;
	unsigned char Hash[32] = {0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                                  0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a};
	unsigned int xnTime = 0;
        struct timeval begin,end;

        ulRes = SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, &encPubKey);
        if(ulRes != SDR_OK)
        {
                printf("SDF_ExportEncPublicKey_ECC error, errno is %02x\n",ulRes);
        }
	for(j = 0; j < testnum; j++)
        {       
                
                gettimeofday( &begin, NULL );
                ulRes = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &encPubKey, Hash, 16, pucEncData); 
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
                
                if(ulRes != 0)
                {       
                        printf("SDF_ExternalEncrypt_ECC fail!ret = %02x\n", ulRes);
                        continue;
                }
                
                if (!(j % 100))
                {       
                        printf("·");
                        fflush(stdout);
                }
        }

        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
	
}

void *internalDecrypt(void *arg)
{
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j;
	void *symKeyHandle = NULL;
	void *hKeyHandle = NULL;
	unsigned char buff[512] = {0};
	unsigned char pucPassword[]= "dms123456";
	ECCCipher *pCipherKey = buff;
	unsigned int xnTime = 0;
	unsigned int uiISKIndex =1;
        struct timeval begin,end;

	ulRes = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiISKIndex, 128, pCipherKey, &symKeyHandle);
        if(ulRes != SDR_OK)
        {
                printf("SDF_GenerateKeyWithIPK_ECC error, errno is %02x\n",ulRes);
        }
	ulRes = SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword, 9);
        if(ulRes != SDR_OK)
        {       
                printf("GetPrivateKeyAccessRight error, errno is %02x\n",ulRes);
        }

        for(j = 0; j < testnum; j++)
        {
                 
                gettimeofday( &begin, NULL );
                ulRes = SDF_ImportKeyWithISK_ECC(hSessionHandle, uiISKIndex, pCipherKey, &hKeyHandle);
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;

                if(ulRes != 0)
                {
                        printf("SDF_ImportKeyWithISK_ECC fail!ret = %02x\n", ulRes);
                        continue;
                }
		ulRes = SDF_DestroyKey(hSessionHandle, hKeyHandle);
	        if(ulRes != 0)
        	{       
                 	printf("SDF_DestroyKey fail!ret = %02x\n", ulRes);
	        }
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_DestroyKey(hSessionHandle, symKeyHandle);
        if(ulRes != 0)
        {
                printf("SDF_DestroyKey fail!ret = %02x\n", ulRes);
        }

        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
	
}

void *sm4Encrypt(void *arg)
{
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j;
        void *symKeyHandle = NULL;

	unsigned char *pucIndata = NULL;
        unsigned int nEncInSize = 1024 * 128;
	pucIndata = malloc(nEncInSize);
	unsigned char *pucEncOutData = NULL;
        unsigned int nEncOutLen = 1024 * 128;
 	pucEncOutData = malloc(nEncOutLen);

	unsigned char pucIV[16] = {0x00};
        unsigned char buff[512] = {0};
        ECCCipher *pCipherKey = buff;
        unsigned int xnTime = 0;
        unsigned int uiISKIndex =1;
        struct timeval begin,end;
	ulRes = SDF_GenerateRandom(hSessionHandle, nEncInSize, pucIndata);
        if(ulRes != SDR_OK)
        {
                 dmsdebug("SDF_GenerateRandom, errno is %02x\n", ulRes);
        }
        ulRes = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiISKIndex, 128, pCipherKey, &symKeyHandle);
        if(ulRes != SDR_OK)
        {
                printf("SDF_GenerateKeyWithIPK_ECC error, errno is %02x\n",ulRes);
        }
	for(j = 0; j < testnum; j++)
        {

                gettimeofday( &begin, NULL );
		ulRes = SDF_Encrypt(hSessionHandle, symKeyHandle, SGD_SM4_CBC, pucIV, pucIndata, nEncInSize, pucEncOutData, &nEncOutLen);
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;

                if(ulRes != 0)
                {
                        printf("SDF_Encrypt fail!ret = %02x\n", ulRes);
                        continue;
                }
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
        ulRes = SDF_DestroyKey(hSessionHandle, symKeyHandle);
        if(ulRes != 0)
        {
                printf("SDF_DestroyKey fail!ret = %02x\n", ulRes);
        }

	free(pucIndata);
	free(pucEncOutData);
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);	
}

void *sm4Decrypt(void * arg)
{
        pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
        unsigned int ulRes, j;
        void *symKeyHandle = NULL;

        unsigned char *pucIndata = NULL;
        unsigned int nEncInSize = 1024 * 128;
        pucIndata = malloc(nEncInSize);
        unsigned char *pucEncOutData = NULL;
        unsigned int nEncOutLen = 1024 * 128;
        pucEncOutData = malloc(nEncOutLen);
        unsigned char *pucDecOutData = NULL;
        unsigned int nDecOutSize = 1024 * 128;
	pucDecOutData = malloc(nDecOutSize);

        unsigned char pucIV[16] = {0x00};
        unsigned char buff[512] = {0};
        ECCCipher *pCipherKey = buff;
        unsigned int xnTime = 0;
        unsigned int uiISKIndex =1;
        struct timeval begin,end;
        ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {       
                printf("SDF_OpenSession error, errno is %02x\n",ulRes);
        }
        ulRes = SDF_GenerateRandom(hSessionHandle, nEncInSize, pucIndata);
        if(ulRes != SDR_OK)
        {        
                 dmsdebug("SDF_GenerateRandom error, errno is %02x\n", ulRes);
        }
        ulRes = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiISKIndex, 128, pCipherKey, &symKeyHandle);
        if(ulRes != SDR_OK)
        {       
                printf("SDF_GenerateKeyWithIPK_ECC error, errno is %02x\n",ulRes);
        }
	ulRes = SDF_Encrypt(hSessionHandle, symKeyHandle, SGD_SM4_CBC, pucIV, pucIndata, nEncInSize, pucEncOutData, &nEncOutLen);
        if(ulRes != SDR_OK)
        {
                printf("SDF_Encrypt error, errno is %02x\n",ulRes);
        }
        for(j = 0; j < testnum; j++)
        {   

                gettimeofday( &begin, NULL );
		ulRes = SDF_Decrypt(hSessionHandle, symKeyHandle, SGD_SM4_CBC, pucIV, pucEncOutData, nEncOutLen, pucDecOutData, &nDecOutSize);
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
                if(ulRes != 0)
                {
                        printf("SDF_Decrypt fail!ret = %02x\n", ulRes);
                        continue;
                }
		ulRes = memcmp(pucIndata, pucDecOutData, nDecOutSize);
		if(ulRes != 0)
		{
                        printf("DecData is different from EncData! ret = %02x\n", ulRes);
                }
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
        ulRes = SDF_DestroyKey(hSessionHandle, symKeyHandle);
        if(ulRes != 0)
        {
                printf("SDF_DestroyKey fail!ret = %02x\n", ulRes);
        }

        free(pucIndata);
        free(pucEncOutData);
        free(pucDecOutData);
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);	
}

void *sm3Hash(void * arg)
{
        pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
        unsigned int ulRes, j;
	ECCrefPublicKey encPubKey;
        unsigned char *hashIndata = NULL;
        unsigned int hashIndataLen = 1024 * 16;
	hashIndata = malloc(hashIndataLen); 
        unsigned char pucHash[32]= {0};
	unsigned int hashLen = 0;
        unsigned char pucID[] = "abcd1234";
        unsigned int uiIDLength = 8;
	unsigned int xnTime = 0;
        struct timeval begin,end;
        ulRes = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
        if(ulRes != SDR_OK)
        {
                printf("SDF_OpenSession error, errno is %02x\n",ulRes);
        }
	ulRes = SDF_GenerateRandom(hSessionHandle, hashIndataLen, hashIndata);
        if(ulRes != SDR_OK)
        {
                 printf("SDF_GenerateRandom error, errno is %02x\n", ulRes);
        }

	ulRes = SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, &encPubKey);
        if(ulRes!=SDR_OK)
        {
	        printf("SDF_ExportEncPublicKey_ECC error! errno is %x\n",ulRes);
        }
	for(j = 0; j < testnum; j++)
        {

                gettimeofday( &begin, NULL );
		ulRes = SDF_HashInit(hSessionHandle, SGD_SM3, &encPubKey, pucID, uiIDLength);
                if(ulRes!= SDR_OK)
                {
	                printf("SDF_HashInit error, errno = %2x", ulRes);
			continue;
                }
		ulRes = SDF_HashUpdate(hSessionHandle, hashIndata, hashIndataLen);
                if (ulRes != SDR_OK)
                {
	                printf("SDF_HashUpdate error, errno = %2x\n", ulRes);
			continue;
                }
		ulRes = SDF_HashFinal(hSessionHandle, pucHash, &hashLen);
                if (ulRes != SDR_OK)
                {
	                printf("SDF_HashFinal error, errno = %2x\n", ulRes);
			continue;
                }
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec;
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);		
}

void *generateHubPublicKey(void *arg)
{
	
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;

		unsigned int uiKeyIndex = 1;
		unsigned int KeyLen = 256;
		ECCrefPublicKey pucPublicKey[2] = {0x00};
	
        unsigned int xnTime = 0;
        struct timeval begin,end;
        
	for(j = 0; j < testnum; j++)
        {
			ulRes = dmsPCI_SVSClearContainer(hSessionHandle, uiKeyIndex);
                if (SDR_OK != ulRes) {
					printf("dmsPCI_SVSClearContainer error, errno = %2x\n", ulRes);
                    continue;    
                }
		gettimeofday( &begin, NULL );
                ulRes= dmsPCI_SVSGenECCKeyPair(hSessionHandle, uiKeyIndex, KeyLen, pucPublicKey);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) ;
		
                if(ulRes != 0)
                {
                        printf("dmsPCI_SVSGenECCKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }

                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }

        printf("\ntest_num %d cnt, once time = %ds, total time = %ds\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
}


void *importSKE(void *arg)
{
	
	pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int uiAlgID = SGD_SM2_3;
        unsigned int uiKeyIndex = 1;
	unsigned int KeyLen = 256;
	ECCrefPublicKey pucPublicKey[2] = {0x00};
	unsigned int region = 1;
	unsigned char identify[] = "abcd1234";
	unsigned int identifyLen = 8;
	unsigned char licenceIssuingauthority[] = "abcd1234";
	unsigned int licenceIssuingauthorityLen = 8;
        unsigned char takeEffectDate[] = "2020-10-09";
	unsigned int takeEffectDateLen = 10;
        unsigned char loseEffectDate[] = "2020-10-09"; 
	unsigned int loseEffectDateLen = 10;
        unsigned char * pubKey = (unsigned char*)pucPublicKey;
	unsigned int pubKeyLen = 264;
        unsigned char pke[132] = {0x00};
	unsigned int pkeLen = 132;
        unsigned char pks[132] = {0x00};
	unsigned int pksLen = 132;
        unsigned char ske[384] = {0x00}; 
	unsigned int skeLen = 384;	
	ENVELOPEDKEYBLOB* cipher = (ENVELOPEDKEYBLOB*)ske;
	
	
        unsigned int xnTime = 0;
        struct timeval begin,end;
        
	for(j = 0; j < testnum; j++)
        {
			ulRes = dmsPCI_SVSClearContainer(hSessionHandle, uiKeyIndex);
            if (SDR_OK != ulRes) {
                printf("dmsPCI_SVSClearContainer fail!ret = %02x\n", ulRes);
                continue;
                }
			
			ulRes= dmsPCI_SVSGenECCKeyPair(hSessionHandle, uiKeyIndex, KeyLen, pucPublicKey);
			if (SDR_OK != ulRes) {
                printf("dmsPCI_SVSGenECCKeyPair fail!ret = %02x\n", ulRes);
                continue;
                }
				
			ulRes = dmsPCI_CalculatePersonKey(hSessionHandle, region, identify, identifyLen, 
						licenceIssuingauthority, licenceIssuingauthorityLen,
						takeEffectDate, takeEffectDateLen,
						loseEffectDate, loseEffectDateLen,
						pubKey, pubKeyLen,
						pke, &pkeLen, 
						pks, &pksLen, 
						ske, &skeLen);
            if (SDR_OK != ulRes) {
                printf("dmsPCI_CalculatePersonKey fail!ret = %02x\n", ulRes);
                continue;
                }
			
		gettimeofday( &begin, NULL );
                ulRes= dmsPCI_SVSImportKeyWithECCKeyPair(hSessionHandle, uiKeyIndex, 0, cipher);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) ;
		
                if(ulRes != 0)
                {
                        printf("dmsPCI_SVSImportKeyWithECCKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }

                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }

        printf("\ntest_num %d cnt, once time = %ds, total time = %ds\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	pthread_mutex_unlock(&mutex);
}



int testSign()
{
	int i, num, testnum;
	dmsdebug("please input thread num:");
	scanf("%d",&num);
	dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	pthread_mutex_init(&mutex, NULL);
	pthread_t ts[num];
	for (i = 0; i < num; i++)
		{
			pthread_create(&ts[i], NULL, sign, &testnum); 
			/*pthread_create函数
			第一个参数为指向线程标识符的指针（新创建的线程ID指向的内存单元。）
			第二个参数设置线程属性（线程属性，默认为NULL）
			第三个参数线程运行函数的起始地址	
			第四个参数是运行函数的参数（默认为NULL。若上述函数需要参数，将参数放入结构中并将地址作为arg传入）	
			*/
		}
	for (i = 0; i < num; i++)
		{
			pthread_join(ts[i], NULL);
		}
		
	//销毁互斥向量
	pthread_mutex_destroy(&mutex);
	return 0;
	
}

int testVerify()
{
	int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
		pthread_create(&ts[i], NULL, verify, &testnum); 
        }   
        for (i = 0; i < num; i++)
        {   
		pthread_join(ts[i], NULL);
        }  	
	
	//销毁互斥向量
	pthread_mutex_destroy(&mutex);
	return 0;

}

int testcalculatePersonKey()
{
        int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {
                pthread_create(&ts[i], NULL, calculatePersonKey, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
	//销毁互斥向量
	pthread_mutex_destroy(&mutex);
        return 0;
}


int testExternalVerify()
{
        int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {
                pthread_create(&ts[i], NULL, externalVerify, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
	//初始化互斥向量
	pthread_mutex_destroy(&mutex);
        return 0;
}

int testExternalEncrypt()
{
	int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
                pthread_create(&ts[i], NULL, externalEncrypt, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;
}

int testInternalDecrypt()
{
	int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {
                pthread_create(&ts[i], NULL, internalDecrypt, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
 	pthread_mutex_destroy(&mutex);
        return 0;

}

int testsm4Encrypt()
{
	int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
                pthread_create(&ts[i], NULL, sm4Encrypt, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
 	pthread_mutex_destroy(&mutex);
        return 0;
}

int testsm4Decrypt()
{
        int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {
                pthread_create(&ts[i], NULL, sm4Decrypt, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
	pthread_mutex_destroy(&mutex);
        return 0;

}

int testsm3Hash()
{
        int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
                pthread_create(&ts[i], NULL, sm3Hash, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;

}


int testGenerateHubPublicKey()
{
        int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {
                pthread_create(&ts[i], NULL, generateHubPublicKey, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
	pthread_mutex_destroy(&mutex);
        return 0;

}

int testImportSKE()
{
        int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
                pthread_create(&ts[i], NULL, importSKE, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;

}


int main(int argc, char * argv[])
{
	int i, ulRes;
	//打开设备
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 
		
	while(1)
	{
		dmsdebug( YELLOW "***********************Performance test*************************\n");
        	dmsdebug("input 1:TestSign\n");
        	dmsdebug("input 2:TestVerify\n");	
        	dmsdebug("input 3:TestCalculatePersonKey\n");	
        	dmsdebug("input 4:TestExternalVerify\n");	
        	dmsdebug("input 5:TestExternalEncrypt\n");	
        	dmsdebug("input 6:TestInternalDecrypt\n");	
        	dmsdebug("input 7:Testsm4Encrypt\n");	
        	dmsdebug("input 8:Testsm4Decrypt\n");	
        	dmsdebug("input 9:Testsm3Hash\n");	
			dmsdebug("input a:TestGenerateHubPublicKey\n");	
        	dmsdebug("input b:TestImportSKE\n");
		dmsdebug("***************************End Test*****************************\n" NONE);
		
		dmsdebug("please input cmd():");
		scanf("%x",&i);
		
		switch(i)
		{
			case 0x01:
				ulRes = testSign();
				printf("test Sign result=%d\n", ulRes);
				break;
				
			case 0x02:
				ulRes = testVerify();
				printf("test Verify result=%d\n", ulRes);
				break;

			case 0x03:
				ulRes = testcalculatePersonKey();
                                printf("test calculatePersonKey result=%d\n", ulRes);
                                break;

			case 0x04:
                                ulRes = testExternalVerify();
                                printf("test ExternalVerify result=%d\n", ulRes);
                                break;

			case 0x05:
                                ulRes = testExternalEncrypt();
                                printf("test ExternalEncrypt result=%d\n", ulRes);
                                break;

			case 0x06:
                                ulRes = testInternalDecrypt();
                                printf("test InternalDecrypt result=%d\n", ulRes);
                                break;

			case 0x07:
				ulRes = testsm4Encrypt();
                                printf("test sm4Encrypt result=%d\n", ulRes);
                                break;
			
			case 0x08:
                                ulRes = testsm4Decrypt();
                                printf("test sm4decrypt result=%d\n", ulRes);
                                break;

			case 0x09:
                                ulRes = testsm3Hash();
                                printf("test sm3Hash result=%d\n", ulRes);
                                break;	
								
			case 0x0a:
                                ulRes = testGenerateHubPublicKey();
                                printf("test GenerateHubPublicKey result=%d\n", ulRes);
                                break;

			case 0x0b:
                                ulRes = testImportSKE();
                                printf("test ImportSKE result=%d\n", ulRes);
                                break;

			default:
				break;
			
		}
		
		
	}

}
            
