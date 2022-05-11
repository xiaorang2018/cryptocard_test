#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "dms_sdf.h" 
#include "common_def.h"
#include "color.h"

//全局变量
void *hDeviceHandle = NULL;
//void *hSessionHandle = NULL;
pthread_mutex_t mutex;
struct InParameter
{
	unsigned int num;
	unsigned int algID;
}InParameter;
	

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

void *calculatePersonKey(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int uiAlgID = SGD_SM2_3;
        unsigned int uiKeyIndex = 5;
	unsigned int KeyLen = 256;
	ECCrefPublicKey pucPublicKey[2] = {0x00};
	unsigned int region = 1;
	unsigned char identify[] = "abcd1234";
	unsigned char licenceIssuingauthority[] = "abcd1234";
	unsigned int licenceIssuingauthorityLen = 8;
        unsigned char takeEffectDate[] = "2020-10-09";
	unsigned int takeEffectDateLen = 10;
        unsigned char loseEffectDate[] = "2020-10-09"; 
	unsigned int loseEffectDateLen = 10;
        unsigned char *pTmpSignPublicKey = &pucPublicKey[0];
	unsigned char *pTmpEncPublicKey = &pucPublicKey[1];
	unsigned char buffer1[1024] = {0};
	CkiEnvelope * pEnv = (CkiEnvelope *)buffer1;
	unsigned char buffer2[1024] = {0};	
	EnvelopedKeyBlob * pSke = (EnvelopedKeyBlob*)buffer2;
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 
		
		ulRes = SDF_dmsPCI_GenECCKeyPair(hSessionHandle, uiKeyIndex, &pucPublicKey[0], &pucPublicKey[1]);
                if (SDR_OK != ulRes) {
                        printf("SDF_ExportSignPublicKey_ECC error, errno is %02x\n",ulRes);
                }

        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes = SDF_dmsPCI_CalculatePersonKey(hSessionHandle, region, identify, 
						licenceIssuingauthority,
						takeEffectDate,
						loseEffectDate,
						pTmpSignPublicKey, pTmpEncPublicKey,
						pEnv, pSke);
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
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}

void *generatePKIKeyPair(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int index = 2;
        unsigned short KeyFlag = 3;

	
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        }
			
        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes =  SDF_dmsGenerate_PKIKeyPair(hSessionHandle, index, KeyFlag);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsGenerate_PKIKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }
				SDF_dmsPCI_SVSClearContainer(hSessionHandle, index);
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}

void *internalSign(void *arg)
{
	//pthread_mutex_lock(&mutex);
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
	void * hSessionHandle = NULL;
	#if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 
		printf("");
		
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
            		printf("SDF_InternalSign_ECC fail !ret = %02x\n", ulRes);
            		continue;
        	}

        	if (!(j % 100))
        	{
            		printf("·");
            		fflush(stdout);
        	} 
    	}
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
	printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
	xnTime = 0;
	//pthread_mutex_unlock(&mutex);
    
}

void *internalVerify(void *arg)
{
	//pthread_mutex_lock(&mutex);
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
		void * hSessionHandle = NULL;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 

        
	ulRes = SDF_ExportSignPublicKey_ECC(hSessionHandle, uiISKIndex, &testPubKey);
        if(ulRes != SDR_OK)
        {
                printf("SDF_ExportSignPublicKey_ECC error, errno is %02x\n",ulRes);
        }
        ulRes = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiISKIndex, pucPassword, 9);
        if(ulRes != SDR_OK)
        {
                printf("GetPrivateKeyAccessRight error, errno is %02x\n",ulRes);
        }
	ulRes = SDF_InternalSign_ECC(hSessionHandle, uiISKIndex, Hash, 32, &pucSignature);
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
		ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 

        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}


void *externalSign(void *arg)
{
	//pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
	unsigned int ulRes, j, resLen;
	unsigned int uiAlgID = SGD_SM2;
	unsigned int uiKeyBits = 256;
	unsigned int xnTime = 0;
	char data[1024*16]={0};
	unsigned int dataLen= 0;
	unsigned char Hash[32];
	memset(Hash,0x11,sizeof(Hash));
	ECCSignature pucSignature;
	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;
	struct timeval begin,end;
	unsigned char buff[64 * 1024];
	void * hSessionHandle = NULL;
	#if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 

		
		ulRes =  SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits,  &pucPublicKey, &pucPrivateKey);
    	if(ulRes != SDR_OK)
    	{
        	printf("SDF_GenerateKeyPair_ECC error, errno is %02x\n",ulRes);
    	}
		
		uiAlgID = SGD_SM2_1;

    	for(j = 0; j < testnum; j++)
    	{
        	gettimeofday( &begin, NULL );
        	ulRes =  SDF_ExternalSign_ECC(hSessionHandle, uiAlgID, &pucPrivateKey, Hash, 32, &pucSignature);
        	gettimeofday( &end, NULL );
        	xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
					
        	if(ulRes != 0)
        	{
            		printf("SDF_ExternalSign_ECC fail!ret = %02x\n", ulRes);
            		continue;
        	}

        	if (!(j % 100))
        	{
            		printf("·");
            		fflush(stdout);
        	} 
    	}
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
	printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
	xnTime = 0;
	//pthread_mutex_unlock(&mutex);
    
}


void *externalVerify(void *arg)
{
	//pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
	unsigned int ulRes, j, resLen;
	unsigned int uiAlgID = SGD_SM2;
	unsigned int uiKeyBits = 256;
	unsigned int xnTime = 0;
	char data[1024*16]={0};
	unsigned int dataLen= 0;
	unsigned char Hash[32];
	memset(Hash,0x11,sizeof(Hash));
	ECCSignature pucSignature;
	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;
	struct timeval begin,end;
	unsigned char buff[64 * 1024];
	void * hSessionHandle = NULL;
	#if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 

		
		ulRes =  SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits,  &pucPublicKey, &pucPrivateKey);
    	if(ulRes != SDR_OK)
    	{
        	printf("SDF_GenerateKeyPair_ECC error, errno is %02x\n",ulRes);
    	}
		uiAlgID = SGD_SM2_1;
		ulRes =  SDF_ExternalSign_ECC(hSessionHandle, uiAlgID, &pucPrivateKey, Hash, 32, &pucSignature);
		if(ulRes != SDR_OK)
    	{
        	printf("SDF_ExternalSign_ECC error, errno is %02x\n",ulRes);
    	}

    	for(j = 0; j < testnum; j++)
    	{
        	gettimeofday( &begin, NULL );
        	ulRes =  SDF_ExternalVerify_ECC(hSessionHandle,uiAlgID, &pucPublicKey, Hash, 32, &pucSignature);
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
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
	printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
	xnTime = 0;
	//pthread_mutex_unlock(&mutex);
    
}

void *externalEncrypt(void *arg)
{
        //pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
        unsigned int ulRes, j;
	unsigned char Hash[32] = {0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                                  0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a};
	
		unsigned int uiAlgID = SGD_SM2;
		unsigned int uiKeyBits =256;
		ECCrefPublicKey pucPublicKey;
		ECCrefPrivateKey pucPrivateKey;
		unsigned char buffer[1024] = {0};
		ECCCipher *pucEncData = buffer;
		struct timeval begin,end;
		unsigned int xnTime = 0;
		void * hSessionHandle = NULL;
	#if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 

		
		ulRes =  SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits, &pucPublicKey, &pucPrivateKey);
    	if(ulRes != SDR_OK)
    	{
        	printf("SDF_GenerateKeyPair_ECC error, errno is %02x\n",ulRes);
    	}
		uiAlgID = SGD_SM2_3;

	for(j = 0; j < testnum; j++)
        {       
                
                gettimeofday( &begin, NULL );
                ulRes = SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, &pucPublicKey, Hash, 16, pucEncData); 
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
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
	
}

void *externalDecrypt(void *arg)
{
	    //pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
        unsigned int ulRes, j;
	unsigned char Hash[32] = {0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                                  0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a};
		
		ECCrefPublicKey pucPublicKey;
		ECCrefPrivateKey pucPrivateKey;
		unsigned char buffer1[1024] = {0};
		unsigned char buffer2[1024] = {0};
		ECCCipher *pucEncData = buffer1;
		unsigned char *pucData = buffer2;
		unsigned int puiDataLength = 0;
		unsigned int uiAlgID = SGD_SM2;
		unsigned int uiKeyBits = 256;
		
		struct timeval begin,end;
			unsigned int xnTime = 0;
		void * hSessionHandle = NULL;
	#if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_OpenSession error! errorno is %02x\n", ulRes);
                return -1;
        } 

		
		ulRes =  SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits, &pucPublicKey, &pucPrivateKey);
    	if(ulRes != SDR_OK)
    	{
        	printf("SDF_GenerateKeyPair_ECC error, errno is %02x\n",ulRes);
    	}
		uiAlgID = SGD_SM2_3;
		ulRes = SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, &pucPublicKey, Hash,16, pucEncData); 
		if(ulRes != SDR_OK)
    	{
        	printf("SDF_ExternalEncrypt_ECC error, errno is %02x\n",ulRes);
    	}
        for(j = 0; j < testnum; j++)
        {
                 
                gettimeofday( &begin, NULL );
                ulRes =  SDF_ExternalDecrypt_ECC(hSessionHandle, uiAlgID, &pucPrivateKey, pucEncData, pucData, &puiDataLength);
                gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;

                if(ulRes != 0)
                {
                        printf("SDF_ExternalDecrypt_ECC fail!ret = %02x\n", ulRes);
                        continue;
                }
				if(memcmp(pucData, Hash, puiDataLength)!=0)
				{
					printf("DecryptData is different from EncryptData!");
				}

                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
	
}

void *SM4Encrypt(void *arg)
{
	//pthread_mutex_lock(&mutex);
        struct InParameter * tmp; 
		tmp = (struct InParameter *)arg;
        unsigned int ulRes, j;
        void *symKeyHandle = NULL;

	unsigned char *pucIndata = NULL;
        unsigned int nEncInSize = 1024 * 128;
	pucIndata = malloc(nEncInSize);
	if (pucIndata == NULL){
		return -1;
	}
	
	unsigned char *pucEncOutData = NULL;
        unsigned int nEncOutLen = 1024 * 128;
 	pucEncOutData = malloc(nEncOutLen);
		if (pucEncOutData == NULL){
		return -1;
	}

		unsigned char pucIV[16] = {0x00};
        unsigned char buff[512] = {0};
        ECCCipher *pCipherKey = buff;
        unsigned int xnTime = 0;
        unsigned int uiISKIndex =1;
		unsigned int ID[4] = {SGD_SM4_ECB, SGD_SM4_CBC, SGD_SM4_CFB, SGD_SM4_OFB};
		unsigned int testnum =  tmp->num;
		unsigned int uiAlgID = ID[tmp->algID - 1];
		
		
        struct timeval begin,end;
		void * hSessionHandle = NULL;
		
		#if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        } 
		
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
			
				memset(pucIV, 0, 16);
                gettimeofday( &begin, NULL );
		ulRes = SDF_Encrypt(hSessionHandle, symKeyHandle, uiAlgID, pucIV, pucIndata, nEncInSize, pucEncOutData, &nEncOutLen);
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
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);	
}

void *SM4Decrypt(void * arg)
{
        //pthread_mutex_lock(&mutex);
		struct InParameter * tmp; 
		tmp = (struct InParameter *)arg;
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
		unsigned int ID[4] = {SGD_SM4_ECB, SGD_SM4_CBC, SGD_SM4_CFB, SGD_SM4_OFB};
		unsigned int testnum =  tmp->num;
		unsigned int uiAlgID = ID[tmp->algID - 1];
        unsigned int xnTime = 0;
        unsigned int uiISKIndex =1;
        struct timeval begin,end;
		void * hSessionHandle = NULL;
		
        #if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
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
	ulRes = SDF_Encrypt(hSessionHandle, symKeyHandle, uiAlgID, pucIV, pucIndata, nEncInSize, pucEncOutData, &nEncOutLen);
        if(ulRes != SDR_OK)
        {
                printf("SDF_Encrypt error, errno is %02x\n",ulRes);
        }
        for(j = 0; j < testnum; j++)
        {   
				memset(pucIV, 0 ,16);
                gettimeofday( &begin, NULL );
		ulRes = SDF_Decrypt(hSessionHandle, symKeyHandle, uiAlgID, pucIV, pucEncOutData, nEncOutLen, pucDecOutData, &nDecOutSize);
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
		ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);	
}

void *SM3Hash(void * arg)
{
        //pthread_mutex_lock(&mutex);
	int testnum = *(int *)arg;
        unsigned int ulRes, j;
	ECCrefPublicKey encPubKey;
        unsigned char *hashIndata = NULL;
        unsigned int hashIndataLen = 1024 * 64;
	hashIndata = malloc(hashIndataLen); 
        unsigned char pucHash[32]= {0};
	unsigned int hashLen = 0;
        unsigned char pucID[] = "abcd1234";
        unsigned int uiIDLength = 8;
	unsigned int xnTime = 0;
        struct timeval begin,end;
		void * hSessionHandle = NULL;
		
        #if 0
	ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif	
	ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
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
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
	printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);		
}

        	dmsdebug("11:testSM3Hash                   12:testGenerateKeyPair_RSA\n");	
        	dmsdebug("13:testSign_RSA                  14:testVerify_RSA\n");	
        	dmsdebug("15:testEncrypt_RSA               16:testDecrypt_RSA\n");	

void *generateKeyPair_RSA(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int index = 2;
        unsigned short KeyFlag = 3;

	
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        }
			
        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes =  SDF_dmsGenerate_PKIKeyPair(hSessionHandle, index, KeyFlag);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsGenerate_PKIKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }
				SDF_dmsPCI_SVSClearContainer(hSessionHandle, index);
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}


void *sign_RSA(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int index = 2;
        unsigned short KeyFlag = 3;

	
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        }
			
        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes =  SDF_dmsGenerate_PKIKeyPair(hSessionHandle, index, KeyFlag);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsGenerate_PKIKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }
				SDF_dmsPCI_SVSClearContainer(hSessionHandle, index);
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}


void *verify_RSA(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int index = 2;
        unsigned short KeyFlag = 3;

	
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        }
			
        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes =  SDF_dmsGenerate_PKIKeyPair(hSessionHandle, index, KeyFlag);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsGenerate_PKIKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }
				SDF_dmsPCI_SVSClearContainer(hSessionHandle, index);
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}


void *encrypt_RSA(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int index = 2;
        unsigned short KeyFlag = 3;

	
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        }
			
        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes =  SDF_dmsGenerate_PKIKeyPair(hSessionHandle, index, KeyFlag);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsGenerate_PKIKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }
				SDF_dmsPCI_SVSClearContainer(hSessionHandle, index);
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
}


void *decrypt_RSA(void *arg)
{
	//pthread_mutex_lock(&mutex);
        int testnum = *(int *)arg;
        unsigned int ulRes, j, resLen;
	unsigned int index = 2;
        unsigned short KeyFlag = 3;

	
        unsigned int xnTime = 0;
		void * hSessionHandle = NULL;

        struct timeval begin,end;
		
		#if 0
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
		#endif	
		ulRes = SDF_OpenSession(hDeviceHandle,&hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("openSessione error! errorno is %02x\n", ulRes);
                return -1;
        }
			
        
	for(j = 0; j < testnum; j++)
        {

		gettimeofday( &begin, NULL );
				ulRes =  SDF_dmsGenerate_PKIKeyPair(hSessionHandle, index, KeyFlag);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) * 1000000 + end.tv_usec - begin.tv_usec ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsGenerate_PKIKeyPair fail!ret = %02x\n", ulRes);
                        continue;
                }
				SDF_dmsPCI_SVSClearContainer(hSessionHandle, index);
                if (!(j % 100))
                {
                        printf("·");
                        fflush(stdout);
                }
        }
	ulRes = SDF_CloseSession(hSessionHandle);
        if(ulRes != SDR_OK)
        {    
                printf("SDF_CloseSession error! errorno is %02x\n", ulRes);
                return -1;
        } 
        printf("\ntest_num %d cnt, once time = %dus, total time = %dus\n", testnum, xnTime / testnum, xnTime);
        xnTime = 0;
	//pthread_mutex_unlock(&mutex);
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
		void * hSessionHandle = NULL;
        
	for(j = 0; j < testnum; j++)
        {
			ulRes = SDF_dmsPCI_SVSClearContainer(hSessionHandle, uiKeyIndex);
                if (SDR_OK != ulRes) {
					printf("SDF_dmsPCI_SVSClearContainer error, errno = %2x\n", ulRes);
                    continue;    
                }
		gettimeofday( &begin, NULL );
                ulRes= SDF_dmsPCI_GenECCKeyPair(hSessionHandle, uiKeyIndex, KeyLen, pucPublicKey);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsPCI_GenECCKeyPair fail!ret = %02x\n", ulRes);
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
        unsigned char * pTmpSignPublicKey = &pucPublicKey[0];
	unsigned char * pTmpEncPublicKey = &pucPublicKey[1];
	unsigned char buffer1[1024] = {0};
	CkiEnvelope * pEnv = (CkiEnvelope *)buffer1;
	unsigned char buffer2[1024] = {0};	
	EnvelopedKeyBlob * pSke = (EnvelopedKeyBlob*)buffer2;
	void * hSessionHandle = NULL;
	
	
        unsigned int xnTime = 0;
        struct timeval begin,end;
        
	for(j = 0; j < testnum; j++)
        {
			ulRes = SDF_dmsPCI_GenECCKeyPair(hSessionHandle, uiKeyIndex, &pucPublicKey[0], &pucPublicKey[1]);
			
            if (SDR_OK != ulRes) {
                printf("SDF_dmsPCI_GenECCKeyPair fail!ret = %02x\n", ulRes);
                continue;
                }
			
				
			ulRes = SDF_dmsPCI_CalculatePersonKey(hSessionHandle, region, identify, 
						licenceIssuingauthority,
						takeEffectDate,
						loseEffectDate,
						pTmpSignPublicKey, pTmpEncPublicKey,
						pEnv, pSke);
            if (SDR_OK != ulRes) {
                printf("SDF_dmsPCI_CalculatePersonKey fail!ret = %02x\n", ulRes);
                continue;
                }
			
		gettimeofday( &begin, NULL );
                ulRes= SDF_dmsPCI_ImportKeyWithECCKeyPair(hSessionHandle, uiKeyIndex, pSke);
		gettimeofday( &end, NULL );
                xnTime += (end.tv_sec - begin.tv_sec) ;
		
                if(ulRes != 0)
                {
                        printf("SDF_dmsPCI_ImportKeyWithECCKeyPair fail!ret = %02x\n", ulRes);
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



int testCalculatePersonKey()
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



int testGeneratePKIKeyPair()
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
                pthread_create(&ts[i], NULL, generatePKIKeyPair, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
	//销毁互斥向量
	pthread_mutex_destroy(&mutex);
        return 0;
}


int testInternalSign()
{
	int i, num, testnum;
	dmsdebug("please input thread num:");
	scanf("%d",&num);
	dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	//pthread_mutex_init(&mutex, NULL);
	pthread_t ts[num];
	for (i = 0; i < num; i++)
		{
			pthread_create(&ts[i], NULL, internalSign, &testnum); 
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
	//pthread_mutex_destroy(&mutex);
	return 0;	
}

int testInternalVerify()
{
	int i, num, testnum;
        dmsdebug("please input thread num:");
        scanf("%d",&num);
        dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	//pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
		pthread_create(&ts[i], NULL, internalVerify, &testnum); 
        }   
        for (i = 0; i < num; i++)
        {   
		pthread_join(ts[i], NULL);
        }  	
	
	//销毁互斥向量
	//pthread_mutex_destroy(&mutex);
	return 0;

}

int testExternalSign()
{
	int i, num, testnum;
	dmsdebug("please input thread num:");
	scanf("%d",&num);
	dmsdebug("please input test num:");
        scanf("%d",&testnum);
	//初始化互斥向量
	//pthread_mutex_init(&mutex, NULL);
	pthread_t ts[num];
	for (i = 0; i < num; i++)
		{
			pthread_create(&ts[i], NULL, externalSign, &testnum); 
		}
	for (i = 0; i < num; i++)
		{
			pthread_join(ts[i], NULL);
		}
		
	//销毁互斥向量
	//pthread_mutex_destroy(&mutex);
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
	//pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
		pthread_create(&ts[i], NULL, externalVerify, &testnum); 
        }   
        for (i = 0; i < num; i++)
        {   
		pthread_join(ts[i], NULL);
        }  	
	
	//销毁互斥向量
	//pthread_mutex_destroy(&mutex);
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

int testExternalDecrypt()
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
                pthread_create(&ts[i], NULL, externalDecrypt, &testnum);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
 	pthread_mutex_destroy(&mutex);
        return 0;

}

int testSM4Encrypt()
{
	int i, num;	
        dmsdebug("please input thread num:");
        scanf("%d",&num);
		struct InParameter info;
        dmsdebug("please input test num:");
        scanf("%d",&info.num);
		dmsdebug("please input test algorithm(1.SGD_SM4_ECB, 2.SGD_SM4_CBC, 3.SGD_SM4_CFB, 4.SGD_SM4_OFB):");
		scanf("%d",&info.algID);
		pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {   
                pthread_create(&ts[i], NULL, SM4Encrypt, &info);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
 	pthread_mutex_destroy(&mutex);
        return 0;
}

int testSM4Decrypt()
{
        int i, num;	
        dmsdebug("please input thread num:");
        scanf("%d",&num);
		struct InParameter info;
        dmsdebug("please input test num:");
        scanf("%d",&info.num);
		dmsdebug("please input test algorithm(1.SGD_SM4_ECB, 2.SGD_SM4_CBC, 3.SGD_SM4_CFB, 4.SGD_SM4_OFB):");
		scanf("%d",&info.algID);
	pthread_mutex_init(&mutex, NULL);
        pthread_t ts[num];
        for (i = 0; i < num; i++)
        {
                pthread_create(&ts[i], NULL, SM4Decrypt, &info);
        }
        for (i = 0; i < num; i++)
        {
                pthread_join(ts[i], NULL);
        }
	pthread_mutex_destroy(&mutex);
        return 0;

}

int testSM3Hash()
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
                pthread_create(&ts[i], NULL, SM3Hash, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;
}


int testGenerateKeyPair_RSA()
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
                pthread_create(&ts[i], NULL, generateKeyPair_RSA, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;
}

int testSign_RSA()
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
                pthread_create(&ts[i], NULL, sign_RSA, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;
}

int testVerify_RSA()
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
                pthread_create(&ts[i], NULL, verify_RSA, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;
}


int testEncrypt_RSA()
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
                pthread_create(&ts[i], NULL, encrypt_RSA, &testnum);
        }   
        for (i = 0; i < num; i++)
        {   
                pthread_join(ts[i], NULL);
        }   
	pthread_mutex_destroy(&mutex);
        return 0;
}

int testDecrypt_RSA()
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
                pthread_create(&ts[i], NULL, decrypt_RSA, &testnum);
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
	#if 1
	//打开设备
		ulRes = SDF_OpenDevice(&hDeviceHandle);
        if(ulRes!= SDR_OK)
        {
                printf("SDF_OpenDevice error! errorno is %02x\n", ulRes);
                return -1;
        }
	#endif
		
	while(1)
	{
		dmsdebug( YELLOW "***********************Performance test*************************\n");
		dmsdebug("1:testCalculatePersonKey         2:testGenerate_PKIKeyPair\n");
        	dmsdebug("3:testInternalSign               4:testInternalVerify\n");
		dmsdebug("5:testExternalSign               6:testExternalVerify\n");
		dmsdebug("7:testExternalEncrypt            8:testExternalDecrypt\n");	
        	dmsdebug("9:testSM4Encrypt                 10:testSM4Decrypt\n");		
        	dmsdebug("11:testSM3Hash                   12:testGenerateKeyPair_RSA\n");	
        	dmsdebug("13:testSign_RSA                  14:testVerify_RSA\n");	
        	dmsdebug("15:testEncrypt_RSA               16:testDecrypt_RSA\n");	
		dmsdebug("***************************End Test*****************************\n" NONE);
		
		dmsdebug("please input cmd():");
		scanf("%x",&i);
		
		switch(i)
		{
			case 0x01:
				ulRes = testCalculatePersonKey();
				printf("TestCalculatePersonKey result=%d\n", ulRes);
				break;
				
			case 0x02:
				ulRes = testGeneratePKIKeyPair();
				printf("TestGeneratePKIKeyPair result=%d\n", ulRes);
				break;

			case 0x03:
				ulRes = testInternalSign();
                                printf("TestInternalSign result=%d\n", ulRes);
                                break;

			case 0x04:
                                ulRes = testInternalVerify();
                                printf("TestInternalVerify result=%d\n", ulRes);
                                break;

			case 0x05:
                                ulRes = testExternalSign();
                                printf("TestExternalSign result=%d\n", ulRes);
                                break;

			case 0x06:
                                ulRes = testExternalVerify();
                                printf("TestExternalVerify result=%d\n", ulRes);
                                break;

			case 0x07:
				ulRes = testExternalEncrypt();
                                printf("TestExternalEncrypt result=%d\n", ulRes);
                                break;
			
			case 0x08:
                                ulRes = testExternalDecrypt();
                                printf("TestExternalDecrypt result=%d\n", ulRes);
                                break;

			case 0x09:
                                ulRes = testSM4Encrypt();
                                printf("TestSM4Encrypt result=%d\n", ulRes);
                                break;	
								
			case 0x10:
                                ulRes = testSM4Decrypt();
                                printf("TestSM4Decrypt result=%d\n", ulRes);
                                break;

			case 0x11:
                                ulRes = testSM3Hash();
                                printf("TestSM3Hash result=%d\n", ulRes);
                                break;

			case 0x12:
                                ulRes = testGenerateKeyPair_RSA();
                                printf("TestGenerateKeyPair_RSA result=%d\n", ulRes);
                                break;

			case 0x13:
                                ulRes = testSign_RSA();
                                printf("TestSign_RSA result=%d\n", ulRes);
                                break;

			case 0x14:
                                ulRes = testVerify_RSA();
                                printf("TestVerify_RSA result=%d\n", ulRes);
                                break;

			case 0x15:
                                ulRes = testEncrypt_RSA();
                                printf("TestEncrypt_RSA result=%d\n", ulRes);
                                break;

			case 0x16:
                                ulRes = testDecrypt_RSA();
                                printf("TestDecrypt_RSA result=%d\n", ulRes);
                                break;

			default:
				break;
			
		}
		
		
	}

}
            
