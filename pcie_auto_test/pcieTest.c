#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "dms_sdf.h"
#include "Automated.h"
#include "Basic.h"
#include "Console.h"
#include "CUnit.h"
#include "TestDB.h"
/*
#include "CUError.h"
#include "CUnit_intl.h"
#include "MyMem.h"
#include "TestRun.h"
#include "Util.h"
*/

/*
void RSAtest()
{
	CU_ASSERT_EQUAL(test_ExportEncPublicKeyAndExportSignPublicKey_RSA(1), 0);
	CU_ASSERT_EQUAL(test_GenerateKeyAndImportKey_RSA(1), 0);
	CU_ASSERT_EQUAL(test_PublicKeyAndPrivateKeyOperation_RSA(1), 0);
	
}
*/

void DMtest()
{
	CU_ASSERT_EQUAL(test_GenerateRandom(1), 0);
	CU_ASSERT_EQUAL(test_GetDeviceInfo(1), 0);
	CU_ASSERT_EQUAL(test_GetAndReleasePrivateKeyAccessRight(1), 0);		
}

void KMtest()
{

	CU_ASSERT_EQUAL(test_ExportEncPublicKeyAndExportSignPublicKey(1), 0);
	CU_ASSERT_EQUAL(test_GenerateKeyWithEPK_ECC(1), 0);
	CU_ASSERT_EQUAL(test_GenerateKeyWithIPK_ECC(1), 0);
	CU_ASSERT_EQUAL(test_ImportKeyWithISK_ECC(1), 0);
	CU_ASSERT_EQUAL(test_GenerateKeyAndImportKeyWithKEK(1), 0);
	CU_ASSERT_EQUAL(test_KeyAgreement(1), 0);
	CU_ASSERT_EQUAL(test_ExchangeDigitEnvelopeBaseOnECC(1), 0);        

}


void ASMtest()
{
	CU_ASSERT_EQUAL(test_InternalSignAndVerify(1), 0);
	CU_ASSERT_EQUAL(test_ExternalSignAndVerify(1), 0);
	CU_ASSERT_EQUAL(test_ExternalEncryptAndDecrypt(1), 0);	
}
 
void SYMtest()
{
	CU_ASSERT_EQUAL(test_EncryptAndDecrypt(1), 0);	
	CU_ASSERT_EQUAL(test_CalculateMAC(1), 0);	
}
 
void HASHtest()
{
	
	CU_ASSERT_EQUAL(test_Hash(1), 0);	
}

void FILEtest()
{
	
	CU_ASSERT_EQUAL(test_WriteFileAndReadFile(1), 0);	
}

void IKItest()
{	
#if 0
	CU_ASSERT_EQUAL(test_InitAndGenerateMatrix(1), 0);
	CU_ASSERT_EQUAL(test_ExportPubMatrixAndImportPubMatrix(1), 0);	
	CU_ASSERT_EQUAL(test_InitAndGenerateMatrix(1), 0);
	CU_ASSERT_EQUAL(test_ImportKeyWithECCKeyPair(1), 0);
	CU_ASSERT_EQUAL(test_SVSClearContainer(1), 0);	
	CU_ASSERT_EQUAL(test_ImportKeyWithECCKeyPair(1), 0);
	CU_ASSERT_EQUAL(test_BackupAndRecovery(1), 0);	
	CU_ASSERT_EQUAL(test_BackupAndRecoveryThreshold(1), 0);	
	CU_ASSERT_EQUAL(test_DeleteKEKAndGenerateKEK(1), 0);	
	CU_ASSERT_EQUAL(test_TestSelf(1), 0);   
    	CU_ASSERT_EQUAL(test_SVSGetKeyPoolState(1), 0); 


    	CU_ASSERT_EQUAL(test_GetKEKPoolStatus(1), 0);
    	CU_ASSERT_EQUAL(test_ChangeCardPIN(1), 0);      
    	CU_ASSERT_EQUAL(test_ChangeKeyPIN(1), 0);       

	CU_ASSERT_EQUAL(test_SVSClearContainer(1), 0);	
    	CU_ASSERT_EQUAL(test_Generate_PKIKeyPair(3), 0);	
	CU_ASSERT_EQUAL(test_ImportKey(1), 0);	
	CU_ASSERT_EQUAL(test_CalculatePubKeyAndIdentifyECCSignForEnvelope(1), 0);	
	CU_ASSERT_EQUAL(test_CalculatePubKey_OptimizeAndIdentifyECCSignForEnvelope_Optimize(1), 0);	
	CU_ASSERT_EQUAL(test_GetAndReleasePriMatrixAccessRight(1), 0);	
#endif
	CU_ASSERT_EQUAL(test_NoCert(1), 0);	
	CU_ASSERT_EQUAL(test_MK(1), 0);	
	CU_ASSERT_EQUAL(test_ExchangeDigitEnvelopeKeyBlob(1), 0);	

}

CU_TestInfo testcases[] = {
	{"Testing for RSA:", RSAtest},
	{"Testing for iki:", IKItest},
	{"Testing for dm:", DMtest},
	{"Testing for km:", KMtest}, 
	{"Testing for asm:", ASMtest},
	{"Testing for sym:", SYMtest},
	{"Testing for hash:", HASHtest},
	{"Testing for file:", FILEtest},

	CU_TEST_INFO_NULL
};


/****************** suite初始化过程 *******************************/
int init_suite(void)
{
	return 0;
}

int setup_suite(void) 
{ 
	return 0; 
}


/**********Suite清理过程，以便恢复原状，使结果不影响到下次运行*****/
int clean_suite(void)
{
	return 0;
}

int teardown_suite(void) 
{ 
	return 0; 
}


/***定义suite数组，包括多个suite，每个suite又会包括若干个测试方法***/
CU_SuiteInfo suites[]=
{
	{"Testing the function:", init_suite, clean_suite, setup_suite, teardown_suite, testcases},
	CU_TEST_INFO_NULL
};


/***************************测试类add接口************************/
void AddTests(void)
{
	assert(NULL!=CU_get_registry());
	assert(!CU_is_test_running());

	if(CUE_SUCCESS!=CU_register_suites(suites))
	{
		fprintf(stderr, "Register suites failed - %s ", CU_get_error_msg());
		exit(EXIT_FAILURE);
	}

	printf("AddTests end!\n");
	
}


/***************************测试类run接口************************/
int RunTest()
{
	if(CU_initialize_registry())
	{
		fprintf(stderr, "Initialization of Test Registry failed.");
		exit(EXIT_FAILURE);

	}
	else
	{
		AddTests();
		/**** Automated Mode *****************/
		CU_set_output_filename("TestMax");
		CU_list_tests_to_file();
		CU_automated_run_tests();
		/************************************/

		
		/**** Basice Mode *********************
  		 CU_basic_set_mode(CU_BRM_VERBOSE);
  		 CU_basic_run_tests();
  		 ************************************/


		/**** Console Mode*********************
  		 CU_console_run_tests();
  		 *************************************/

		CU_cleanup_registry();
		return CU_get_error();
	}

}



/******************************************************************
 * 功能描述：测试类主方法（main函数入口）
 * 参数列表：
 * 返回类型：
 ******************************************************************/
//argv数组中的第一个单元指向的字符串总是可执行程序的名字，以后的单元指向的字符串依次是程序调用的参数XXX
int main(int argc, char * argv[])
{
	int i;
	while(1){

	RunTest();
}
	return 0;
	
}
