#include "TestSDS.h"

int FunctionTest(int nMyPos, int nDefaultSelect)
{
	int nSel;

	if((nDefaultSelect < 1) || (nDefaultSelect > 6))
	{
		nSel = 1;
	}
	else
	{
		nSel = nDefaultSelect;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("功能测试:\n");
		printf("------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|基本函数测试\n");
	else
		printf("   1|基本函数测试\n");
		printf("    |    获取设备信息、随机数功能测试及分析。\n");
		printf("\n");
	if(nSel == 2)
		printf(" ->2|RSA非对称密码运算函数测试\n");
	else
		printf("   2|RSA非对称密码运算函数测试\n");
		printf("    |    RSA密钥对产生，内部和外部密钥运算，数字信封转换测试。\n");
		printf("\n");
	if(nSel == 3)
		printf(" ->3|ECC非对称密码运算函数测试\n");
	else
		printf("   3|ECC非对称密码运算函数测试\n");
		printf("    |    ECC密钥对产生，内部和外部密钥运算，密钥交换协议测试\n");
		printf("\n");
	if(nSel == 4)
		printf(" ->4|对称密码运算函数测试\n");
	else
		printf("   4|对称密码运算函数测试\n");
		printf("    |    对称密钥管理，对称算法加、解密，产生MAC值测试。\n");
		printf("\n");
	if(nSel == 5)
		printf(" ->5|杂凑运算函数测试\n");
	else
		printf("   5|杂凑运算函数测试\n");
		printf("    |    杂凑运算功能测试。\n");
		printf("\n");
	if(nSel == 6)
		printf(" ->6|用户文件操作函数测试\n");
	else
		printf("   6|用户文件操作函数测试\n");
		printf("    |    创建、删除用户文件，用户文件读写功能测试。\n");
		printf("\n");
		printf("\n");
		printf("选择功能测试类别 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetSelect(nSel, 6);

		switch(nSel)
		{
		case 1:
			nSel = BasicFuncTest(1,1);
			break;
		case 2:
			nSel = RSAFuncTest(2,1);
			break;
		case 3:
			nSel = ECCFuncTest(3,1);
			break;
		case 4:
			nSel = SymmFuncTest(4,1);
			break;
		case 5:
			nSel = HashFuncTest(5,1);
			break;
		case 6:
			nSel = FileFuncTest(6,1);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
			return OPT_EXIT;

		if(nSel == OPT_RETURN)
			return nMyPos;
	}

	return nMyPos;
}

int BasicFuncTest(int nMyPos, int nDefaultSelect)
{
	int rv;
	int nSel;

	SGD_HANDLE hSessionHandle;

	if((nDefaultSelect < 1) || (nDefaultSelect > 2)) 
		nSel = 1;
	else
		nSel = nDefaultSelect;

	//创建会话句柄
	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(rv != SDR_OK)
	{
		printf("打开会话句柄错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("基本函数测试:\n");
		printf("-------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|获取设备信息测试\n");
	else
		printf("   1|获取设备信息测试\n");
		printf("    |    获取设备出厂信息、维护信息、能力字段等信息，并打印。\n");
		printf("\n");
	if(nSel == 2)
		printf(" ->2|随机数测试\n");
	else
		printf("   2|随机数测试\n");
		printf("    |    产生随机数并对随机数质量进行分析。\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("选择测试项目 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetSelect(nSel, 2);

		switch(nSel)
		{
		case 1:
			nSel = GetDeviceInfoTest(1, hSessionHandle);
			break;
		case 2:
			nSel = GenRandomTest(2, hSessionHandle);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
		{
			SDF_CloseSession(hSessionHandle);

			return OPT_EXIT;
		}

		if(nSel == OPT_RETURN)
		{
			SDF_CloseSession(hSessionHandle);

			return nMyPos;
		}
	}

	return nMyPos;
}

int GetDeviceInfoTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	unsigned char sFirmwareVersion[32] = {0};
	unsigned int  uiFirmwareVersionLen = 32;
	unsigned char sLibraryVersion[16] = {0};
	unsigned int  uiLibraryVersionLen = 16;

	DEVICEINFO stDeviceInfo;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("获取设备信息测试:\n");
	printf("-----------------\n");
	printf("\n");

//获取设备信息
rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
if(rv != SDR_OK)
{
	printf("获取设备信息错误，错误码[0x%08x]\n", rv);
}
else
{
	printf("获取设备信息成功。\n");
	printf("\n");
	printf("    |     项目      |   返回值  \n");
	printf("   _|_______________|______________________________________________________\n");
	printf("   1|   生产厂商    | %s\n",stDeviceInfo.IssuerName);
	printf("   2|   设备型号    | %s\n",stDeviceInfo.DeviceName);
	printf("   3|  设备序列号   | %s\n",stDeviceInfo.DeviceSerial);
	printf("   4|   设备版本    | v%08x\n",stDeviceInfo.DeviceVersion);
	printf("   5| 支持标准版本  | v%d\n",stDeviceInfo.StandardVersion);
	printf("   6| 支持公钥算法  | %08x | %08x\n",stDeviceInfo.AsymAlgAbility[0],stDeviceInfo.AsymAlgAbility[1]);
	printf("   7| 支持对称算法  | %08x\n",stDeviceInfo.SymAlgAbility);
	printf("   8| 支持杂凑算法  | %08x\n",stDeviceInfo.HashAlgAbility);
	printf("   9| 用户存储空间  | %dKB\n",stDeviceInfo.BufferSize >> 10);
}

	printf("\n");

//获取固件版本
rv = SDF_GetFirmwareVersion(hSessionHandle, sFirmwareVersion, &uiFirmwareVersionLen);
if(rv != SDR_OK)
{
	printf("获取设备固件版本信息错误，错误码[0x%08x]\n", rv);
}
else
{
	printf("设备固件版本：%s\n", sFirmwareVersion);
}

//获取软件库版本
rv = SDF_GetLibraryVersion(hSessionHandle, sLibraryVersion, &uiLibraryVersionLen);
if(rv != SDR_OK)
{
	printf("获取软件库版本错误， 错误码[0x%08x]\n", rv);
}
else
{
	printf("设备软件版本：%s\n", sLibraryVersion);
}

	printf("\n");
	printf("\n按任意键返回...");
	GETCH();

	return nMyPos;
}

int GenRandomTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;
	int randLen;
	unsigned char pbOutBuffer[16384];

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("产生随机数测试:\n");
		printf("---------------\n");
		printf("\n");
		printf("根据输入的长度，产生指定长度的随机数，并进行随机数质量分析。\n");
		printf("\n");
		printf("\n输入要产生的随机数长度(默认16字节，长度范围为1-16K)，或 [退出(Q)] [返回(R)] [下一步(N)]>");
		randLen = GetInputLength(16, 1, 16384);

		if(randLen == OPT_EXIT)
			return OPT_EXIT;

		if(randLen == OPT_RETURN)
			return nMyPos;

		//随机数长度参数检查
		if((randLen < 1) || (randLen > 16384))
		{
			printf("\n程序支持的随机数长度为1-16K");

			continue;
		}

		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("产生随机数测试:\n");
		printf("---------------\n");
		printf("\n");

		rv = SDF_GenerateRandom(hSessionHandle, randLen, pbOutBuffer);
		if(rv != SDR_OK)
		{
			printf("产生随机数错误，错误码[0x%08x]\n", rv);
		}
		else
		{
			PrintData("随机数", pbOutBuffer, randLen, 16);

			printf("\n");
		}

		printf("\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;;
	}

	return nMyPos;
}

int RSAFuncTest(int nMyPos, int nDefaultSelect)
{
	unsigned int rv;
	int nSel;

	SGD_HANDLE hSessionHandle;

	if((nDefaultSelect < 1) || (nDefaultSelect > 5)) 
		nSel = 1;
	else
		nSel = nDefaultSelect;

	//创建会话句柄
	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(rv != SDR_OK)
	{
		printf("打开会话句柄错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("RSA运算函数测试:\n");
		printf("----------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|产生RSA密钥对测试\n");
	else
		printf("   1|产生RSA密钥对测试\n");
		printf("    |    产生可导出的RSA密钥对，并打印。\n");
		printf("\n");
	if(nSel == 2)
		printf(" ->2|导出RSA公钥测试\n");
	else
		printf("   2|导出RSA公钥测试\n");
		printf("    |    导出指定密钥号的RSA公钥，并打印。\n");
		printf("\n");
	if(nSel == 3)
		printf(" ->3|外部RSA密钥运算测试\n");
	else
		printf("   3|外部RSA密钥运算测试\n");
		printf("    |    使用“1 产生RSA密钥对测试”产生RSA密钥对进行运算。\n");
		printf("\n");
	if(nSel == 4)
		printf(" ->4|内部RSA密钥运算测试\n");
	else
		printf("   4|内部RSA密钥运算测试\n");
		printf("    |    使用内部RSA密钥对进行运算，并输出结果。\n");
		printf("\n");
	if(nSel == 5)
		printf(" ->5|转换数字信封测试\n");
	else
		printf("   5|转换数字信封测试\n");
		printf("    |    进行数字信封的加密密钥的密文转换，并进行验证。\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("选择测试项目 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetSelect(nSel, 5);

		switch(nSel)
		{
		case 1:
			nSel = GenRSAKeyPairTest(1, hSessionHandle);
			break;
		case 2:
			nSel = ExportRSAPukTest(2, hSessionHandle);
			break;
		case 3:
			nSel = ExtRSAOptTest(3, hSessionHandle);
			break;
		case 4:
			nSel = IntRSAOptTest(4, hSessionHandle);
			break;
		case 5:
			nSel = TransEnvelopTest(5, hSessionHandle);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
		{
			SDF_CloseSession(hSessionHandle);

			return OPT_EXIT;
		}

		if(nSel == OPT_RETURN)
		{
			SDF_CloseSession(hSessionHandle);

			return nMyPos;
		}
	}

	return nMyPos;
}

int GenRSAKeyPairTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;
	int keyLen;
	unsigned int pukLen, prkLen;
	RSArefPublicKey pubKey;
	RSArefPrivateKey priKey;
	int step = 0;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生RSA密钥对测试:\n");
			printf("------------------\n");
			printf("\n");
			printf("产生可导出的RSA公私钥对。\n");
			printf("\n");
			printf("请选择RSA密钥的模长，支持1024和2048比特。\n");
			printf("\n");
			printf("   _|___________________________________\n");
			printf("   1|  1024\n");
			printf("   2|  2048\n");
			printf("\n");
			printf("\n");
			printf("\n选择模长(默认[1024])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			keyLen = GetSelect(1, 2);

			if(keyLen == OPT_EXIT)
				return OPT_EXIT;

			if(keyLen == OPT_RETURN)
				return nMyPos;

			//密钥模长参数检查
			if((keyLen < 1) || (keyLen > 2))
			{
				printf("\n密钥模长输入参数无效\n");

				break;
			}

			if(keyLen == 2)
				keyLen = 2048;
			else
				keyLen = 1024;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生RSA密钥对测试:\n");
			printf("------------------\n");
			printf("\n");

			rv = SDF_GenerateKeyPair_RSA(hSessionHandle, keyLen, &pubKey, &priKey);
			if(rv != SDR_OK)
			{
				printf("产生RSA密钥对错误，错误码[0x%08x]\n", rv);
			}
			else
			{
				printf("产生RSA密钥对成功，并写入 data/prikey.0, data/pubkey.0\n");

				pukLen = sizeof(RSArefPublicKey);
				prkLen = sizeof(RSArefPrivateKey);

				PrintData("PUBLICKEY", (unsigned char *)&pubKey, pukLen, 16);
				PrintData("PRIVATEKEY", (unsigned char *)&priKey, prkLen, 16);

				FileWrite("data/prikey.0", "wb+", (unsigned char *)&priKey, prkLen);
				FileWrite("data/pubkey.0", "wb+", (unsigned char *)&pubKey, pukLen);
				
				printf("\n");
			}

			printf("\n");

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

int ExportRSAPukTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;
	int keyIndex;
	RSArefPublicKey signPubKey, encPubKey;
	int pukLen;
	char filename[50];

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("导出RSA公钥测试:\n");
		printf("----------------\n");
		printf("\n");
		printf("导出指定的RSA公钥，将同时导出签名公钥和加密公钥，并写入文件。\n");
		printf("\n");
		printf("\n输入要导出的RSA密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
		keyIndex = GetInputLength(1, 1, 100);

		if(keyIndex == OPT_EXIT)
			return OPT_EXIT;

		if(keyIndex == OPT_RETURN)
			return nMyPos;

		//密钥索引参数检查
		if((keyIndex < 1) || (keyIndex > 100))
		{
			printf("\n密钥索引输入参数无效，请重新输入");

			continue;
		}

		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("导出RSA公钥测试:\n");
		printf("----------------\n");
		printf("\n");

		rv = SDF_ExportSignPublicKey_RSA(hSessionHandle, keyIndex, &signPubKey);
		if(rv != SDR_OK)
		{
			printf("导出签名公钥错误，错误码[0x%08x]\n", rv);
		}
		else
		{
			pukLen = sizeof(RSArefPublicKey);
		
			printf("导出签名公钥成功，并写入文件data/signpubkey.%d\n", keyIndex);

			PrintData("SignPublicKey", (unsigned char *)&signPubKey, pukLen, 16);

			sprintf(filename, "data/signpubkey.%d", keyIndex);

			FileWrite(filename, "wb+", (unsigned char *)&signPubKey, pukLen);
		}

		rv = SDF_ExportEncPublicKey_RSA(hSessionHandle, keyIndex, &encPubKey);
		if(rv != SDR_OK)
		{
			printf("导出加密公钥错误，错误码[0x%08x]\n", rv);
		}
		else
		{
			pukLen = sizeof(RSArefPublicKey);

			printf("导出加密公钥成功，并写入文件data/encpubkey.%d\n", keyIndex);
			
			PrintData("EncPublicKey", (unsigned char *)&encPubKey, pukLen, 16);

			sprintf(filename, "data/encpubkey.%d", keyIndex);

			FileWrite(filename, "wb+", (unsigned char *)&encPubKey, pukLen);
		}
	
		printf("\n");
		printf("\n按任意键继续...");
		GETCH();
	}

	return nMyPos;
}

int ExtRSAOptTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;
	RSArefPublicKey pubKey;
	RSArefPrivateKey priKey;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int tmpLen;
	int pukLen, prkLen;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("外部RSA密钥运算测试:\n");
	printf("--------------------\n");
	printf("\n");

	prkLen = FileRead("data/prikey.0", "rb", (unsigned char *)&priKey, sizeof(priKey));
	if(prkLen < sizeof(RSArefPrivateKey))
	{
		printf("读私钥文件错误。\n");
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从文件中读取私钥成功。\n");
	}

	pukLen = FileRead("data/pubkey.0", "rb", (unsigned char *)&pubKey, sizeof(pubKey));
	if(pukLen < sizeof(RSArefPublicKey))
	{
		printf("读公钥文件错误。\n");
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从文件中读取公钥成功。\n");
	}

	inData[0] = 0;

	rv = SDF_GenerateRandom(hSessionHandle, priKey.bits / 8 - 1, &inData[1]);
	if(rv != SDR_OK)
	{
		printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从产生随机加密数据成功。\n");

		PrintData("随机加密数据", inData, priKey.bits / 8, 16);
	}

	rv = SDF_ExternalPrivateKeyOperation_RSA(hSessionHandle, &priKey, inData, priKey.bits / 8, tmpData, &tmpLen);
	if(rv != SDR_OK)
	{
		printf("私钥运算错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("私钥运算成功。\n");

		PrintData("私钥运算结果", tmpData, tmpLen, 16);
	}

	rv = SDF_ExternalPublicKeyOperation_RSA(hSessionHandle, &pubKey, tmpData, tmpLen, outData, &tmpLen);
	if(rv != SDR_OK)
	{
		printf("公钥运算错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("公钥运算成功。\n");

		PrintData("公钥运算结果", outData, tmpLen, 16);
	}

	if((priKey.bits / 8 == tmpLen) && (memcmp(inData, outData, priKey.bits / 8) == 0))
	{
		printf("结果比较成功。\n");
	}
	else
	{
		printf("结果比较失败。\n");
	}

	printf("\n");

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

int IntRSAOptTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv, keyIndex;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int tmpLen, outDataLen, encKeyBits = 0, signKeyBits = 0;
	char sPrkAuthCode[128];
	RSArefPublicKey sign_PubKey;
	RSArefPublicKey enc_PubKey;
	int step = 0;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部RSA密钥运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("指定要测试的密钥号，对随机数据进行公钥运算和私钥运算，并比较结果。\n");
			printf("\n");
			printf("\n");
			printf("\n输入RSA密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			keyIndex = GetInputLength(1, 1, 100);

			if(keyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(keyIndex == OPT_RETURN)
				return nMyPos;

			//密钥索引参数检查
			if((keyIndex < 1) || (keyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部RSA密钥运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", keyIndex);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCode, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCode[0] = '\0';
			}
			else
			{
				//口令长度检查

				if(strlen(sPrkAuthCode) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部RSA密钥运算测试:\n");
			printf("--------------------\n");
			printf("\n");

			rv = SDF_ExportSignPublicKey_RSA(hSessionHandle, keyIndex, &sign_PubKey);
			if(rv != SDR_OK)
			{
				printf("导出签名公钥错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();
				
				return nMyPos;
			}
			else
			{
				signKeyBits = sign_PubKey.bits;

				printf("导出签名公钥成功。\n");
			}
			
			rv = SDF_ExportEncPublicKey_RSA(hSessionHandle, keyIndex, &enc_PubKey);
			if(rv != SDR_OK)
			{
				printf("导出加密公钥错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}
			else
			{
				encKeyBits = enc_PubKey.bits;

				printf("导出加密公钥成功。\n");
			}

			if(strlen(sPrkAuthCode) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, keyIndex, sPrkAuthCode, (unsigned int)strlen(sPrkAuthCode));
				if(rv != SDR_OK)
				{
					printf("获取私钥访问权限错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("获取私钥访问权限成功。\n");
				}
			}
			
			if(signKeyBits > 0)
			{
				//生成随机数作为私钥操作的明文
				inData[0] = 0;

				rv = SDF_GenerateRandom(hSessionHandle, signKeyBits / 8 - 1, &inData[1]);
				if(rv != SDR_OK)
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("产生随机待加密数据成功。\n");

					PrintData("随机加密数据", inData, signKeyBits / 8, 16);
				}

				memset(tmpData, 0, sizeof(tmpData));
				tmpLen = sizeof(tmpData);

				rv = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, keyIndex, SGD_RSA_SIGN, inData, signKeyBits/8, tmpData, &tmpLen);
				if(rv != SDR_OK)
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("签名私钥运算错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("签名私钥运算成功。\n");

					PrintData("私钥运算结果", tmpData, tmpLen, 16);
				}

				memset(outData, 0, sizeof(outData));
				outDataLen = sizeof(outData);

				rv = SDF_InternalPublicKeyOperation_RSA(hSessionHandle, keyIndex, SGD_RSA_SIGN, tmpData, tmpLen, outData, &outDataLen);
				if(rv != SDR_OK)
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("签名公钥运算错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("签名公钥运算成功。\n");

					PrintData("公钥运算结果", outData, outDataLen, 16);
				}

				if((outDataLen != signKeyBits/8) || (memcmp(inData, outData, outDataLen) != 0))
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("签名公钥运算结果与明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("签名公钥运算结果与明文数据比较成功。\n");
				}
			}
			
			if(encKeyBits > 0)
			{
				//生成随机数作为加密私钥操作数据
				inData[0] = 0;

				rv = SDF_GenerateRandom(hSessionHandle, encKeyBits / 8 - 1, &inData[1]);
				if(rv != SDR_OK)
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("产生随机待加密数据成功。\n");
					PrintData("随机加密数据", inData, encKeyBits / 8, 16);
				}

				memset(tmpData, 0, sizeof(tmpData));
				tmpLen = sizeof(tmpData);

				rv = SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, keyIndex, SGD_RSA_ENC, inData, encKeyBits / 8, tmpData, &tmpLen);
				if(rv != SDR_OK)
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("加密私钥运算错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("加密私钥运算成功。\n");

					PrintData("私钥运算结果", tmpData, tmpLen, 16);
				}
				
				memset(outData, 0, sizeof(outData));
				outDataLen = sizeof(outData);

				rv = SDF_InternalPublicKeyOperation_RSA(hSessionHandle, keyIndex, SGD_RSA_ENC, tmpData, tmpLen, outData, &outDataLen);
				if(rv != SDR_OK)
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("加密公钥运算错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("加密公钥运算成功。\n");

					PrintData("加密公钥运算结果", outData, outDataLen, 16);
				}

				if((outDataLen != encKeyBits/8) || (memcmp(inData, outData, outDataLen) != 0))
				{
					if(strlen(sPrkAuthCode) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
					}

					printf("加密公钥运算结果与明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("加密公钥运算结果与明文数据比较成功。\n");
				}
			}
			
			if(strlen(sPrkAuthCode) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				if(rv != SDR_OK)
				{
					printf("释放私钥访问权限错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("释放私钥访问权限成功。\n");
				}
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

#if 0
int TransEnvelopTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	int nKeylen = 16, nKeyIndexSrc = 1, nKeyIndexDest = 1, outSrcKeyLen, outDestKeyLen;
	unsigned char pucKeySrc[512], pucKeyDest[512];
	RSArefPublicKey pubKey;
	unsigned int puiAlg[20];
	SGD_HANDLE hKeySrc, hKeyDest;
	int nSelAlg = 1;
	int nInlen = 1024, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];
	char sPrkAuthCodeSrc[128], sPrkAuthCodeDest[128];

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度产生新的会话密钥，该密钥即为原始数字信封的加密密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			//密钥字节长度检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择RSA密钥对的索引，该密钥即为原始数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndexSrc = GetInputLength(1, 1, 100);

			if(nKeyIndexSrc == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexSrc == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexSrc == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			
			//密钥索引参数检查
			if((nKeyIndexSrc < 1) || (nKeyIndexSrc > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeSrc, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeSrc[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符");

					break;
				}
			}

			step++;
			
			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择另一个RSA密钥对的索引，改密钥即为转换后的数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 2);
			nKeyIndexDest = GetInputLength(2, 1, 100);

			if(nKeyIndexDest == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexDest == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexDest == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexDest < 1) || (nKeyIndexDest > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeDest, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeDest[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeDest) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符");

					break;
				}
			}

			step++;
			
			break;
		case 5:
			printf("\n");	
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试，用于验证数字信封转换的正确性。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择对称密码算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			if(nSelAlg == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 6:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("\n");
			printf("数字信封加密密钥长度：       %2d\n", nKeylen);
			printf("原始数字信封保护密钥索引：   %2d\n", nKeyIndexSrc);
			printf("转换后数字信封保护密钥索引： %2d\n", nKeyIndexDest);
			printf("验证算法标识：               0x%08x\n", puiAlg[nSelAlg]);
			printf("测试数据长度：               %d\n", nInlen);
			printf("\n");
			printf("\n");

			memset(pIv, 0, 16);

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc, sPrkAuthCodeSrc, (unsigned int)strlen(sPrkAuthCodeSrc));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexDest, sPrkAuthCodeDest, (unsigned int)strlen(sPrkAuthCodeDest));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					if(strlen(sPrkAuthCodeSrc) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
					}

					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			memset(pucKeySrc, 0, sizeof(pucKeySrc));
			outSrcKeyLen = sizeof(pucKeySrc);

			rv = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, nKeyIndexSrc, nKeylen * 8, pucKeySrc, &outSrcKeyLen, &hKeySrc);
			if(rv == SDR_OK)
			{
				printf("产生受内部[%d]号公钥保护的会话密钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("产生受内部[%d]号公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_ExportEncPublicKey_RSA(hSessionHandle, nKeyIndexDest, &pubKey);
			if(rv == SDR_OK)
			{
				printf("导出[%d]号加密公钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导出[%d]号加密公钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pucKeyDest, 0, sizeof(pucKeyDest));
			outDestKeyLen = sizeof(pucKeyDest);

			rv = SDF_ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle, nKeyIndexSrc, &pubKey, pucKeySrc, outSrcKeyLen, pucKeyDest, &outDestKeyLen);
			if(rv == SDR_OK)
			{
				printf("数字信封转加密成功。\n");
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("数字信封转加密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_ImportKeyWithISK_RSA(hSessionHandle, nKeyIndexDest, pucKeyDest, outDestKeyLen, &hKeyDest);
			if(rv == SDR_OK)
			{
				printf("导入受[%d]号公钥保护的会话密钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导入受[%d]号公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//释放私有密钥访问控制码
			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					if(strlen(sPrkAuthCodeDest) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
					}

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			memset(pIndata, 0, sizeof(pIndata));

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				printf("产生随机加密数据成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("产生随机加密数据错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();
				
				return nMyPos;
			}

			memset(pEncdata, 0, sizeof(pEncdata));
			nEnclen = sizeof(pEncdata);

			rv = SDF_Encrypt(hSessionHandle, hKeySrc, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
			if(rv == SDR_OK)
			{
				printf("使用原始数字信封加密密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用原始数字信封加密密钥加密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pOutdata, 0, sizeof(pOutdata));
			nOutlen = sizeof(pOutdata);

			rv = SDF_Decrypt(hSessionHandle, hKeyDest, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
			if(rv == SDR_OK)
			{
				printf("使用转换后的数字信封加密密钥解密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用转换后的数字信封加密密钥解密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//不管运算比对是否相等，都要销毁密钥
			SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
			SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

			if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
			{
				printf("运算结果比较正确。\n");
			}
			else
			{
				printf("解密结果错误。\n");
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

int TransEnvelopTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	int nKeylen = 16, nKeyIndexSrc = 1, nKeyIndexDest = 1, outSrcKeyLen, outDestKeyLen;
	unsigned char pucKeySrc[512], pucKeyDest[512];
	RSArefPublicKey pubKey;
	unsigned int puiAlg[20];
	SGD_HANDLE hKeySrc, hKeyDest;
	int nSelAlg = 1;
	int nInlen = 1024, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];
	char sPrkAuthCodeSrc[128], sPrkAuthCodeDest[128];

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度产生新的会话密钥，该密钥即为原始数字信封的加密密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			//密钥字节长度检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择RSA密钥对的索引，该密钥即为原始数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndexSrc = GetInputLength(1, 1, 100);

			if(nKeyIndexSrc == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexSrc == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexSrc == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			
			//密钥索引参数检查
			if((nKeyIndexSrc < 1) || (nKeyIndexSrc > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeSrc, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeSrc[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符");

					break;
				}
			}

			step++;
			
			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择另一个RSA密钥对的索引，改密钥即为转换后的数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 2);
			nKeyIndexDest = GetInputLength(2, 1, 100);

			if(nKeyIndexDest == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexDest == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexDest == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexDest < 1) || (nKeyIndexDest > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeDest, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeDest[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeDest) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符");

					break;
				}
			}

			step++;
			
			break;
		case 5:
			printf("\n");	
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试，用于验证数字信封转换的正确性。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;

				if(stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK)
				{
					printf("  %2d | SGD_SM4_XTS\n\n", i);
					puiAlg[i++]=SGD_SM4_XTS;
				}
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择对称密码算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			if(nSelAlg == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 6:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("\n");
			printf("数字信封加密密钥长度：       %2d\n", nKeylen);
			printf("原始数字信封保护密钥索引：   %2d\n", nKeyIndexSrc);
			printf("转换后数字信封保护密钥索引： %2d\n", nKeyIndexDest);
			printf("验证算法标识：               0x%08x\n", puiAlg[nSelAlg]);
			printf("测试数据长度：               %d\n", nInlen);
			printf("\n");
			printf("\n");

			memset(pIv, 0, 16);

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc, sPrkAuthCodeSrc, (unsigned int)strlen(sPrkAuthCodeSrc));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexDest, sPrkAuthCodeDest, (unsigned int)strlen(sPrkAuthCodeDest));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					if(strlen(sPrkAuthCodeSrc) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
					}

					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			memset(pucKeySrc, 0, sizeof(pucKeySrc));
			outSrcKeyLen = sizeof(pucKeySrc);

			rv = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, nKeyIndexSrc, nKeylen * 8, pucKeySrc, &outSrcKeyLen, &hKeySrc);
			if(rv == SDR_OK)
			{
				printf("产生受内部[%d]号公钥保护的会话密钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("产生受内部[%d]号公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_ExportEncPublicKey_RSA(hSessionHandle, nKeyIndexDest, &pubKey);
			if(rv == SDR_OK)
			{
				printf("导出[%d]号加密公钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导出[%d]号加密公钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pucKeyDest, 0, sizeof(pucKeyDest));
			outDestKeyLen = sizeof(pucKeyDest);

			rv = SDF_ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle, nKeyIndexSrc, &pubKey, pucKeySrc, outSrcKeyLen, pucKeyDest, &outDestKeyLen);
			if(rv == SDR_OK)
			{
				printf("数字信封转加密成功。\n");
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("数字信封转加密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_ImportKeyWithISK_RSA(hSessionHandle, nKeyIndexDest, pucKeyDest, outDestKeyLen, &hKeyDest);
			if(rv == SDR_OK)
			{
				printf("导入受[%d]号公钥保护的会话密钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导入受[%d]号公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//释放私有密钥访问控制码
			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					if(strlen(sPrkAuthCodeDest) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
					}

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			memset(pIndata, 0, sizeof(pIndata));

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				printf("产生随机加密数据成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("产生随机加密数据错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();
				
				return nMyPos;
			}

			memset(pEncdata, 0, sizeof(pEncdata));
			nEnclen = sizeof(pEncdata);

			if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
			{
				rv = SDF_Encrypt(hSessionHandle, hKeySrc, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
			}
			else
			{
				rv = SDF_Encrypt_Ex(hSessionHandle, hKeySrc, hKeySrc, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen, nInlen);
			}

			if(rv == SDR_OK)
			{
				printf("使用原始数字信封加密密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用原始数字信封加密密钥加密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pOutdata, 0, sizeof(pOutdata));
			nOutlen = sizeof(pOutdata);

			if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
			{
				rv = SDF_Decrypt(hSessionHandle, hKeyDest, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
			}
			else
			{
				rv = SDF_Decrypt_Ex(hSessionHandle, hKeyDest, hKeyDest, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen, nEnclen);
			}

			if(rv == SDR_OK)
			{
				printf("使用转换后的数字信封加密密钥解密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用转换后的数字信封加密密钥解密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//不管运算比对是否相等，都要销毁密钥
			SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
			SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

			if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
			{
				printf("运算结果比较正确。\n");
			}
			else
			{
				printf("解密结果错误。\n");
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}

int ECCFuncTest(int nMyPos, int nDefaultSelect)
{
	int rv;
	int nSel;
	SGD_HANDLE hSessionHandle;

	if((nDefaultSelect < 1) || (nDefaultSelect > 10)) 
		nSel = 1;
	else
		nSel = nDefaultSelect;

	//创建会话句柄
	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(rv != SDR_OK)
	{
		printf("打开会话句柄错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("ECC运算函数测试:\n");
		printf("----------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf("  ->1|产生ECC密钥对测试\n");
	else
		printf("    1|产生ECC密钥对测试\n");
		printf("     |    产生可导出的ECC密钥对，并打印。\n");
		printf("\n");
	if(nSel == 2)
		printf("  ->2|导出ECC公钥测试\n");
	else
		printf("    2|导出ECC公钥测试\n");
		printf("     |    导出指定密钥号的ECC公钥，并打印。\n");
		printf("\n");
	if(nSel == 3)
		printf("  ->3|外部ECC密钥加解密运算测试\n");
	else
		printf("    3|外部ECC密钥加解密运算测试\n");
		printf("     |    使用“1 产生ECC密钥对测试”产生ECC密钥对进行加解密运算。\n");
		printf("\n");
	if(nSel == 4)
		printf("  ->4|外部ECC密钥签名验证运算测试\n");
	else
		printf("    4|外部ECC密钥签名验证运算测试\n");
		printf("     |    使用“1 产生ECC密钥对测试”产生ECC密钥对进行签名验证运算。\n");
		printf("\n");
	if(nSel == 5)
		printf("  ->5|内部ECC密钥加解密运算测试\n");
	else
		printf("    5|内部ECC密钥加解密运算测试\n");
		printf("     |    使用内部ECC密钥对进行加解密运算，并输出结果。\n");
		printf("\n");
	if(nSel == 6)
		printf("  ->6|内部ECC密钥签名验证运算测试\n");
	else
		printf("    6|内部ECC密钥签名验证运算测试\n");
		printf("     |    使用内部ECC密钥对进行签名验证运算，并输出结果。\n");
		printf("\n");
	if(nSel == 7)
		printf("  ->7|ECC密钥协商运算测试\n");
	else
		printf("    7|ECC密钥协商运算测试\n");
		printf("     |    使用ECC密钥协商运算，并测试结果。\n");
		printf("\n");
	if(nSel == 8)
		printf("  ->8|ECC数字信封转换测试\n");
	else
		printf("    8|ECC数字信封转换测试\n");
		printf("     |    使用ECC数字信封转换运算，并测试结果。\n");
		printf("\n");
	if(nSel == 9)
		printf("  ->9|ECC标准数据验证测试\n");
	else
		printf("    9|ECC标准数据验证测试\n");
		printf("     |    使用ECC标准数据进行验证运算，并测试结果。\n");
		printf("\n");
	if(nSel == 10)
		printf(" ->10|ECC标准数据解密测试\n");
	else
		printf("   10|ECC标准数据解密测试\n");
		printf("     |    使用ECC标准数据解密运算，并测试结果。\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("选择测试项目 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetInputLength(nSel, 1, 10);

		switch(nSel)
		{
		case 1:
			nSel = GenECCKeyPairTest(1, hSessionHandle);
			break;
		case 2:
			nSel = ExportECCPukTest(2, hSessionHandle);
			break;
		case 3:
			nSel = ExtECCOptTest(3, hSessionHandle);
			break;
		case 4:
			nSel = ExtECCSignTest(4, hSessionHandle);
			break;
		case 5:
			nSel = IntECCOptTest(5, hSessionHandle);
			break;
		case 6:
			nSel = IntECCSignTest(6, hSessionHandle);
			break;
		case 7:
			nSel = ECCAgreementTest(7, hSessionHandle);
			break;
		case 8:
			nSel = ECCTransEnvelopTest(8, hSessionHandle);
			break;
		case 9:
			nSel = ECCStdDataVerifyTest(9, hSessionHandle);
			break;
		case 10:
			nSel = ECCStdDataDecTest(10, hSessionHandle);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
		{
			SDF_CloseSession(hSessionHandle);

			return OPT_EXIT;
		}

		if(nSel == OPT_RETURN)
		{
			SDF_CloseSession(hSessionHandle);

			return nMyPos;
		}
	}

	return nMyPos;
}

int GenECCKeyPairTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv, keyLen;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	int pukLen, prkLen;

	keyLen = 256;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("产生ECC密钥对测试:\n");
	printf("------------------\n");
	printf("\n");

	rv = SDF_GenerateKeyPair_ECC(hSessionHandle, SGD_SM2_3, keyLen, &pubKey, &priKey);
	if(rv != SDR_OK)
	{
		printf("产生ECC密钥对错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("产生ECC密钥对成功，并写入 data/prikey_ecc.0, data/pubkey_ecc.0\n");

		pukLen = sizeof(ECCrefPublicKey);
		prkLen = sizeof(ECCrefPrivateKey);
		
		PrintData("PUBLICKEY", (unsigned char *)&pubKey, pukLen, 16);
		PrintData("PRIVATEKEY", (unsigned char *)&priKey, prkLen, 16);

		FileWrite("data/prikey_ecc.0", "wb+", (unsigned char *)&priKey, prkLen);
		FileWrite("data/pubkey_ecc.0", "wb+", (unsigned char *)&pubKey, pukLen);

		printf("\n");
	}

	printf("\n");

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

int ExportECCPukTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv, keyIndex;
	ECCrefPublicKey signPubKey, encPubKey;
	int pukLen;
	char filename[50];
	
	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("导出ECC公钥测试:\n");
		printf("----------------\n");
		printf("\n");
		printf("导出指定的ECC公钥，将同时导出签名公钥和加密公钥，并写入文件。\n");
		printf("\n");
		printf("\n输入要导出的ECC密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
		keyIndex = GetInputLength(1, 1, 100);

		if(keyIndex == OPT_EXIT)
			return OPT_EXIT;

		if(keyIndex == OPT_RETURN)
			return nMyPos;

		//密钥索引参数检查
		if((keyIndex < 1) || (keyIndex > 100))
		{
			printf("\n密钥索引输入参数无效，请重新输入");

			continue;
		}

		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("导出ECC公钥测试:\n");
		printf("----------------\n");
		printf("\n");

		rv = SDF_ExportSignPublicKey_ECC(hSessionHandle, keyIndex, &signPubKey);
		if(rv != SDR_OK)
		{
			printf("导出签名公钥错误，错误码[0x%08x]\n", rv);
		}
		else
		{
			pukLen = sizeof(ECCrefPublicKey);

			printf("导出签名公钥成功，并写入文件data/signpubkey_ecc.%d\n", keyIndex);

			PrintData("SignPublicKey", (unsigned char *)&signPubKey, pukLen, 16);

			sprintf(filename, "data/signpubkey_ecc.%d", keyIndex);
			FileWrite(filename, "wb+", (unsigned char *)&signPubKey, pukLen);
		}

		rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, keyIndex, &encPubKey);
		if(rv != SDR_OK)
		{
			printf("导出加密公钥错误，错误码[0x%08x]\n", rv);
		}
		else
		{
			pukLen = sizeof(ECCrefPublicKey);

			printf("导出加密公钥成功，并写入文件data/encpubkey_ecc.%d\n", keyIndex);

			PrintData("EncPublicKey",(unsigned char *)&encPubKey, pukLen, 16);

			sprintf(filename, "data/encpubkey_ecc.%d", keyIndex);
			FileWrite(filename, "wb+", (unsigned char *)&encPubKey, pukLen);
		}

		printf("\n");

		printf("\n按任意键继续...");
		GETCH();
	}

	return nMyPos;
}

int ExtECCOptTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int outDataLen;
	int pukLen, prkLen;
	unsigned int inPlainLen;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("外部ECC密钥加解密运算测试:\n");
	printf("--------------------\n");
	printf("\n");

	prkLen = FileRead("data/prikey_ecc.0", "rb", (unsigned char *)&priKey, sizeof(priKey));
	if(prkLen < sizeof(ECCrefPrivateKey))
	{
		printf("读私钥文件错误。\n");
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从文件中读取私钥成功。\n");
	}

	pukLen = FileRead("data/pubkey_ecc.0", "rb", (unsigned char *)&pubKey, sizeof(pubKey));
	if(pukLen < sizeof(ECCrefPublicKey))
	{
		printf("读公钥文件错误。\n");
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从文件中读取公钥成功。\n");
	}

	//通过生成随机数从而设定明文数据长度
	rv = SDF_GenerateRandom(hSessionHandle, 1, &inData[0]);
	if(rv != SDR_OK)
	{
		printf("产生随机数错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}

	inPlainLen = (inData[0] % ECCref_MAX_CIPHER_LEN) + 1;

	memset(inData, 0, sizeof(inData));

	rv = SDF_GenerateRandom(hSessionHandle, inPlainLen, &inData[0]);
	if(rv != SDR_OK)
	{
		printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("产生随机加密数据成功。\n");

		PrintData("随机加密数据", inData, inPlainLen, 16);
	}

	memset(tmpData, 0, sizeof(tmpData));

	rv = SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, &pubKey, inData, inPlainLen, (ECCCipher *)tmpData);
	if(rv != SDR_OK)
	{
		printf("公钥钥运算错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("公钥运算成功。\n");
	}

	memset(outData, 0, sizeof(outData));
	outDataLen = sizeof(outData);

	rv = SDF_ExternalDecrypt_ECC(hSessionHandle, SGD_SM2_3, &priKey, (ECCCipher *)tmpData, outData, &outDataLen);
	if(rv != SDR_OK)
	{
		printf("私钥运算错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("私钥运算成功。\n");

		PrintData("私钥运算结果", outData, outDataLen, 16);
	}

	if((inPlainLen != outDataLen) || (memcmp(inData, outData, outDataLen) != 0))
	{
		printf("结果比较失败。\n");
	}
	else
	{
		printf("结果比较成功。\n");
	}

	printf("\n");
	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

int ExtECCSignTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	unsigned char inData[512], tmpData[512];
	int pukLen, prkLen;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("外部ECC密钥签名验证运算测试:\n");
	printf("--------------------\n");
	printf("\n");

	prkLen = FileRead("data/prikey_ecc.0", "rb", (unsigned char *)&priKey, sizeof(ECCrefPrivateKey));
	if(prkLen < sizeof(ECCrefPrivateKey))
	{
		printf("读私钥文件错误。\n");
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从文件中读取私钥成功。\n");
	}

	pukLen = FileRead("data/pubkey_ecc.0", "rb", (unsigned char *)&pubKey, sizeof(ECCrefPublicKey));
	if(pukLen < sizeof(ECCrefPublicKey))
	{
		printf("读公钥文件错误。\n");
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("从文件中读取公钥成功。\n");
	}

	memset(inData, 0, sizeof(inData));

	rv = SDF_GenerateRandom(hSessionHandle, priKey.bits / 8 - 1, &inData[1]);
	if(rv != SDR_OK)
	{
		printf("产生随机签名数据错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("产生随机签名数据成功。\n");

		PrintData("随机签名数据", inData, priKey.bits / 8, 16);
	}

	memset(tmpData, 0, sizeof(tmpData));

	rv = SDF_ExternalSign_ECC(hSessionHandle, SGD_SM2_1, &priKey, inData, priKey.bits/8, (ECCSignature *)tmpData);
	if(rv != SDR_OK)
	{
		printf("签名运算错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("签名运算成功。\n");

		PrintData("私钥签名运算结果", tmpData, sizeof(ECCSignature), 16);
	}

	rv = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &pubKey, inData, priKey.bits/8, (ECCSignature *)tmpData);
	if(rv != SDR_OK)
	{
		printf("验证签名运算错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETANYKEY();

		return nMyPos;
	}
	else
	{
		printf("验证签名运算成功。\n");
	}

	printf("\n");
	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

int IntECCOptTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv, keyIndex;
	ECCrefPublicKey encPubKey;
	unsigned char inData[512], outData[512], tmpData[512];
	unsigned int outDataLen;
	char sPrkAuthCode[128];
	int nKeyLen = 32;
	int uiDataLength;
	int step = 0;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥对加解密运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("指定要测试的密钥号，对随机数据进行公钥运算和私钥运算，并比较结果。\n");
			printf("\n");
			printf("\n");
			printf("\n输入ECC密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			keyIndex = GetInputLength(1, 1, 100);

			if(keyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(keyIndex == OPT_RETURN)
				return nMyPos;

			//密钥索引参数检查
			if((keyIndex < 1) || (keyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥对加解密运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("输入[%d]号ECC密钥对的“私钥访问控制码”。\n", keyIndex);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCode, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCode[0] = '\0';
			}
			else
			{
				//口令长度检查

				if(strlen(sPrkAuthCode) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥对加解密运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("请选择输入数据字节长度，长度范围(1 - %d)。\n", ECCref_MAX_CIPHER_LEN);
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[32])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			uiDataLength = GetInputLength(32, 1, ECCref_MAX_CIPHER_LEN);

			if(uiDataLength == OPT_EXIT)
				return OPT_EXIT;

			if(uiDataLength == OPT_RETURN)
				return nMyPos;

			if(uiDataLength == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else
			{
				//输入数据长度参数检查
				if((uiDataLength < 1) || (uiDataLength > ECCref_MAX_CIPHER_LEN))
				{
					printf("\n输入数据长度范围要求为(1 - %d)\n", ECCref_MAX_CIPHER_LEN);

					break;				
				}
			}

			step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥对加解密运算测试:\n");
			printf("--------------------\n");
			printf("\n");

			//导出ECC加密公钥
			rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, keyIndex, &encPubKey);
			if(rv != SDR_OK)
			{
				printf("导出加密公钥错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}

			rv = SDF_GenerateRandom(hSessionHandle, uiDataLength, &inData[0]);
			if(rv != SDR_OK)
			{
				printf("产生随机加密数据错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();
				
				return nMyPos;
			}
			else
			{
				printf("产生随机加密数据成功。\n");

				PrintData("随机加密数据", inData, uiDataLength, 16);
			}

			printf("\n");

			if(strlen(sPrkAuthCode) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, keyIndex, sPrkAuthCode, (unsigned int)strlen(sPrkAuthCode));
				if(rv != SDR_OK)
				{
					printf("获取私钥访问权限错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("获取私钥访问权限成功。\n");
				}
			}

			memset(tmpData, 0, sizeof(tmpData));

			rv = SDF_InternalEncrypt_ECC(hSessionHandle, keyIndex, SGD_SM2_3, inData, uiDataLength, (ECCCipher *)tmpData);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCode) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				}

				printf("公钥钥运算错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}
			else
			{
				printf("公钥运算成功。\n");
			}

			rv = SDF_InternalDecrypt_ECC(hSessionHandle, keyIndex, SGD_SM2_3, (ECCCipher *)tmpData, outData, &outDataLen);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCode) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				}

				printf("私钥运算错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}
			else
			{
				printf("私钥运算成功。\n");

				PrintData("私钥运算结果", outData, outDataLen, 16);
			}

			if(strlen(sPrkAuthCode) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				if(rv != SDR_OK)
				{
					printf("释放私钥访问权限错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("释放私钥访问权限成功。\n");
				}
			}

			if((uiDataLength != outDataLen) || (memcmp(inData, outData, outDataLen) != 0))
			{
				printf("结果比较失败。\n");
			}
			else
			{
				printf("结果比较成功。\n");
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

int IntECCSignTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv, keyIndex;
	ECCrefPublicKey pubKey;
	unsigned char inData[512], tmpData[512];
	char sPrkAuthCode[128];
	int step = 0;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥签名验证运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("指定要测试的密钥号，对随机数据进行签名运算和验证签名运算。\n");
			printf("\n");
			printf("\n");
			printf("\n输入ECC密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			keyIndex = GetInputLength(1, 1, 100);

			if(keyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(keyIndex == OPT_RETURN)
				return nMyPos;

			//密钥索引参数检查
			if((keyIndex < 1) || (keyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥签名验证运算测试:\n");
			printf("--------------------\n");
			printf("\n");
			printf("输入[%d]号ECC密钥对的“私钥访问控制码”。\n", keyIndex);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCode, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCode[0] = '\0';
			}
			else
			{
				//口令长度检查

				if(strlen(sPrkAuthCode) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;
			
			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部ECC密钥签名验证运算测试:\n");
			printf("--------------------\n");
			printf("\n");

			rv = SDF_ExportSignPublicKey_ECC(hSessionHandle, keyIndex, &pubKey);
			if(rv != SDR_OK)
			{
				printf("导出签名公钥错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}

			if(strlen(sPrkAuthCode) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, keyIndex, sPrkAuthCode, (unsigned int)strlen(sPrkAuthCode));
				if(rv != SDR_OK)
				{
					printf("获取私钥访问权限错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("获取私钥访问权限成功。\n");
				}
			}

			memset(inData, 0, sizeof(inData));

			rv = SDF_GenerateRandom(hSessionHandle, pubKey.bits / 8 - 1, &inData[1]);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCode) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				}

				printf("产生随机签名数据错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}
			else
			{
				printf("产生随机签名数据成功。\n");

				PrintData("随机签名数据", inData, pubKey.bits / 8, 16);
			}

			memset(tmpData, 0, sizeof(tmpData));

			rv = SDF_InternalSign_ECC(hSessionHandle, keyIndex, inData, pubKey.bits / 8, (ECCSignature *)tmpData);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCode) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				}

				printf("签名运算错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}
			else
			{
				printf("签名运算成功。\n");

				PrintData("签名运算结果", tmpData, sizeof(ECCSignature), 16);
			}

			rv = SDF_InternalVerify_ECC(hSessionHandle, keyIndex, inData, pubKey.bits / 8, (ECCSignature *)tmpData);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCode) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				}

				printf("验证签名运算错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETANYKEY();

				return nMyPos;
			}
			else
			{
				printf("验证签名运算成功。\n");
				
			}

			if(strlen(sPrkAuthCode) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, keyIndex);
				if(rv != SDR_OK)
				{
					printf("释放私钥访问权限错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETANYKEY();

					return nMyPos;
				}
				else
				{
					printf("释放私钥访问权限成功。\n");
				}
			}
			
			printf("\n");
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}

#if 0
int ECCAgreementTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	int nKeylen, nKeyIndexSrc, nKeyIndexDest=1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen = 1024, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];
	char sPrkAuthCodeSrc[128], sPrkAuthCodeDest[128];

	char pucSrcID[128];
	unsigned int uiSrcIDLength;
	char pucDestID[128];
	unsigned int uiDestIDLength;

	ECCrefPublicKey ECC_srcPubKey;
	ECCrefPublicKey ECC_srcTmpPubKey;
	SGD_HANDLE phAgreementHandle = NULL;
	SGD_HANDLE srcKeyHandle;

	ECCrefPublicKey ECC_destPubKey;
	ECCrefPublicKey ECC_destTmpPubKey;
	SGD_HANDLE destKeyHandle;


	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度协商会话密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			//密钥长度参数检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}

			step++;
			
			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择密钥协商发起方的密钥对的索引。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndexSrc = GetInputLength(1, 1, 100);

			if(nKeyIndexSrc == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexSrc == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexSrc == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexSrc < 1) || (nKeyIndexSrc > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");
				
				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商发起方的[%d]号ECC密钥对的“私钥访问控制码”。\n", nKeyIndexSrc);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeSrc, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeSrc[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}
			
			step++;
			
			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商发起方的ID标识参数，字节长度范围为(1 - 64)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥协商发起方的ID标识参数，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetString(pucSrcID, 64);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				pucSrcID[0] = '\0';
			}
			else
			{
				if((strlen(pucSrcID) < 1) || (strlen(pucSrcID) > 64))
				{
					printf("\nID标识参数，字节长度范围为(1 - 64)\n");

					break;
				}
			}

			step++;
			
			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择密钥协商响应方的密钥对的索引。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 2);
			nKeyIndexDest = GetInputLength(2, 1, 100);

			if(nKeyIndexDest == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexDest == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexDest == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexDest < 1) || (nKeyIndexDest > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 5:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商响应方的[%d]号ECC密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeDest, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeDest[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeDest) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;

			break;
		case 6:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商响应方的ID标识参数，字节长度范围为(1 - 64)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥协商响应方的ID标识参数，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetString(pucDestID, 64);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				pucDestID[0] = '\0';
			}
			else
			{
				if((strlen(pucDestID) < 1) || (strlen(pucDestID) > 64))
				{
					printf("\nID标识参数，字节长度范围为(1 - 64)\n");

					break;
				}
			}

			step++;
			
			break;
		case 7:
			printf("\n");	
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试，用于验证密钥协商的正确性。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择对称密码算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			if(nSelAlg == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 8:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择密钥协商的对称加解密测试数据长度，程序支持的最大长度为16K。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 256);
			nInlen = GetInputLength(256, 8, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 9:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("\n");
			printf("ECC密钥协商对称密钥密钥长度：       %2d\n", nKeylen);
			printf("ECC密钥协商发起方密钥对索引：       %2d\n", nKeyIndexSrc);
			printf("ECC密钥协商响应方密钥对索引：       %2d\n", nKeyIndexDest);
			printf("验证算法标识：               0x%08x\n", puiAlg[nSelAlg]);
			printf("测试数据长度：               %d\n", nInlen);
			printf("\n");
			printf("\n");

			memset(pIv, 0, 16);

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc, sPrkAuthCodeSrc, (unsigned int)strlen(sPrkAuthCodeSrc));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexSrc, rv);
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexDest, sPrkAuthCodeDest, (unsigned int)strlen(sPrkAuthCodeDest));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					if(strlen(sPrkAuthCodeSrc) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
					}

					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexDest, rv);
					GETCH();

					return nMyPos;
				}
			}

			//调用密钥协商接口函数
			uiSrcIDLength = (unsigned int)strlen(pucSrcID);
			uiDestIDLength = (unsigned int)strlen(pucDestID);

			//发起方
			rv = SDF_GenerateAgreementDataWithECC(hSessionHandle, nKeyIndexSrc, nKeylen * 8, pucSrcID, uiSrcIDLength, &ECC_srcPubKey, &ECC_srcTmpPubKey, &phAgreementHandle);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("发起方产生密钥协商参数错误，错误码[0x%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			else
			{
				printf("发起方产生密钥协商参数成功\n");
			}

			//响应方
			rv = SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, nKeyIndexDest, nKeylen * 8, pucDestID, uiDestIDLength, pucSrcID, uiSrcIDLength, &ECC_srcPubKey, &ECC_srcTmpPubKey, \
														&ECC_destPubKey, &ECC_destTmpPubKey, &destKeyHandle);
			if(rv != SDR_OK)
			{
				//释放密钥协商句柄phAgreementHandle所指向的内存空间
				if(phAgreementHandle != NULL)
				{
					free(phAgreementHandle);
				}

				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("响应方产生协商数据并计算会话密钥错误，[0x%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			else
			{
				printf("响应方产生协商数据并计算会话密钥成功\n");
			}
			
			//发起方
			rv = SDF_GenerateKeyWithECC(hSessionHandle, pucDestID, uiDestIDLength, &ECC_destPubKey, &ECC_destTmpPubKey, phAgreementHandle, &srcKeyHandle);
			if(rv != SDR_OK)
			{
				//销毁响应方对称密钥句柄
				SDF_DestroyKey(hSessionHandle, destKeyHandle);

				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("发起方计算会话密钥错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			else
			{
				printf("发起方计算会话密钥成功\n");
			}

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功\n", nKeyIndexSrc);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

					if(strlen(sPrkAuthCodeDest) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
					}

					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexSrc, rv);
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功\n", nKeyIndexDest);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexDest, rv);
					GETCH();

					return nMyPos;
				}
			}

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				printf("产生随机加密数据成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

				printf("产生随机加密数据错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}

			rv = SDF_Encrypt(hSessionHandle, srcKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
			if(rv == SDR_OK)
			{
				printf("使用密钥协商发起方会话密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

				printf("使用密钥协商发起方会话密钥加密错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}

			rv = SDF_Decrypt(hSessionHandle, destKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
			if(rv == SDR_OK)
			{
				printf("使用密钥协商响应方会话密钥解密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

				printf("使用密钥协商响应方会话密钥解密错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			
			//不管运算比对是否相等，都要销毁密钥
			SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
			SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

			if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
			{
				printf("运算结果比较正确。\n");
			}
			else
			{
				printf("解密结果错误。\n");
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

int ECCAgreementTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	int nKeylen, nKeyIndexSrc, nKeyIndexDest=1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen = 1024, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];
	char sPrkAuthCodeSrc[128], sPrkAuthCodeDest[128];

	char pucSrcID[128];
	unsigned int uiSrcIDLength;
	char pucDestID[128];
	unsigned int uiDestIDLength;

	ECCrefPublicKey ECC_srcPubKey;
	ECCrefPublicKey ECC_srcTmpPubKey;
	SGD_HANDLE phAgreementHandle = NULL;
	SGD_HANDLE srcKeyHandle;

	ECCrefPublicKey ECC_destPubKey;
	ECCrefPublicKey ECC_destTmpPubKey;
	SGD_HANDLE destKeyHandle;


	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度协商会话密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			//密钥长度参数检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}

			step++;
			
			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择密钥协商发起方的密钥对的索引。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndexSrc = GetInputLength(1, 1, 100);

			if(nKeyIndexSrc == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexSrc == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexSrc == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexSrc < 1) || (nKeyIndexSrc > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");
				
				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商发起方的[%d]号ECC密钥对的“私钥访问控制码”。\n", nKeyIndexSrc);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeSrc, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeSrc[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}
			
			step++;
			
			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商发起方的ID标识参数，字节长度范围为(1 - 64)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥协商发起方的ID标识参数，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetString(pucSrcID, 64);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				pucSrcID[0] = '\0';
			}
			else
			{
				if((strlen(pucSrcID) < 1) || (strlen(pucSrcID) > 64))
				{
					printf("\nID标识参数，字节长度范围为(1 - 64)\n");

					break;
				}
			}

			step++;
			
			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择密钥协商响应方的密钥对的索引。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 2);
			nKeyIndexDest = GetInputLength(2, 1, 100);

			if(nKeyIndexDest == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexDest == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexDest == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexDest < 1) || (nKeyIndexDest > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 5:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商响应方的[%d]号ECC密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeDest, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeDest[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeDest) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;

			break;
		case 6:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入密钥协商响应方的ID标识参数，字节长度范围为(1 - 64)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥协商响应方的ID标识参数，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetString(pucDestID, 64);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				pucDestID[0] = '\0';
			}
			else
			{
				if((strlen(pucDestID) < 1) || (strlen(pucDestID) > 64))
				{
					printf("\nID标识参数，字节长度范围为(1 - 64)\n");

					break;
				}
			}

			step++;
			
			break;
		case 7:
			printf("\n");	
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试，用于验证密钥协商的正确性。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;

				if(stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK)
				{
					printf("  %2d | SGD_SM4_XTS\n\n", i);
					puiAlg[i++]=SGD_SM4_XTS;
				}
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择对称密码算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			if(nSelAlg == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 8:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择密钥协商的对称加解密测试数据长度，程序支持的最大长度为16K。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 256);
			nInlen = GetInputLength(256, 8, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 9:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC密钥协商运算测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("\n");
			printf("ECC密钥协商对称密钥密钥长度：       %2d\n", nKeylen);
			printf("ECC密钥协商发起方密钥对索引：       %2d\n", nKeyIndexSrc);
			printf("ECC密钥协商响应方密钥对索引：       %2d\n", nKeyIndexDest);
			printf("验证算法标识：               0x%08x\n", puiAlg[nSelAlg]);
			printf("测试数据长度：               %d\n", nInlen);
			printf("\n");
			printf("\n");

			memset(pIv, 0, 16);

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc, sPrkAuthCodeSrc, (unsigned int)strlen(sPrkAuthCodeSrc));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexSrc, rv);
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexDest, sPrkAuthCodeDest, (unsigned int)strlen(sPrkAuthCodeDest));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					if(strlen(sPrkAuthCodeSrc) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
					}

					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexDest, rv);
					GETCH();

					return nMyPos;
				}
			}

			//调用密钥协商接口函数
			uiSrcIDLength = (unsigned int)strlen(pucSrcID);
			uiDestIDLength = (unsigned int)strlen(pucDestID);

			//发起方
			rv = SDF_GenerateAgreementDataWithECC(hSessionHandle, nKeyIndexSrc, nKeylen * 8, pucSrcID, uiSrcIDLength, &ECC_srcPubKey, &ECC_srcTmpPubKey, &phAgreementHandle);
			if(rv != SDR_OK)
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("发起方产生密钥协商参数错误，错误码[0x%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			else
			{
				printf("发起方产生密钥协商参数成功\n");
			}

			//响应方
			rv = SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, nKeyIndexDest, nKeylen * 8, pucDestID, uiDestIDLength, pucSrcID, uiSrcIDLength, &ECC_srcPubKey, &ECC_srcTmpPubKey, \
														&ECC_destPubKey, &ECC_destTmpPubKey, &destKeyHandle);
			if(rv != SDR_OK)
			{
				//释放密钥协商句柄phAgreementHandle所指向的内存空间
				if(phAgreementHandle != NULL)
				{
					free(phAgreementHandle);
				}

				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("响应方产生协商数据并计算会话密钥错误，[0x%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			else
			{
				printf("响应方产生协商数据并计算会话密钥成功\n");
			}
			
			//发起方
			rv = SDF_GenerateKeyWithECC(hSessionHandle, pucDestID, uiDestIDLength, &ECC_destPubKey, &ECC_destTmpPubKey, phAgreementHandle, &srcKeyHandle);
			if(rv != SDR_OK)
			{
				//销毁响应方对称密钥句柄
				SDF_DestroyKey(hSessionHandle, destKeyHandle);

				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("发起方计算会话密钥错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			else
			{
				printf("发起方计算会话密钥成功\n");
			}

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功\n", nKeyIndexSrc);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

					if(strlen(sPrkAuthCodeDest) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
					}

					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexSrc, rv);
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功\n", nKeyIndexDest);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

					printf("获取[%d]号私钥访问权限错误，错误码[0x%08x]\n", nKeyIndexDest, rv);
					GETCH();

					return nMyPos;
				}
			}

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				printf("产生随机加密数据成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

				printf("产生随机加密数据错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}

			if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
			{
				rv = SDF_Encrypt(hSessionHandle, srcKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
			}
			else
			{
				rv = SDF_Encrypt_Ex(hSessionHandle, srcKeyHandle, srcKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen, nInlen);		
			}

			if(rv == SDR_OK)
			{
				printf("使用密钥协商发起方会话密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

				printf("使用密钥协商发起方会话密钥加密错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}

			if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
			{
				rv = SDF_Decrypt(hSessionHandle, destKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
			}
			else
			{
				rv = SDF_Decrypt_Ex(hSessionHandle, destKeyHandle, destKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen, nEnclen);
			}

			if(rv == SDR_OK)
			{
				printf("使用密钥协商响应方会话密钥解密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

				printf("使用密钥协商响应方会话密钥解密错误，[%08x]\n", rv);
				GETCH();

				return nMyPos;
			}
			
			//不管运算比对是否相等，都要销毁密钥
			SDF_DestroyKey(hSessionHandle, srcKeyHandle);	//销毁原密钥
			SDF_DestroyKey(hSessionHandle, destKeyHandle);	//销毁新密钥

			if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
			{
				printf("运算结果比较正确。\n");
			}
			else
			{
				printf("解密结果错误。\n");
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}

//ECC标准数据验证测试
int ECCStdDataVerifyTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;

	unsigned char xa[32] = {0x5C,0xA4,0xE4,0x40,0xC5,0x08,0xC4,0x5F,0xE7,0xD7,0x58,0xAB,0x10,0xC4,0x5D,0x82,0x37,0xC4,0xF9,0x55,0x9F,0x7D,0x46,0x61,0x85,0xF2,0x95,0x39,0x9F,0x0A,0xA3,0x7D};
	unsigned char ya[32] = {0x59,0xAD,0x8A,0x3C,0xD1,0x79,0x03,0x28,0x76,0x81,0xBF,0x9D,0x21,0xDA,0x2E,0xB3,0x16,0xA0,0xCE,0x8F,0xD4,0x1C,0x89,0xCE,0x1E,0x2B,0x3F,0x1B,0x8E,0x04,0x1A,0xBA};
	
	//标准数据
	unsigned char e[32] = {0x38,0x54,0xC4,0x63,0xFA,0x3F,0x73,0x78,0x36,0x21,0xB1,0xCE,0x4E,0xF8,0x3F,0x7C,0x78,0x04,0x8A,0xAC,0x79,0xB2,0x21,0xFC,0xDD,0x29,0x08,0x66,0xCC,0x13,0x11,0x74};

	//标准签名数据
	unsigned char r[32] = {0x6E,0x5D,0xB4,0x9D,0xBD,0x09,0x92,0xB9,0x70,0x40,0x08,0x0A,0x96,0x00,0x3C,0x72,0x1C,0xDB,0x9C,0xF6,0x4C,0x88,0xD7,0x43,0x21,0xFC,0x2F,0x63,0x0A,0xDF,0x37,0x74};
	unsigned char s[32] = {0x2F,0x6D,0xFF,0x45,0x3D,0xFC,0x8D,0x7A,0x50,0x6D,0x3F,0x52,0x30,0x1B,0xEE,0x52,0x9E,0x62,0xFD,0xDD,0x38,0x94,0x8F,0x0D,0x5D,0x2C,0xBC,0xBC,0x55,0x90,0x0C,0xFA};

	ECCrefPublicKey ECC_PubKey;
	ECCSignature ECC_SignatureValue;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("ECC标准数据验证测试:\n");
	printf("-----------------\n");
	printf("\n");
	printf("\n");
	printf("使用ECC标准数据进行验证运算，并测试结果。\n");
	printf("\n");
	printf("\n");


	memset(&ECC_PubKey, 0, sizeof(ECCrefPublicKey));
	memcpy(ECC_PubKey.x, xa, 32);
	memcpy(ECC_PubKey.y, ya, 32);
	ECC_PubKey.bits = 256;

	memset(&ECC_SignatureValue, 0, sizeof(ECCSignature));
	memcpy(ECC_SignatureValue.r, r, 32);
	memcpy(ECC_SignatureValue.s, s, 32);

	//验证签名运算
	rv = SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, &ECC_PubKey, e, 32, &ECC_SignatureValue);
	if(rv != SDR_OK)
	{
		printf("ECC标准数据验证错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		printf("ECC标准数据验证成功\n");
	}

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

//ECC标准数据解密测试
int ECCStdDataDecTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;

	unsigned char da[32] = {0xE7,0xCB,0x09,0x60,0x6A,0x53,0x32,0x0B,0x34,0x7F,0x61,0xF3,0xF1,0x42,0xDC,0xB1,0x18,0xF7,0x23,0xA9,0xBC,0x27,0x87,0x9F,0x28,0x05,0xBE,0x77,0x8F,0x24,0xAE,0xE5};
	
	//标准数据
	unsigned char P[32] = {0xEA,0x4E,0xC3,0x52,0xF0,0x76,0xA6,0xBE};

	//标准密文数据
	unsigned char cx[32] = {0x9E,0x2A,0x4A,0x1A,0xA4,0xCF,0x77,0x26,0x22,0xAB,0xBB,0xF1,0xC6,0xD6,0x61,0xEE,0x58,0xFF,0x01,0xFF,0x98,0x43,0x78,0x2E,0x5A,0x63,0x18,0x5A,0xBF,0x6C,0x2E,0xFA};
	unsigned char cy[32] = {0x9B,0x2D,0x59,0xB2,0xB1,0xE0,0xD0,0xA7,0x95,0xBF,0xEF,0x53,0xFA,0xBB,0x24,0xC0,0x3A,0x02,0x26,0x57,0x51,0xB8,0x20,0x59,0x12,0x00,0xF0,0xD3,0x1C,0x55,0x1E,0xD6};
	unsigned char cc[32] = {0x7D,0xFD,0xFC,0x65,0xCC,0x9D,0xF7,0xD6};
	unsigned char cM[32] = {0x28,0x7D,0x5B,0xF3,0x35,0x8B,0xED,0x99,0x28,0x81,0xB6,0x9F,0xBA,0x13,0xC8,0xAF,0x76,0xEF,0xC1,0x57,0x45,0x5D,0xB8,0x1E,0xCF,0xAC,0xC7,0xB4,0x43,0xEA,0x1D,0xB0};

	ECCrefPrivateKey ECC_PriKey;
	ECCCipher ECC_CipherData;

	//解密结果
	unsigned char pucOutData[ECCref_MAX_CIPHER_LEN] = {0};
	unsigned int uiOutDataLen;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("ECC标准数据解密测试:\n");
	printf("-----------------\n");
	printf("\n");
	printf("\n");
	printf("使用ECC标准数据进行解密运算，并测试结果。\n");
	printf("\n");
	printf("\n");

	memset(&ECC_PriKey, 0, sizeof(ECCrefPrivateKey));
	memcpy(ECC_PriKey.D, da, 32);
	ECC_PriKey.bits = 256;

	memset(&ECC_CipherData, 0, sizeof(ECCCipher));
	ECC_CipherData.clength = 8;
	memcpy(ECC_CipherData.x, cx, 32);
	memcpy(ECC_CipherData.y, cy, 32);
	memcpy(ECC_CipherData.C, cc, 8);
	memcpy(ECC_CipherData.M, cM, 32);


	//ECC解密运算
	rv = SDF_ExternalDecrypt_ECC(hSessionHandle, SGD_SM2_3, &ECC_PriKey, &ECC_CipherData, pucOutData, &uiOutDataLen);
	if(rv != SDR_OK)
	{
		printf("ECC解密运算错误，错误码[0x%08x]\n", rv);

		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	//解密结果与标准明文比对
	if((uiOutDataLen != 8) || (memcmp(P, pucOutData, 8) != 0))
	{
		printf("ECC解密结果与标准明文不相等\n");
	}
	else
	{
		printf("ECC解密结果与标准明文相等\n");
	}

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

#if 0
int ECCTransEnvelopTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	int nKeylen=16, nKeyIndexSrc=1, nKeyIndexDest=1;
	ECCCipher pucKeySrc, pucKeyDest;
	ECCrefPublicKey pubKey;
	ECCrefPublicKey src_pubKey;
	unsigned int puiAlg[20];
	SGD_HANDLE hKeySrc, hKeyDest;
	int nSelAlg = 1;
	int nInlen = 1024, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];
	char sPrkAuthCodeSrc[128], sPrkAuthCodeDest[128];

	
	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度产生新的会话密钥，该密钥即为原始数字信封的加密密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			//密钥长度参数检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择ECC密钥对的索引，该密钥即为原始数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndexSrc = GetInputLength(1, 1, 100);

			if(nKeyIndexSrc == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexSrc == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexSrc == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexSrc < 1) || (nKeyIndexSrc > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号ECC密钥对的“私钥访问控制码”。\n", nKeyIndexSrc);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeSrc, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeSrc[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;
			
			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择另一个ECC密钥对的索引，该密钥即为转换后的数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 2);
			nKeyIndexDest = GetInputLength(2, 1, 100);

			if(nKeyIndexDest == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexDest == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexDest == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexDest < 1) || (nKeyIndexDest > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeDest, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeDest[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeDest) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}
			
			step++;
			
			break;
		case 5:
			printf("\n");	
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试，用于验证数字信封转换的正确性。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择对称密码算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			if(nSelAlg == OPT_PREVIOUS)
				step--;
			else
				step++;
			
			break;
		case 6:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("\n");
			printf("数字信封加密密钥长度：       %2d\n", nKeylen);
			printf("原始数字信封保护密钥索引：   %2d\n", nKeyIndexSrc);
			printf("转换后数字信封保护密钥索引： %2d\n", nKeyIndexDest);
			printf("验证算法标识：               0x%08x\n", puiAlg[nSelAlg]);
			printf("测试数据长度：               %d\n", nInlen);
			printf("\n");
			printf("\n");

			memset(pIv, 0, 16);

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc, sPrkAuthCodeSrc, (unsigned int)strlen(sPrkAuthCodeSrc));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexDest, sPrkAuthCodeDest, (unsigned int)strlen(sPrkAuthCodeDest));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					if(strlen(sPrkAuthCodeSrc) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
					}

					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

#if 0
			//产生受内部ECC公钥保护的会话密钥

			memset(&pucKeySrc, 0, sizeof(ECCCipher));

			rv = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, nKeyIndexSrc, nKeylen * 8, &pucKeySrc, &hKeySrc);
			if(rv == SDR_OK)
			{
				printf("产生受内部[%d]号公钥保护的会话密钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("产生受内部[%d]号公钥保护的会话密钥错误，[%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
#endif

#if 1
			//产生受外部ECC公钥保护的会话密钥

			rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, nKeyIndexSrc, &src_pubKey);
			if(rv == SDR_OK)
			{
				printf("导出[%d]号加密公钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("导出[%d]号加密公钥错误，[0x%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, nKeylen * 8, SGD_SM2_3, &src_pubKey, &pucKeySrc, &hKeySrc);
			if(rv == SDR_OK)
			{
				printf("产生受[%d]号加密公钥保护的会话密钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("产生受[%d]号加密公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
#endif

			rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, nKeyIndexDest, &pubKey);
			if(rv == SDR_OK)
			{
				printf("导出[%d]号加密公钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导出[%d]号加密公钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(&pucKeyDest, 0, sizeof(ECCCipher));

			rv = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, nKeyIndexSrc, SGD_SM2_3, &pubKey, &pucKeySrc, &pucKeyDest);
			if(rv == SDR_OK)
			{
				printf("数字信封转加密成功。\n");
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("数字信封转加密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_ImportKeyWithISK_ECC(hSessionHandle, nKeyIndexDest, &pucKeyDest, &hKeyDest);
			if(rv == SDR_OK)
			{
				printf("导入受[%d]号公钥保护的会话密钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导入受[%d]号公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//释放私有密钥访问控制码
			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					if(strlen(sPrkAuthCodeDest) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
					}

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			
			memset(pIndata, 0, sizeof(pIndata));

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				printf("产生随机加密数据成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("产生随机加密数据错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();
				
				return nMyPos;
			}

			memset(pEncdata, 0, sizeof(pEncdata));
			nEnclen = sizeof(pEncdata);

			rv = SDF_Encrypt(hSessionHandle, hKeySrc, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
			if(rv == SDR_OK)
			{
				printf("使用原始数字信封加密密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用原始数字信封加密密钥加密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pOutdata, 0, sizeof(pOutdata));
			nOutlen = sizeof(pOutdata);

			rv = SDF_Decrypt(hSessionHandle, hKeyDest, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
			if(rv == SDR_OK)
			{
				printf("使用转换后的数字信封加密密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用转换后的数字信封加密密钥解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//不管运算比对是否相等，都要销毁密钥
			SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
			SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

			if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
			{
				printf("运算结果比较正确。\n");
			}
			else
			{
				printf("解密结果错误。\n");
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

int ECCTransEnvelopTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	int nKeylen=16, nKeyIndexSrc=1, nKeyIndexDest=1;
	ECCCipher pucKeySrc, pucKeyDest;
	ECCrefPublicKey pubKey;
	ECCrefPublicKey src_pubKey;
	unsigned int puiAlg[20];
	SGD_HANDLE hKeySrc, hKeyDest;
	int nSelAlg = 1;
	int nInlen = 1024, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];
	char sPrkAuthCodeSrc[128], sPrkAuthCodeDest[128];

	
	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度产生新的会话密钥，该密钥即为原始数字信封的加密密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			//密钥长度参数检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择ECC密钥对的索引，该密钥即为原始数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndexSrc = GetInputLength(1, 1, 100);

			if(nKeyIndexSrc == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexSrc == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexSrc == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexSrc < 1) || (nKeyIndexSrc > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号ECC密钥对的“私钥访问控制码”。\n", nKeyIndexSrc);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeSrc, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeSrc[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}

			step++;
			
			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请选择另一个ECC密钥对的索引，该密钥即为转换后的数字信封的保护密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 2);
			nKeyIndexDest = GetInputLength(2, 1, 100);

			if(nKeyIndexDest == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndexDest == OPT_RETURN)
				return nMyPos;

			if(nKeyIndexDest == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndexDest < 1) || (nKeyIndexDest > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("输入[%d]号RSA密钥对的“私钥访问控制码”。\n", nKeyIndexDest);
			printf("\n");
			printf("\n");
			printf("\n输入私钥权限访问标识码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			rv = GetPasswd(sPrkAuthCodeDest, 8);

			if(rv == OPT_EXIT)
				return OPT_EXIT;

			if(rv == OPT_RETURN)
				return nMyPos;

			if(rv == OPT_PREVIOUS)
			{
				step--;

				break;
			}
			else if(rv == OPT_NEXT)
			{
				sPrkAuthCodeDest[0] = '\0';
			}
			else
			{
				if(strlen(sPrkAuthCodeDest) != 8)
				{
					printf("\n私钥权限访问标识码长度为8个字符\n");

					break;
				}
			}
			
			step++;
			
			break;
		case 5:
			printf("\n");	
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试，用于验证数字信封转换的正确性。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;

				if(stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK)
				{
					printf("  %2d | SGD_SM4_XTS\n\n", i);
					puiAlg[i++]=SGD_SM4_XTS;
				}
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择对称密码算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			if(nSelAlg == OPT_PREVIOUS)
				step--;
			else
				step++;
			
			break;
		case 6:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("ECC数字信封转换测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("\n");
			printf("数字信封加密密钥长度：       %2d\n", nKeylen);
			printf("原始数字信封保护密钥索引：   %2d\n", nKeyIndexSrc);
			printf("转换后数字信封保护密钥索引： %2d\n", nKeyIndexDest);
			printf("验证算法标识：               0x%08x\n", puiAlg[nSelAlg]);
			printf("测试数据长度：               %d\n", nInlen);
			printf("\n");
			printf("\n");

			memset(pIv, 0, 16);

			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc, sPrkAuthCodeSrc, (unsigned int)strlen(sPrkAuthCodeSrc));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndexDest, sPrkAuthCodeDest, (unsigned int)strlen(sPrkAuthCodeDest));
				if(rv == SDR_OK)
				{
					printf("获取[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					if(strlen(sPrkAuthCodeSrc) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
					}

					printf("获取[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

#if 0
			//产生受内部ECC公钥保护的会话密钥

			memset(&pucKeySrc, 0, sizeof(ECCCipher));

			rv = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, nKeyIndexSrc, nKeylen * 8, &pucKeySrc, &hKeySrc);
			if(rv == SDR_OK)
			{
				printf("产生受内部[%d]号公钥保护的会话密钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("产生受内部[%d]号公钥保护的会话密钥错误，[%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
#endif

#if 1
			//产生受外部ECC公钥保护的会话密钥

			rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, nKeyIndexSrc, &src_pubKey);
			if(rv == SDR_OK)
			{
				printf("导出[%d]号加密公钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("导出[%d]号加密公钥错误，[0x%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, nKeylen * 8, SGD_SM2_3, &src_pubKey, &pucKeySrc, &hKeySrc);
			if(rv == SDR_OK)
			{
				printf("产生受[%d]号加密公钥保护的会话密钥成功。\n", nKeyIndexSrc);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				printf("产生受[%d]号加密公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexSrc, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
#endif

			rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, nKeyIndexDest, &pubKey);
			if(rv == SDR_OK)
			{
				printf("导出[%d]号加密公钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导出[%d]号加密公钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(&pucKeyDest, 0, sizeof(ECCCipher));

			rv = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, nKeyIndexSrc, SGD_SM2_3, &pubKey, &pucKeySrc, &pucKeyDest);
			if(rv == SDR_OK)
			{
				printf("数字信封转加密成功。\n");
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("数字信封转加密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			rv = SDF_ImportKeyWithISK_ECC(hSessionHandle, nKeyIndexDest, &pucKeyDest, &hKeyDest);
			if(rv == SDR_OK)
			{
				printf("导入受[%d]号公钥保护的会话密钥成功。\n", nKeyIndexDest);
			}
			else
			{
				if(strlen(sPrkAuthCodeSrc) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				}

				if(strlen(sPrkAuthCodeDest) != 0)
				{
					SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				}

				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥

				printf("导入受[%d]号公钥保护的会话密钥错误，[0x%08x]\n", nKeyIndexDest, rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//释放私有密钥访问控制码
			if(strlen(sPrkAuthCodeSrc) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexSrc);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexSrc);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					if(strlen(sPrkAuthCodeDest) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
					}

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexSrc, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}

			if(strlen(sPrkAuthCodeDest) != 0)
			{
				rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndexDest);
				if(rv == SDR_OK)
				{
					printf("释放[%d]号私钥访问权限成功。\n", nKeyIndexDest);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
					SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

					printf("释放[%d]号私钥访问权限错误，[0x%08x]\n", nKeyIndexDest, rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			
			memset(pIndata, 0, sizeof(pIndata));

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				printf("产生随机加密数据成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("产生随机加密数据错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();
				
				return nMyPos;
			}

			memset(pEncdata, 0, sizeof(pEncdata));
			nEnclen = sizeof(pEncdata);

			if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
			{
				rv = SDF_Encrypt(hSessionHandle, hKeySrc, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
			}
			else
			{
				rv = SDF_Encrypt_Ex(hSessionHandle, hKeySrc, hKeySrc, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen, nInlen);
			}

			if(rv == SDR_OK)
			{
				printf("使用原始数字信封加密密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用原始数字信封加密密钥加密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pOutdata, 0, sizeof(pOutdata));
			nOutlen = sizeof(pOutdata);

			if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
			{
				rv = SDF_Decrypt(hSessionHandle, hKeyDest, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
			}
			else
			{
				rv = SDF_Decrypt_Ex(hSessionHandle, hKeyDest, hKeyDest, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen, nEnclen);
			}

			if(rv == SDR_OK)
			{
				printf("使用转换后的数字信封加密密钥加密成功\n");
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
				SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

				printf("使用转换后的数字信封加密密钥解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
			
			//不管运算比对是否相等，都要销毁密钥
			SDF_DestroyKey(hSessionHandle, hKeySrc);	//销毁原密钥
			SDF_DestroyKey(hSessionHandle, hKeyDest);	//销毁新密钥

			if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
			{
				printf("运算结果比较正确。\n");
			}
			else
			{
				printf("解密结果错误。\n");
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETANYKEY();

			return nMyPos;
		}
	}

	return nMyPos;
}


int SymmFuncTest(int nMyPos, int nDefaultSelect)
{
	int rv, nSel;
	SGD_HANDLE hSessionHandle;
	SGD_HANDLE hKey = NULL;

	if((nDefaultSelect < 1) || (nDefaultSelect > 7)) 
		nSel = 1;
	else
		nSel = nDefaultSelect;

	//创建会话句柄
	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(rv != SDR_OK)
	{
		printf("打开会话句柄错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("对称密码算法测试:\n");
		printf("-----------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|产生会话密钥测试\n");
	else
		printf("   1|产生会话密钥测试\n");
		printf("    |    产生受保护的会话密钥，并保存到文件中。\n");
		printf("\n");
	if(nSel == 2)
		printf(" ->2|导入会话密钥测试\n");
	else
		printf("   2|导入会话密钥测试\n");
		printf("    |    导入明文会话密钥或受公钥保护的会话密钥。\n");
		printf("\n");
	if(nSel == 3)
		printf(" ->3|销毁会话密钥测试\n");
	else
		printf("   3|销毁会话密钥测试\n");
		printf("    |    销毁会话密钥句柄。\n");
		printf("\n");
	if(nSel == 4)
		printf(" ->4|对称运算加解密测试\n");
	else
		printf("   4|对称运算加解密测试\n");
		printf("    |    使用会话密钥对输入数据进行加解密运算。\n");
		printf("\n");
	if(nSel == 5)
		printf(" ->5|算法正确性测试\n");
	else
		printf("   5|算法正确性测试\n");
		printf("    |    使用标准数据验证对称算法的正确性。\n");
		printf("\n");
	if(nSel == 6)
		printf(" ->6|MAC算法正确性测试\n");
	else
		printf("   6|MAC算法正确性测试\n");
		printf("    |    使用标准数据验证MAC算法的正确性。\n");
		printf("\n");
	if (nSel == 7)
		printf(" ->7|内部对称密钥加解密运算测试\n");
	else
		printf("   7|内部对称密钥加解密运算测试\n");
		printf("    |    使用内部对称密钥对输入数据进行加解密运算，并比较结果。\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("选择测试项目 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetSelect(nSel, 7);

		switch(nSel)
		{
		case 1:
			nSel = GenKeyTest(1, hSessionHandle, &hKey);
			break;
		case 2:
			nSel = ImportKeyTest(2, hSessionHandle, &hKey);
			break;
		case 3:
			nSel = DestroyKeyTest(3, hSessionHandle, &hKey);
			break;
		case 4:
			nSel = SymmEncDecTest(4, hSessionHandle, &hKey);
			break;
		case 5:
			nSel = SymmCorrectnessTest(5, hSessionHandle);
			break;
		case 6:
			nSel = SymmCalculateMACTest(6, hSessionHandle);
			break;
		case 7:
			nSel = InSymmEncDecTest(7, hSessionHandle);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
		{
			if(hKey != NULL)
			{
				printf("\n请确认密钥已销毁，然后退出...\n");
				printf("按任意键继续...");
				GETCH();

				continue;
			}

			SDF_CloseSession(hSessionHandle);

			return OPT_EXIT;
		}

		if(nSel == OPT_RETURN)
		{
			if(hKey != NULL)
			{
				printf("\n请确认密钥已销毁，然后返回...\n");
				printf("按任意键继续...");
				GETCH();

				continue;
			}

			SDF_CloseSession(hSessionHandle);

			return nMyPos;
		}
	}

	return nMyPos;
}

#if 0
int GenKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	int nSel, nKeylen = 16, nKeyIndex = 1, i;
	unsigned char pucKey[512];
	ECCCipher ECC_pucKey;
	char filename[128];
	unsigned int puiAlg[10];
	unsigned int outKeylen;
	int nSelAlg = 1;
	DEVICEINFO stDeviceInfo;
	RSArefPublicKey pubKey;
	ECCrefPublicKey ECC_pubKey;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("产生会话密钥测试:\n");
	printf("-----------------\n");
	printf("\n");
	printf("\n");

	if(*phKeyHandle != NULL)
	{
		printf("\n会话密钥已存在，请将已存在的会话密钥先销毁...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("选择产生会话密钥的方式。\n");
			printf("\n");
			printf("   1 | 产生会话密钥并以密钥加密密钥(KEK)加密后导出。\n");
			printf("   2 | 产生会话密钥并以内部RSA公钥加密后导出。\n");
			printf("   3 | 产生会话密钥并以外部RSA公钥加密后导出。\n");
			printf("   4 | 产生会话密钥并以内部ECC公钥加密后导出。\n");
			printf("   5 | 产生会话密钥并以外部ECC公钥加密后导出。\n");
			printf("\n");
			printf("\n");
			printf("\n输入产生方式(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			nSel = GetSelect(1, 5);

			if(nSel == OPT_EXIT)
				return OPT_EXIT;

			if(nSel == OPT_RETURN)
				return nMyPos;
			
			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度产生新的会话密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			if(nKeylen == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥长度参数检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				printf("请选择密钥加密密钥(KEK)的索引，对产生的会话密钥进行加密。\n");
			}
			if(nSel == 2)
			{
				printf("请选择RSA密钥对的索引，对产生的会话密钥进行加密。\n");
			}
			if(nSel == 3)
			{
				printf("为方便测试，将导出RSA加密公钥后再调用外部加密接口进行测试。\n");
				printf("请选择RSA密钥对的索引。\n");
			}
			if(nSel == 4)
			{
				printf("请选择ECC密钥对的索引，对产生的会话密钥进行加密。\n");
			}
			if(nSel == 5)
			{
				printf("为方便测试，将导出ECC加密公钥后再调用外部加密接口进行测试。\n");
				printf("请选择ECC密钥对的索引。\n");
			}

			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndex = GetInputLength(1, 1, 100);

			if(nKeyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndex == OPT_RETURN)
				return nMyPos;

			if(nKeyIndex == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndex < 1) || (nKeyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

				rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
				if(rv != SDR_OK)
				{
					printf("获取设备信息错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}

				i=1;

				if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_SM1_ECB\n\n", i);
					puiAlg[i++]=SGD_SM1_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_SSF33_ECB\n\n", i);
					puiAlg[i++]=SGD_SSF33_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_AES_ECB\n\n", i);
					puiAlg[i++]=SGD_AES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_DES_ECB\n\n", i);
					puiAlg[i++]=SGD_DES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_3DES_ECB\n\n", i);
					puiAlg[i++]=SGD_3DES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_SM4_ECB\n\n", i);
					puiAlg[i++]=SGD_SM4_ECB;
				}

				printf("请选择密钥加密密钥(KEK)的加密算法。\n");
				printf("选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
				nSelAlg = GetInputLength(1, 1, i-1);

				if(nSelAlg == OPT_EXIT)
					return OPT_EXIT;

				if(nSelAlg == OPT_RETURN)
					return nMyPos;

				if(nSelAlg == OPT_PREVIOUS)
					step--;
				else
					step++;
			}

			if(nSel == 2)
			{
				rv = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, nKeyIndex, nKeylen * 8, pucKey, &outKeylen, phKeyHandle);
				if(rv != SDR_OK)
				{
					printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("生成会话密钥成功。\n");
					printf("可以使用该密钥进行对称加解密运算测试。\n");

					sprintf(filename, "data/keybyisk.%d", nKeyIndex);
					FileWrite(filename, "wb+", pucKey, outKeylen);

					printf("会话密钥密文已经写入文件：%s。\n",filename);
					PrintData(filename, pucKey, outKeylen, 16);
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 3)
			{
				rv = SDF_ExportEncPublicKey_RSA(hSessionHandle, nKeyIndex, &pubKey);
				if(rv != SDR_OK)
				{
					printf("导出RSA加密公钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					rv = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, nKeylen * 8, &pubKey, pucKey, &outKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("生成会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						sprintf(filename, "data/keybyisk.%d", nKeyIndex);
						FileWrite(filename, "wb+", pucKey, outKeylen);

						printf("会话密钥密文已经写入文件：%s。\n",filename);
						PrintData(filename, pucKey, outKeylen, 16);
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 4)
			{
				memset(&ECC_pucKey, 0, sizeof(ECCCipher));

				rv = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, nKeyIndex, nKeylen * 8, &ECC_pucKey, phKeyHandle);
				if(rv != SDR_OK)
				{
					printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("生成会话密钥成功。\n");
					printf("可以使用该密钥进行对称加解密运算测试。\n");

					sprintf(filename, "data/keybyisk_ecc.%d", nKeyIndex);
					FileWrite(filename, "wb+", (unsigned char *)&ECC_pucKey, sizeof(ECCCipher));

					printf("会话密钥密文已经写入文件：%s。\n",filename);
					PrintData(filename, (unsigned char *)&ECC_pucKey, sizeof(ECCCipher), 16);
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 5)
			{
				rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, nKeyIndex, &ECC_pubKey);
				if(rv != SDR_OK)
				{
					printf("导出ECC加密公钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					memset(&ECC_pucKey, 0, sizeof(ECCCipher));

					rv = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, nKeylen * 8, SGD_SM2_3, &ECC_pubKey, &ECC_pucKey, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("生成会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						sprintf(filename, "data/keybyisk_ecc.%d", nKeyIndex);
						FileWrite(filename, "wb+", (unsigned char *)&ECC_pucKey, sizeof(ECCCipher));

						printf("会话密钥密文已经写入文件：%s。\n", filename);
						PrintData(filename, (unsigned char *)&ECC_pucKey, sizeof(ECCCipher), 16);
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				memset(pucKey, 0, sizeof(pucKey));
				outKeylen = sizeof(pucKey);

				rv = SDF_GenerateKeyWithKEK(hSessionHandle, nKeylen * 8, puiAlg[nSelAlg], nKeyIndex, pucKey, &outKeylen, phKeyHandle);
				if(rv != SDR_OK)
				{
					//更新phKeyHandle指向的指针值
					if(*phKeyHandle != NULL)
					{
						*phKeyHandle = NULL;
					}

					printf("生成受密钥加密密钥保护的对称密钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("\n");
					printf("生成受密钥加密密钥保护的对称密钥成功。\n");
					printf("可以使用该密钥进行对称加解密运算测试。\n");

					sprintf(filename, "data/keybykek.%d", nKeyIndex);
					FileWrite(filename, "wb+", pucKey, outKeylen);

					printf("\n会话密钥密文已经写入文件：%s。\n",filename);
					PrintData("cipher", pucKey, outKeylen, 16);
				}
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		} //end switch
	}//end while

	return nMyPos;
}
#endif

int GenKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	int nSel, nKeylen = 16, nKeyIndex = 1, i;
	unsigned char pucKey[512];
	ECCCipher ECC_pucKey;
	char filename[128];
	unsigned int puiAlg[10];
	unsigned int outKeylen;
	int nSelAlg = 1;
	DEVICEINFO stDeviceInfo;
	RSArefPublicKey pubKey;
	ECCrefPublicKey ECC_pubKey;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("产生会话密钥测试:\n");
	printf("-----------------\n");
	printf("\n");
	printf("\n");

	if(*phKeyHandle != NULL)
	{
		printf("\n会话密钥已存在，请将已存在的会话密钥先销毁...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("选择产生会话密钥的方式。\n");
			printf("\n");
			printf("   1 | 产生会话密钥并以密钥加密密钥(KEK)加密后导出。\n");
			printf("   2 | 产生会话密钥并以内部RSA公钥加密后导出。\n");
			printf("   3 | 产生会话密钥并以外部RSA公钥加密后导出。\n");
			printf("   4 | 产生会话密钥并以内部ECC公钥加密后导出。\n");
			printf("   5 | 产生会话密钥并以外部ECC公钥加密后导出。\n");
			printf("\n");
			printf("\n");
			printf("\n输入产生方式(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			nSel = GetSelect(1, 5);

			if(nSel == OPT_EXIT)
				return OPT_EXIT;

			if(nSel == OPT_RETURN)
				return nMyPos;
			
			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("将根据输入的密钥长度产生新的会话密钥。\n");
			printf("\n");
			printf("\n");
			printf("\n输入密钥字节长度(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 16);
			nKeylen = GetInputLength(16, 8, 32);

			if(nKeylen == OPT_EXIT)
				return OPT_EXIT;

			if(nKeylen == OPT_RETURN)
				return nMyPos;

			if(nKeylen == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥长度参数检查
			if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
			{
				printf("\n密钥长度输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				printf("请选择密钥加密密钥(KEK)的索引，对产生的会话密钥进行加密。\n");
			}
			if(nSel == 2)
			{
				printf("请选择RSA密钥对的索引，对产生的会话密钥进行加密。\n");
			}
			if(nSel == 3)
			{
				printf("为方便测试，将导出RSA加密公钥后再调用外部加密接口进行测试。\n");
				printf("请选择RSA密钥对的索引。\n");
			}
			if(nSel == 4)
			{
				printf("请选择ECC密钥对的索引，对产生的会话密钥进行加密。\n");
			}
			if(nSel == 5)
			{
				printf("为方便测试，将导出ECC加密公钥后再调用外部加密接口进行测试。\n");
				printf("请选择ECC密钥对的索引。\n");
			}

			printf("\n");
			printf("\n");
			printf("\n输入密钥索引(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
			nKeyIndex = GetInputLength(1, 1, 100);

			if(nKeyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndex == OPT_RETURN)
				return nMyPos;

			if(nKeyIndex == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndex < 1) || (nKeyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

				rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
				if(rv != SDR_OK)
				{
					printf("获取设备信息错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}

				i=1;

				if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SM1_ECB\n\n", i);
					puiAlg[i++]=SGD_SM1_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SSF33_ECB\n\n", i);
					puiAlg[i++]=SGD_SSF33_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_AES_ECB\n\n", i);
					puiAlg[i++]=SGD_AES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_DES_ECB\n\n", i);
					puiAlg[i++]=SGD_DES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_3DES_ECB\n\n", i);
					puiAlg[i++]=SGD_3DES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SM4_ECB\n\n", i);
					puiAlg[i++]=SGD_SM4_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SM7_ECB\n\n", i);
					puiAlg[i++]=SGD_SM7_ECB;
				}

				printf("请选择密钥加密密钥(KEK)的加密算法。\n");
				printf("选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
				nSelAlg = GetInputLength(1, 1, i-1);

				if(nSelAlg == OPT_EXIT)
					return OPT_EXIT;

				if(nSelAlg == OPT_RETURN)
					return nMyPos;

				if(nSelAlg == OPT_PREVIOUS)
					step--;
				else
					step++;
			}

			if(nSel == 2)
			{
				rv = SDF_GenerateKeyWithIPK_RSA(hSessionHandle, nKeyIndex, nKeylen * 8, pucKey, &outKeylen, phKeyHandle);
				if(rv != SDR_OK)
				{
					printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("生成会话密钥成功。\n");
					printf("可以使用该密钥进行对称加解密运算测试。\n");

					sprintf(filename, "data/keybyisk.%d", nKeyIndex);
					FileWrite(filename, "wb+", pucKey, outKeylen);

					printf("会话密钥密文已经写入文件：%s。\n",filename);
					PrintData(filename, pucKey, outKeylen, 16);
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 3)
			{
				rv = SDF_ExportEncPublicKey_RSA(hSessionHandle, nKeyIndex, &pubKey);
				if(rv != SDR_OK)
				{
					printf("导出RSA加密公钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					rv = SDF_GenerateKeyWithEPK_RSA(hSessionHandle, nKeylen * 8, &pubKey, pucKey, &outKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("生成会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						sprintf(filename, "data/keybyisk.%d", nKeyIndex);
						FileWrite(filename, "wb+", pucKey, outKeylen);

						printf("会话密钥密文已经写入文件：%s。\n",filename);
						PrintData(filename, pucKey, outKeylen, 16);
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 4)
			{
				memset(&ECC_pucKey, 0, sizeof(ECCCipher));

				rv = SDF_GenerateKeyWithIPK_ECC(hSessionHandle, nKeyIndex, nKeylen * 8, &ECC_pucKey, phKeyHandle);
				if(rv != SDR_OK)
				{
					printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("生成会话密钥成功。\n");
					printf("可以使用该密钥进行对称加解密运算测试。\n");

					sprintf(filename, "data/keybyisk_ecc.%d", nKeyIndex);
					FileWrite(filename, "wb+", (unsigned char *)&ECC_pucKey, sizeof(ECCCipher));

					printf("会话密钥密文已经写入文件：%s。\n",filename);
					PrintData(filename, (unsigned char *)&ECC_pucKey, sizeof(ECCCipher), 16);
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 5)
			{
				rv = SDF_ExportEncPublicKey_ECC(hSessionHandle, nKeyIndex, &ECC_pubKey);
				if(rv != SDR_OK)
				{
					printf("导出ECC加密公钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					memset(&ECC_pucKey, 0, sizeof(ECCCipher));

					rv = SDF_GenerateKeyWithEPK_ECC(hSessionHandle, nKeylen * 8, SGD_SM2_3, &ECC_pubKey, &ECC_pucKey, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("生成会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("生成会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						sprintf(filename, "data/keybyisk_ecc.%d", nKeyIndex);
						FileWrite(filename, "wb+", (unsigned char *)&ECC_pucKey, sizeof(ECCCipher));

						printf("会话密钥密文已经写入文件：%s。\n", filename);
						PrintData(filename, (unsigned char *)&ECC_pucKey, sizeof(ECCCipher), 16);
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			break;
		case 4:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("产生会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				memset(pucKey, 0, sizeof(pucKey));
				outKeylen = sizeof(pucKey);

				rv = SDF_GenerateKeyWithKEK(hSessionHandle, nKeylen * 8, puiAlg[nSelAlg], nKeyIndex, pucKey, &outKeylen, phKeyHandle);
				if(rv != SDR_OK)
				{
					//更新phKeyHandle指向的指针值
					if(*phKeyHandle != NULL)
					{
						*phKeyHandle = NULL;
					}

					printf("生成受密钥加密密钥保护的对称密钥错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("\n");
					printf("生成受密钥加密密钥保护的对称密钥成功。\n");
					printf("可以使用该密钥进行对称加解密运算测试。\n");

					sprintf(filename, "data/keybykek.%d", nKeyIndex);
					FileWrite(filename, "wb+", pucKey, outKeylen);

					printf("\n会话密钥密文已经写入文件：%s。\n",filename);
					PrintData("cipher", pucKey, outKeylen, 16);
				}
			}

			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		} //end switch
	}//end while

	return nMyPos;
}

#if 0
int ImportKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	char passwd[128] = {0};
	int nSel, nKeylen, nKeyIndex, i;
	unsigned char pucKey[512];
	ECCCipher ECC_pucKey;
	char filename[128];
	unsigned int puiAlg[10];
	int nSelAlg = 1;
	DEVICEINFO stDeviceInfo;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("导入会话密钥测试:\n");
	printf("-----------------\n");
	printf("\n");
	printf("\n");

	if(*phKeyHandle != NULL)
	{
		printf("\n会话密钥已存在，请将已存在的会话密钥先销毁...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("选择导入会话密钥的来源。\n");
			printf("\n");
			printf("   1 | 导入明文会话密钥\n");
			printf("   2 | 导入受密钥加密密钥(KEK)保护的会话密钥\n");
			printf("   3 | 导入受RSA公钥保护的会话密钥\n");
			printf("   4 | 导入受ECC公钥保护的会话密钥\n");
			printf("\n");
			printf("\n");
			printf("\n输入导入方式(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			nSel = GetSelect(1, 4);

			if(nSel == OPT_EXIT)
				return OPT_EXIT;

			if(nSel == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				printf("将根据输入的密钥长度产生新的会话密钥。\n");
				printf("\n");
				printf("\n");
				printf("\n输入密钥长度(默认[16])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeylen = GetInputLength(16, 8, 32);

				if(nKeylen == OPT_EXIT)
					return OPT_EXIT;

				if(nKeylen == OPT_RETURN)
					return nMyPos;

				if(nKeylen == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥长度参数检查
				if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
				{
					printf("\n密钥长度输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			if(nSel == 2)
			{
				memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

				rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
				if(rv != SDR_OK)
				{
					printf("获取设备信息错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}

				i=1;

				if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_SM1_ECB\n\n", i);
					puiAlg[i++]=SGD_SM1_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_SSF33_ECB\n\n", i);
					puiAlg[i++]=SGD_SSF33_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_AES_ECB\n\n", i);
					puiAlg[i++]=SGD_AES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_DES_ECB\n\n", i);
					puiAlg[i++]=SGD_DES_ECB;
				}	
				if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_3DES_ECB\n\n", i);
					puiAlg[i++]=SGD_3DES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
				{
					printf("  %d | SGD_SM4_ECB\n\n", i);
					puiAlg[i++]=SGD_SM4_ECB;
				}

				printf("选择“1 产生会话密钥测试”中指定的KEK加密算法。\n");
				printf("\n从以下支持的算法中选择一项进行测试。\n");
				printf("选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
				nSelAlg = GetInputLength(1, 1, i-1);

				if(nSelAlg == OPT_EXIT)
					return OPT_EXIT;

				if(nSelAlg == OPT_RETURN)
					return nMyPos;

				if(nSelAlg == OPT_PREVIOUS)
					step--;
				else
					step++;
			}

			if(nSel == 3)
			{
				printf("从文件中读取“1 产生会话密钥测试”中产生的会话密钥密文，并导入。\n");
				printf("\n");
				printf("\n");
				printf("\n输入内部RSA密钥号(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeyIndex = GetInputLength(1, 1, 100);

				if(nKeyIndex == OPT_EXIT)
					return OPT_EXIT;

				if(nKeyIndex == OPT_RETURN)
					return nMyPos;

				if(nKeyIndex == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥索引参数检查
				if((nKeyIndex < 1) || (nKeyIndex > 100))
				{
					printf("\n密钥号输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			if(nSel == 4)
			{
				printf("从文件中读取“1 产生会话密钥测试”中产生的会话密钥密文，并导入。\n");
				printf("\n");
				printf("\n");
				printf("\n输入内部ECC密钥号(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeyIndex = GetInputLength(1, 1, 100);

				if(nKeyIndex == OPT_EXIT)
					return OPT_EXIT;

				if(nKeyIndex == OPT_RETURN)
					return nMyPos;

				if(nKeyIndex == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥索引参数检查
				if((nKeyIndex < 1) || (nKeyIndex > 100))
				{
					printf("\n密钥号输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				rv = SDF_GenerateRandom(hSessionHandle, nKeylen, pucKey);
				if(rv != SDR_OK)
				{
					printf("产生随机密钥数据错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("从产生随机密钥数据成功。\n");
					PrintData("随机密钥数据", pucKey, nKeylen, 16);

					rv = SDF_ImportKey(hSessionHandle, pucKey, nKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入明文会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 2)
			{
				printf("\n");
				printf("\n");
				printf("\n输入KEK密钥号(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeyIndex = GetInputLength(1, 1, 100);

				if(nKeyIndex == OPT_EXIT)
					return OPT_EXIT;

				if(nKeyIndex == OPT_RETURN)
					return nMyPos;

				if(nKeyIndex == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥索引参数检查
				if((nKeyIndex < 1) || (nKeyIndex > 100))
				{
					printf("\n密钥号输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			if(nSel == 3)
			{
				
				printf("\n输入内部RSA密钥号为[%d]的私钥访问控制码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", nKeyIndex);
				rv = GetPasswd(passwd, 8);

				if(rv == OPT_EXIT)
					return OPT_EXIT;

				if(rv == OPT_RETURN)
					return nMyPos;

				if(rv == OPT_PREVIOUS)
				{
					step--;

					break;
				}
				else if(rv == OPT_NEXT)
				{
					passwd[0]= '\0';
				}
				else
				{
					if(strlen(passwd) != 8)
					{
						printf("\n私钥访问控制码长度为8个字符\n");

						break;
					}
				}


				step++;
			}

			if(nSel == 4)
			{
				
				printf("\n输入内部ECC密钥号为[%d]的私钥访问控制码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", nKeyIndex);
				rv = GetPasswd(passwd, 8);

				if(rv == OPT_EXIT)
					return OPT_EXIT;

				if(rv == OPT_RETURN)
					return nMyPos;

				if(rv == OPT_PREVIOUS)
				{
					step--;

					break;
				}
				else if(rv == OPT_NEXT)
				{
					passwd[0]= '\0';
				}
				else
				{
					if(strlen(passwd) != 8)
					{
						printf("\n私钥访问控制码长度为8个字符");

						break;
					}
				}

				step++;			
			}

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 2)
			{
				printf("\n");
				printf("读取“1 产生会话密钥测试”中产生的受密钥加密密钥保护的对称密钥密文。\n");

				sprintf(filename, "data/keybykek.%d", nKeyIndex);
				nKeylen = FileRead(filename, "rb", pucKey, sizeof(pucKey));

				if(nKeylen < 8)
				{
					printf("读取受密钥加密密钥保护的对称密钥密文文件错误。\n");
				}
				else
				{
					printf("\n");
					printf("从文件中读取受密钥加密密钥保护的对称密钥密文成功。\n");

					rv = SDF_ImportKeyWithKEK(hSessionHandle, puiAlg[nSelAlg], nKeyIndex, pucKey, nKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("导入受密钥加密密钥保护的对称密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入受密钥加密密钥保护的对称密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");
					}

				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 3)
			{
				if(strlen(passwd) != 0)
				{
					rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndex, passwd, (unsigned int)strlen(passwd));
					if(rv != SDR_OK)
					{
						printf("获取私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
						printf("\n按任意键继续...");
						GETCH();

						return nMyPos;
					}

					printf("获取私有密钥访问控制码成功\n");
				}

				sprintf(filename, "data/keybyisk.%d", nKeyIndex);
				nKeylen = FileRead(filename, "rb", pucKey, sizeof(pucKey));

				if(nKeylen < 128)
				{
					if(strlen(passwd) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
					}
					
					printf("读会话密钥文件错误。\n");
				}
				else
				{
					printf("从文件中读取会话密钥成功。\n");

					rv = SDF_ImportKeyWithISK_RSA(hSessionHandle, nKeyIndex, pucKey, nKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						if(strlen(passwd) != 0)
						{
							SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
						}

						printf("导入会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						if(strlen(passwd) != 0)
						{
							rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
							if(rv != SDR_OK)
							{
								printf("释放私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
							}

							printf("释放私有密钥访问控制码成功\n");
						}
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 4)
			{
				if(strlen(passwd) != 0)
				{
					rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndex, passwd, (unsigned int)strlen(passwd));
					if(rv != SDR_OK)
					{
						printf("获取私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
						printf("\n按任意键继续...");
						GETCH();

						return nMyPos;
					}

					printf("获取私有密钥访问控制码成功\n");
				}

				sprintf(filename, "data/keybyisk_ecc.%d", nKeyIndex);
				nKeylen = FileRead(filename, "rb", (unsigned char *)&ECC_pucKey, sizeof(ECCCipher));

				if(nKeylen < sizeof(ECCCipher))
				{
					if(strlen(passwd) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
					}

					printf("读会话密钥文件错误。\n");
				}
				else
				{
					printf("从文件中读取会话密钥成功。\n");

					rv = SDF_ImportKeyWithISK_ECC(hSessionHandle, nKeyIndex, &ECC_pucKey, phKeyHandle);
					if(rv != SDR_OK)
					{
						if(strlen(passwd) != 0)
						{
							SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
						}

						printf("导入会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						if(strlen(passwd) != 0)
						{
							rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
							if(rv != SDR_OK)
							{
								printf("释放私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
							}

							printf("释放私有密钥访问控制码成功\n");
						}
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		default:
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		} //end switch
	}//end while

	return nMyPos;
}
#endif

int ImportKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	char passwd[128] = {0};
	int nSel, nKeylen, nKeyIndex, i;
	unsigned char pucKey[512];
	ECCCipher ECC_pucKey;
	char filename[128];
	unsigned int puiAlg[10];
	int nSelAlg = 1;
	DEVICEINFO stDeviceInfo;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("导入会话密钥测试:\n");
	printf("-----------------\n");
	printf("\n");
	printf("\n");

	if(*phKeyHandle != NULL)
	{
		printf("\n会话密钥已存在，请将已存在的会话密钥先销毁...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("选择导入会话密钥的来源。\n");
			printf("\n");
			printf("   1 | 导入明文会话密钥\n");
			printf("   2 | 导入受密钥加密密钥(KEK)保护的会话密钥\n");
			printf("   3 | 导入受RSA公钥保护的会话密钥\n");
			printf("   4 | 导入受ECC公钥保护的会话密钥\n");
			printf("\n");
			printf("\n");
			printf("\n输入导入方式(默认[1])，或 [退出(Q)] [返回(R)] [下一步(N)]>");
			nSel = GetSelect(1, 4);

			if(nSel == OPT_EXIT)
				return OPT_EXIT;

			if(nSel == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				printf("将根据输入的密钥长度产生新的会话密钥。\n");
				printf("\n");
				printf("\n");
				printf("\n输入密钥长度(默认[16])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeylen = GetInputLength(16, 8, 32);

				if(nKeylen == OPT_EXIT)
					return OPT_EXIT;

				if(nKeylen == OPT_RETURN)
					return nMyPos;

				if(nKeylen == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥长度参数检查
				if((nKeylen < 8) || (nKeylen > 32) || (nKeylen%8 != 0))
				{
					printf("\n密钥长度输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			if(nSel == 2)
			{
				memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

				rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
				if(rv != SDR_OK)
				{
					printf("获取设备信息错误，错误码[0x%08x]\n", rv);
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}

				i=1;

				if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SM1_ECB\n\n", i);
					puiAlg[i++]=SGD_SM1_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SSF33_ECB\n\n", i);
					puiAlg[i++]=SGD_SSF33_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_AES_ECB\n\n", i);
					puiAlg[i++]=SGD_AES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_DES_ECB\n\n", i);
					puiAlg[i++]=SGD_DES_ECB;
				}	
				if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_3DES_ECB\n\n", i);
					puiAlg[i++]=SGD_3DES_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SM4_ECB\n\n", i);
					puiAlg[i++]=SGD_SM4_ECB;
				}
				if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
				{
					printf("  %d | SGD_SM7_ECB\n\n", i);
					puiAlg[i++]=SGD_SM7_ECB;
				}

				printf("选择“1 产生会话密钥测试”中指定的KEK加密算法。\n");
				printf("\n从以下支持的算法中选择一项进行测试。\n");
				printf("选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", 1);
				nSelAlg = GetInputLength(1, 1, i-1);

				if(nSelAlg == OPT_EXIT)
					return OPT_EXIT;

				if(nSelAlg == OPT_RETURN)
					return nMyPos;

				if(nSelAlg == OPT_PREVIOUS)
					step--;
				else
					step++;
			}

			if(nSel == 3)
			{
				printf("从文件中读取“1 产生会话密钥测试”中产生的会话密钥密文，并导入。\n");
				printf("\n");
				printf("\n");
				printf("\n输入内部RSA密钥号(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeyIndex = GetInputLength(1, 1, 100);

				if(nKeyIndex == OPT_EXIT)
					return OPT_EXIT;

				if(nKeyIndex == OPT_RETURN)
					return nMyPos;

				if(nKeyIndex == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥索引参数检查
				if((nKeyIndex < 1) || (nKeyIndex > 100))
				{
					printf("\n密钥号输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			if(nSel == 4)
			{
				printf("从文件中读取“1 产生会话密钥测试”中产生的会话密钥密文，并导入。\n");
				printf("\n");
				printf("\n");
				printf("\n输入内部ECC密钥号(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeyIndex = GetInputLength(1, 1, 100);

				if(nKeyIndex == OPT_EXIT)
					return OPT_EXIT;

				if(nKeyIndex == OPT_RETURN)
					return nMyPos;

				if(nKeyIndex == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥索引参数检查
				if((nKeyIndex < 1) || (nKeyIndex > 100))
				{
					printf("\n密钥号输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 1)
			{
				rv = SDF_GenerateRandom(hSessionHandle, nKeylen, pucKey);
				if(rv != SDR_OK)
				{
					printf("产生随机密钥数据错误，错误码[0x%08x]\n", rv);
				}
				else
				{
					printf("从产生随机密钥数据成功。\n");
					PrintData("随机密钥数据", pucKey, nKeylen, 16);

					rv = SDF_ImportKey(hSessionHandle, pucKey, nKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入明文会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 2)
			{
				printf("\n");
				printf("\n");
				printf("\n输入KEK密钥号(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
				nKeyIndex = GetInputLength(1, 1, 100);

				if(nKeyIndex == OPT_EXIT)
					return OPT_EXIT;

				if(nKeyIndex == OPT_RETURN)
					return nMyPos;

				if(nKeyIndex == OPT_PREVIOUS)
				{
					step--;

					break;
				}

				//密钥索引参数检查
				if((nKeyIndex < 1) || (nKeyIndex > 100))
				{
					printf("\n密钥号输入参数无效，请重新输入");

					break;
				}
				
				step++;
			}

			if(nSel == 3)
			{
				
				printf("\n输入内部RSA密钥号为[%d]的私钥访问控制码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", nKeyIndex);
				rv = GetPasswd(passwd, 8);

				if(rv == OPT_EXIT)
					return OPT_EXIT;

				if(rv == OPT_RETURN)
					return nMyPos;

				if(rv == OPT_PREVIOUS)
				{
					step--;

					break;
				}
				else if(rv == OPT_NEXT)
				{
					passwd[0]= '\0';
				}
				else
				{
					if(strlen(passwd) != 8)
					{
						printf("\n私钥访问控制码长度为8个字符\n");

						break;
					}
				}


				step++;
			}

			if(nSel == 4)
			{
				
				printf("\n输入内部ECC密钥号为[%d]的私钥访问控制码(8个字符)，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>", nKeyIndex);
				rv = GetPasswd(passwd, 8);

				if(rv == OPT_EXIT)
					return OPT_EXIT;

				if(rv == OPT_RETURN)
					return nMyPos;

				if(rv == OPT_PREVIOUS)
				{
					step--;

					break;
				}
				else if(rv == OPT_NEXT)
				{
					passwd[0]= '\0';
				}
				else
				{
					if(strlen(passwd) != 8)
					{
						printf("\n私钥访问控制码长度为8个字符");

						break;
					}
				}

				step++;			
			}

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("导入会话密钥测试:\n");
			printf("-----------------\n");
			printf("\n");

			if(nSel == 2)
			{
				printf("\n");
				printf("读取“1 产生会话密钥测试”中产生的受密钥加密密钥保护的对称密钥密文。\n");

				sprintf(filename, "data/keybykek.%d", nKeyIndex);
				nKeylen = FileRead(filename, "rb", pucKey, sizeof(pucKey));

				if(nKeylen < 8)
				{
					printf("读取受密钥加密密钥保护的对称密钥密文文件错误。\n");
				}
				else
				{
					printf("\n");
					printf("从文件中读取受密钥加密密钥保护的对称密钥密文成功。\n");

					rv = SDF_ImportKeyWithKEK(hSessionHandle, puiAlg[nSelAlg], nKeyIndex, pucKey, nKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						printf("导入受密钥加密密钥保护的对称密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入受密钥加密密钥保护的对称密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");
					}

				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 3)
			{
				if(strlen(passwd) != 0)
				{
					rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndex, passwd, (unsigned int)strlen(passwd));
					if(rv != SDR_OK)
					{
						printf("获取私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
						printf("\n按任意键继续...");
						GETCH();

						return nMyPos;
					}

					printf("获取私有密钥访问控制码成功\n");
				}

				sprintf(filename, "data/keybyisk.%d", nKeyIndex);
				nKeylen = FileRead(filename, "rb", pucKey, sizeof(pucKey));

				if(nKeylen < 128)
				{
					if(strlen(passwd) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
					}
					
					printf("读会话密钥文件错误。\n");
				}
				else
				{
					printf("从文件中读取会话密钥成功。\n");

					rv = SDF_ImportKeyWithISK_RSA(hSessionHandle, nKeyIndex, pucKey, nKeylen, phKeyHandle);
					if(rv != SDR_OK)
					{
						if(strlen(passwd) != 0)
						{
							SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
						}

						printf("导入会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						if(strlen(passwd) != 0)
						{
							rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
							if(rv != SDR_OK)
							{
								printf("释放私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
							}

							printf("释放私有密钥访问控制码成功\n");
						}
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			if(nSel == 4)
			{
				if(strlen(passwd) != 0)
				{
					rv = SDF_GetPrivateKeyAccessRight(hSessionHandle, nKeyIndex, passwd, (unsigned int)strlen(passwd));
					if(rv != SDR_OK)
					{
						printf("获取私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
						printf("\n按任意键继续...");
						GETCH();

						return nMyPos;
					}

					printf("获取私有密钥访问控制码成功\n");
				}

				sprintf(filename, "data/keybyisk_ecc.%d", nKeyIndex);
				nKeylen = FileRead(filename, "rb", (unsigned char *)&ECC_pucKey, sizeof(ECCCipher));

				if(nKeylen < sizeof(ECCCipher))
				{
					if(strlen(passwd) != 0)
					{
						SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
					}

					printf("读会话密钥文件错误。\n");
				}
				else
				{
					printf("从文件中读取会话密钥成功。\n");

					rv = SDF_ImportKeyWithISK_ECC(hSessionHandle, nKeyIndex, &ECC_pucKey, phKeyHandle);
					if(rv != SDR_OK)
					{
						if(strlen(passwd) != 0)
						{
							SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
						}

						printf("导入会话密钥错误，错误码[0x%08x]\n", rv);
					}
					else
					{
						printf("导入会话密钥成功。\n");
						printf("可以使用该密钥进行对称加解密运算测试。\n");

						if(strlen(passwd) != 0)
						{
							rv = SDF_ReleasePrivateKeyAccessRight(hSessionHandle, nKeyIndex);
							if(rv != SDR_OK)
							{
								printf("释放私有密钥访问控制码失败，错误码[0x%08x]\n", rv);
							}

							printf("释放私有密钥访问控制码成功\n");
						}
					}
				}

				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		default:
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		} //end switch
	}//end while

	return nMyPos;
}

int DestroyKeyTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	unsigned int rv;

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("销毁会话密钥测试:\n");
	printf("-----------------\n");
	printf("\n");

	if(*phKeyHandle == NULL)
	{
		printf("会话密钥句柄无效，请确认密钥已产生/导入...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	rv = SDF_DestroyKey(hSessionHandle, *phKeyHandle);
	if(rv != SDR_OK)
	{
		printf("销毁会话密钥错误，错误码[0x%08x]\n", rv);
	}
	else
	{
		*phKeyHandle = NULL;

		printf("销毁会话密钥成功。\n");
	}

	printf("\n");
	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

#if 0
int SymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("对称运算加解密测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");

	//判定对称密钥句柄是否有效
	if(*phKeyHandle == NULL)
	{
		printf("会话密钥句柄无效，请确认密钥已产生/导入...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}


	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}

			printf("\n");
			printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为16K)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 8, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:

			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试\n");
			printf("---------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);
			
			memset(pIv, 0, 16);

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				rv = SDF_Encrypt(hSessionHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
				if(rv == SDR_OK)
				{
					memset(pIv, 0, 16);

					rv = SDF_Decrypt(hSessionHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
					if(rv == SDR_OK)
					{
						if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
						{
							printf("运算结果：加密、解密及结果比较均正确。\n");
						}
						else
						{
							printf("运算结果：解密结果错误。\n");
						}
					}
					else
					{
						printf("运算结果：解密错误，[0x%08x]\n", rv);
					}
				}
				else
				{
					printf("运算结果：加密错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

#if 0
int SymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("对称运算加解密测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");

	//判定对称密钥句柄是否有效
	if(*phKeyHandle == NULL)
	{
		printf("会话密钥句柄无效，请确认密钥已产生/导入...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}


	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & 0xFFFFFF00)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为16K)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 8, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:

			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试\n");
			printf("---------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);
			
			memset(pIv, 0, 16);

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				rv = SDF_Encrypt(hSessionHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
				if(rv == SDR_OK)
				{
					memset(pIv, 0, 16);

					rv = SDF_Decrypt(hSessionHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
					if(rv == SDR_OK)
					{
						if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
						{
							printf("运算结果：加密、解密及结果比较均正确。\n");
						}
						else
						{
							printf("运算结果：解密结果错误。\n");
						}
					}
					else
					{
						printf("运算结果：解密错误，[0x%08x]\n", rv);
					}
				}
				else
				{
					printf("运算结果：加密错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

int SymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle, SGD_HANDLE *phKeyHandle)
{
	int rv;
	int step = 0;
	int i = 1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen, nEnclen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[MAX_SYMM_DATA_LENGTH], pEncdata[MAX_SYMM_DATA_LENGTH], pOutdata[MAX_SYMM_DATA_LENGTH];

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("对称运算加解密测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");

	//判定对称密钥句柄是否有效
	if(*phKeyHandle == NULL)
	{
		printf("会话密钥句柄无效，请确认密钥已产生/导入...\n");
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}


	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %2d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %2d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %2d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %2d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %2d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %2d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;

				if(stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK)
				{
					printf("  %2d | SGD_SM4_XTS\n\n", i);
					puiAlg[i++]=SGD_SM4_XTS;
				}
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %2d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %2d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为%dK)。\n", MAX_SYMM_DATA_LENGTH / 1024);
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 8, MAX_SYMM_DATA_LENGTH);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:

			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("对称运算加解密测试\n");
			printf("---------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);
			
			memset(pIv, 0, 16);

			memset(pIndata, 0, sizeof(pIndata));

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				memset(pEncdata, 0, sizeof(pEncdata));
				nEnclen = sizeof(pEncdata);

				if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
				{
					rv = SDF_Encrypt(hSessionHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
				}
				else
				{
					rv = SDF_Encrypt_Ex(hSessionHandle, *phKeyHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen, nInlen);
				}

				if(rv == SDR_OK)
				{
					memset(pIv, 0, 16);

					memset(pOutdata, 0, sizeof(pOutdata));
					nOutlen = sizeof(pOutdata);

					if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
					{
						rv = SDF_Decrypt(hSessionHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
					}
					else
					{
						rv = SDF_Decrypt_Ex(hSessionHandle, *phKeyHandle, *phKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen, nEnclen);
					}

					if(rv == SDR_OK)
					{
						if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
						{
							printf("运算结果：加密、解密及结果比较均正确。\n");
						}
						else
						{
							printf("运算结果：解密结果错误。\n");
						}
					}
					else
					{
						printf("运算结果：解密错误，[0x%08x]\n", rv);
					}
				}
				else
				{
					printf("运算结果：加密错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

#if 0
int SymmCorrectnessTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int num = 1;
	SGD_HANDLE hKeyHandle;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16];
	unsigned int nInlen;

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("算法正确性测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");
	printf("\n");

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbPlainText[16] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
		unsigned char pbCipherText[16] = {0x6d,0x7f,0x45,0xb0,0x8b,0xc4,0xd9,0x66,0x44,0x4c,0x86,0xc2,0xb0,0x7d,0x29,0x93};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM1_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM1_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;			
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM1_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_CBC & 0xFFFFFF00)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0x3a,0x70,0xb5,0xd4,0x9a,0x78,0x2c,0x07,0x2d,0xe1,0x13,0x43,0x81,0x9e,0xc6,0x59,0xf8,0xfc,0x7a,0xf0,0x5e,0x7c,0x6d,0xfb,0x5f,0x81,0x09,0x0f,0x0d,0x87,0x91,0xb2};
		unsigned char pbTempData[128] = {0};
		unsigned int ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM1_CBC运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM1_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//加密结果与标准密文比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM1_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x67,0xbe,0x03,0x7c,0x41,0x96,0x6d,0xdb,0x8c,0x36,0x27,0x48,0x5a,0x05,0x93,0xa5};
		unsigned char pbPlainText[16] = {0xa9,0x37,0x07,0x49,0xfc,0x06,0xaf,0xe6,0x4e,0x30,0x68,0x01,0xd2,0x31,0xb3,0xac};
		unsigned char pbCipherText[16] = {0x9a,0xb7,0x1c,0xcc,0x22,0x7e,0x9e,0x58,0x7a,0xa0,0xe6,0xcf,0x49,0x08,0x5d,0x1f};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SSF33_ECB运算 | ", num++);
		
		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SSF33_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;						
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SSF33_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_CBC & 0xFFFFFF00)
	{
		//标准数据校验
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0xfd,0x3e,0x17,0xf4,0xde,0x33,0xe2,0x96,0xf9,0x9e,0x37,0x92,0x45,0x6b,0x76,0x2b,0x9e,0xe7,0x13,0x44,0x5d,0x91,0x95,0xf6,0x4b,0x34,0x1b,0x3a,0xe7,0x5c,0x68,0x75};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SSF33_CBC运算 | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SSF33_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SSF33_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{			
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}


	if (stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
		unsigned char pbPlainText[16] = {0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20};
		unsigned char pbCipherText[16] = {0xde,0x2e,0x12,0xe4,0x0b,0xd1,0xd8,0x60,0xe3,0xe4,0x24,0x31,0x3b,0xd3,0x72,0xdc};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| AES_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_AES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_AES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[8] = {0x67,0xbe,0x03,0x7c,0x41,0x96,0x6d,0xdb};
		unsigned char pbPlainText[8] = {0xa9,0x37,0x07,0x49,0xfc,0x06,0xaf,0xe6};
		unsigned char pbCipherText[8] = {0x60,0x78,0x32,0xe8,0xb3,0x5a,0x9c,0x6d};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| DES_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 8, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 8;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_DES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;							
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_DES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbPlainText[8] = {0x49,0x07,0x37,0xa9,0xe6,0xaf,0x06,0xfc};
		unsigned char pbCipherText[8] = {0x43,0x01,0xc5,0x6b,0x14,0x00,0xe7,0xce};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| 3DES_ECB运算  | ",num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 8;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_3DES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_3DES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbPlainText[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbCipherText[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_ECB运算  | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}


	if (stDeviceInfo.SymAlgAbility & SGD_SM4_CBC & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbIV[16] = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
		unsigned char pbPlainText[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
		unsigned char pbCipherText[32] = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_CBC运算  | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;					
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}
#endif

#if 0
int SymmCorrectnessTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int num = 1;
	SGD_HANDLE hKeyHandle;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16];
	unsigned int nInlen;

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("算法正确性测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");
	printf("\n");

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbPlainText[16] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
		unsigned char pbCipherText[16] = {0x6d,0x7f,0x45,0xb0,0x8b,0xc4,0xd9,0x66,0x44,0x4c,0x86,0xc2,0xb0,0x7d,0x29,0x93};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM1_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM1_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;			
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM1_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_CBC & 0xFFFFFF00)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0x3a,0x70,0xb5,0xd4,0x9a,0x78,0x2c,0x07,0x2d,0xe1,0x13,0x43,0x81,0x9e,0xc6,0x59,0xf8,0xfc,0x7a,0xf0,0x5e,0x7c,0x6d,0xfb,0x5f,0x81,0x09,0x0f,0x0d,0x87,0x91,0xb2};
		unsigned char pbTempData[128] = {0};
		unsigned int ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM1_CBC运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM1_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//加密结果与标准密文比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM1_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x67,0xbe,0x03,0x7c,0x41,0x96,0x6d,0xdb,0x8c,0x36,0x27,0x48,0x5a,0x05,0x93,0xa5};
		unsigned char pbPlainText[16] = {0xa9,0x37,0x07,0x49,0xfc,0x06,0xaf,0xe6,0x4e,0x30,0x68,0x01,0xd2,0x31,0xb3,0xac};
		unsigned char pbCipherText[16] = {0x9a,0xb7,0x1c,0xcc,0x22,0x7e,0x9e,0x58,0x7a,0xa0,0xe6,0xcf,0x49,0x08,0x5d,0x1f};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SSF33_ECB运算 | ", num++);
		
		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SSF33_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;						
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SSF33_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_CBC & 0xFFFFFF00)
	{
		//标准数据校验
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0xfd,0x3e,0x17,0xf4,0xde,0x33,0xe2,0x96,0xf9,0x9e,0x37,0x92,0x45,0x6b,0x76,0x2b,0x9e,0xe7,0x13,0x44,0x5d,0x91,0x95,0xf6,0x4b,0x34,0x1b,0x3a,0xe7,0x5c,0x68,0x75};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SSF33_CBC运算 | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SSF33_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SSF33_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{			
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}


	if (stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
		unsigned char pbPlainText[16] = {0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20};
		unsigned char pbCipherText[16] = {0xde,0x2e,0x12,0xe4,0x0b,0xd1,0xd8,0x60,0xe3,0xe4,0x24,0x31,0x3b,0xd3,0x72,0xdc};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| AES_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_AES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_AES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[8] = {0x67,0xbe,0x03,0x7c,0x41,0x96,0x6d,0xdb};
		unsigned char pbPlainText[8] = {0xa9,0x37,0x07,0x49,0xfc,0x06,0xaf,0xe6};
		unsigned char pbCipherText[8] = {0x60,0x78,0x32,0xe8,0xb3,0x5a,0x9c,0x6d};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| DES_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 8, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 8;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_DES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;							
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_DES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbPlainText[8] = {0x49,0x07,0x37,0xa9,0xe6,0xaf,0x06,0xfc};
		unsigned char pbCipherText[8] = {0x43,0x01,0xc5,0x6b,0x14,0x00,0xe7,0xce};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| 3DES_ECB运算  | ",num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 8;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_3DES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_3DES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbPlainText[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbCipherText[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}


	if (stDeviceInfo.SymAlgAbility & SGD_SM4_CBC & 0xFFFFFF00)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbIV[16] = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
		unsigned char pbPlainText[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
		unsigned char pbCipherText[32] = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_CBC运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;					
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & 0xFFFFFF00)
	{
		//标准数据 -- 第一组
		//unsigned char pbKeyValue[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		//unsigned char pbPlainText[8] = {0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
		//unsigned char pbCipherText[8] = {0x67,0xfa,0xa9,0x75,0xf1,0x28,0xd1,0xfc};

		//标准数据 -- 第二组
		//unsigned char pbKeyValue[16] = {0x1F,0xD3,0x84,0xD8,0x6B,0x50,0xBE,0x01,0x21,0x43,0xD6,0x16,0x18,0x15,0x19,0x83};
		//unsigned char pbPlainText[8] = {0xE2,0x73,0x2F,0xB8,0x1D,0x7D,0x7E,0x51};
		//unsigned char pbCipherText[8] = {0xCE,0x3C,0x08,0xD4,0x02,0xAE,0x24,0x7C};

		//标准数据 -- 第三组
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
		unsigned char pbPlainText[8] = {0x1a,0x17,0x02,0xe5,0xea,0x62,0x31,0xb4};
		unsigned char pbCipherText[8] = {0xaf,0xa2,0xb6,0x9d,0xca,0x09,0xa3,0xef};

		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM7_ECB运算   | ",num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 8;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM7_ECB, NULL, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;			
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM7_ECB, NULL, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}
#endif

int SymmCorrectnessTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int num = 1;
	SGD_HANDLE hKeyHandle;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16];
	unsigned int nInlen;

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("算法正确性测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");
	printf("\n");

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbPlainText[16] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
		unsigned char pbCipherText[16] = {0x6d,0x7f,0x45,0xb0,0x8b,0xc4,0xd9,0x66,0x44,0x4c,0x86,0xc2,0xb0,0x7d,0x29,0x93};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM1_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM1_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;			
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM1_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_CBC & SGD_SYMM_ALG_MASK)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0x3a,0x70,0xb5,0xd4,0x9a,0x78,0x2c,0x07,0x2d,0xe1,0x13,0x43,0x81,0x9e,0xc6,0x59,0xf8,0xfc,0x7a,0xf0,0x5e,0x7c,0x6d,0xfb,0x5f,0x81,0x09,0x0f,0x0d,0x87,0x91,0xb2};
		unsigned char pbTempData[128] = {0};
		unsigned int ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM1_CBC运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM1_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//加密结果与标准密文比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM1_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x67,0xbe,0x03,0x7c,0x41,0x96,0x6d,0xdb,0x8c,0x36,0x27,0x48,0x5a,0x05,0x93,0xa5};
		unsigned char pbPlainText[16] = {0xa9,0x37,0x07,0x49,0xfc,0x06,0xaf,0xe6,0x4e,0x30,0x68,0x01,0xd2,0x31,0xb3,0xac};
		unsigned char pbCipherText[16] = {0x9a,0xb7,0x1c,0xcc,0x22,0x7e,0x9e,0x58,0x7a,0xa0,0xe6,0xcf,0x49,0x08,0x5d,0x1f};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SSF33_ECB运算 | ", num++);
		
		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SSF33_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;						
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SSF33_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_CBC & SGD_SYMM_ALG_MASK)
	{
		//标准数据校验
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0xfd,0x3e,0x17,0xf4,0xde,0x33,0xe2,0x96,0xf9,0x9e,0x37,0x92,0x45,0x6b,0x76,0x2b,0x9e,0xe7,0x13,0x44,0x5d,0x91,0x95,0xf6,0x4b,0x34,0x1b,0x3a,0xe7,0x5c,0x68,0x75};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SSF33_CBC运算 | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SSF33_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SSF33_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{			
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}


	if (stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
		unsigned char pbPlainText[16] = {0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20};
		unsigned char pbCipherText[16] = {0xde,0x2e,0x12,0xe4,0x0b,0xd1,0xd8,0x60,0xe3,0xe4,0x24,0x31,0x3b,0xd3,0x72,0xdc};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| AES_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_AES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_AES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[8] = {0x67,0xbe,0x03,0x7c,0x41,0x96,0x6d,0xdb};
		unsigned char pbPlainText[8] = {0xa9,0x37,0x07,0x49,0xfc,0x06,0xaf,0xe6};
		unsigned char pbCipherText[8] = {0x60,0x78,0x32,0xe8,0xb3,0x5a,0x9c,0x6d};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| DES_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 8, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 8;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_DES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;							
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_DES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbPlainText[8] = {0x49,0x07,0x37,0xa9,0xe6,0xaf,0x06,0xfc};
		unsigned char pbCipherText[8] = {0x43,0x01,0xc5,0x6b,0x14,0x00,0xe7,0xce};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| 3DES_ECB运算  | ",num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 8;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_3DES_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_3DES_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbPlainText[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbCipherText[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_ECB运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(pIv, 0, 16);

		nInlen = 16;
		
		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);
		
		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, pIv, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;				
			}

			memset(pIv, 0, 16);

			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);
			
			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_ECB, pIv, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}


	if (stDeviceInfo.SymAlgAbility & SGD_SM4_CBC & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbIV[16] = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
		unsigned char pbPlainText[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
		unsigned char pbCipherText[32] = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_CBC运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;					
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM4_CBC, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if ((stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MASK) && (stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbIV[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbPlainText[48] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
										 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x11,
										 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x12};
		unsigned char pbCipherText[48] = {0x55,0x13,0xa7,0x57,0x57,0xaf,0xc1,0xc2,0xa2,0xb6,0xc2,0x11,0x6f,0xeb,0x2b,0x19,
										  0x29,0x53,0x9b,0x73,0xe5,0x35,0x00,0x06,0xab,0x29,0xb6,0xe0,0x84,0x7b,0xe1,0x67,
										  0x6d,0xd9,0x21,0x65,0x41,0x51,0x4a,0x24,0xc4,0x19,0xd3,0xb7,0xd7,0xe0,0x3c,0xf1};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;
		
		printf("   %02d| SM4_XTS运算   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		nInlen = 48;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt_Ex(hSessionHandle, hKeyHandle, hKeyHandle, SGD_SM4_XTS, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen, nInlen);
		if(rv == SDR_OK)
		{
			//与标准密文数据比较
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;					
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt_Ex(hSessionHandle, hKeyHandle, hKeyHandle, SGD_SM4_XTS, pbIV, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen, ulTempDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");

					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
					
					printf("运算结果：解密结果与标准明文数据比较失败。\n");	
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;	
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，错误码[0x%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
	{
		//标准数据 -- 第一组
		//unsigned char pbKeyValue[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		//unsigned char pbPlainText[8] = {0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
		//unsigned char pbCipherText[8] = {0x67,0xfa,0xa9,0x75,0xf1,0x28,0xd1,0xfc};

		//标准数据 -- 第二组
		//unsigned char pbKeyValue[16] = {0x1F,0xD3,0x84,0xD8,0x6B,0x50,0xBE,0x01,0x21,0x43,0xD6,0x16,0x18,0x15,0x19,0x83};
		//unsigned char pbPlainText[8] = {0xE2,0x73,0x2F,0xB8,0x1D,0x7D,0x7E,0x51};
		//unsigned char pbCipherText[8] = {0xCE,0x3C,0x08,0xD4,0x02,0xAE,0x24,0x7C};

		//标准数据 -- 第三组
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
		unsigned char pbPlainText[8] = {0x1a,0x17,0x02,0xe5,0xea,0x62,0x31,0xb4};
		unsigned char pbCipherText[8] = {0xaf,0xa2,0xb6,0x9d,0xca,0x09,0xa3,0xef};

		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		unsigned char pbOutData[128] = {0};
		unsigned int  ulOutDataLen;

		printf("   %02d| SM7_ECB运算   | ",num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		
		nInlen = 8;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_Encrypt(hSessionHandle, hKeyHandle, SGD_SM7_ECB, NULL, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv == SDR_OK)
		{
			if((nInlen == ulTempDataLen) && (memcmp(pbCipherText, pbTempData, nInlen) == 0))
			{
				;
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);
				
				printf("运算结果：加密密文与标准密文数据比较失败。\n");	
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;			
			}
			
			memset(pbOutData, 0, sizeof(pbOutData));
			ulOutDataLen = sizeof(pbOutData);

			rv = SDF_Decrypt(hSessionHandle, hKeyHandle, SGD_SM7_ECB, NULL, pbTempData, ulTempDataLen, pbOutData, &ulOutDataLen);
			if(rv == SDR_OK)
			{
				if((ulOutDataLen == nInlen) && (memcmp(pbPlainText, pbOutData, nInlen) == 0))
				{
					printf("标准数据加密、解密及结果比较均正确。\n");
					SDF_DestroyKey(hSessionHandle, hKeyHandle);
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：解密后结果与标准明文数据比较失败。\n");
					printf("\n按任意键继续...");
					GETCH();

					return nMyPos;
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：解密错误，[%08x]\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}
		}
		else
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：加密错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

//计算MAC测试
int SymmCalculateMACTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int num = 1;
	SGD_HANDLE hKeyHandle;
	DEVICEINFO stDeviceInfo;
	unsigned int nInlen;

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("MAC算法正确性测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");

	if (stDeviceInfo.SymAlgAbility & SGD_SM1_CBC & SGD_SYMM_ALG_MASK)
	{
		//标准数据
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0x3a,0x70,0xb5,0xd4,0x9a,0x78,0x2c,0x07,0x2d,0xe1,0x13,0x43,0x81,0x9e,0xc6,0x59,0xf8,0xfc,0x7a,0xf0,0x5e,0x7c,0x6d,0xfb,0x5f,0x81,0x09,0x0f,0x0d,0x87,0x91,0xb2};
		unsigned char pbTempData[128] = {0};
		unsigned int ulTempDataLen;

		printf("   %02d| SM1_MAC   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		//标准数据计算MAC测试
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_CalculateMAC(hSessionHandle, hKeyHandle, SGD_SM1_MAC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv != SDR_OK)
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：标准数据计算MAC错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;			
		}

		//销毁对称密钥
		SDF_DestroyKey(hSessionHandle, hKeyHandle);

		//与标准MAC比较
		if((ulTempDataLen != 16) || (memcmp(&pbCipherText[16], pbTempData, 16) != 0))
		{
			printf("运算结果：标准数据计算MAC结果值与标准MAC值不相等。\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;			
		}
		else
		{
			printf("标准数据计算MAC值及结果比较均正确。\n");
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SSF33_CBC & SGD_SYMM_ALG_MASK)
	{
		//标准数据校验
		unsigned char pbKeyValue[16] = {0x40,0xbb,0x12,0xdd,0x6a,0x82,0x73,0x86,0x7f,0x35,0x29,0xd3,0x54,0xb4,0xa0,0x26};
		unsigned char pbIV[16] = {0xe8,0x3d,0x17,0x15,0xac,0xf3,0x48,0x63,0xac,0xeb,0x93,0xe0,0xe5,0xab,0x8b,0x90};
		unsigned char pbPlainText[32] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
		unsigned char pbCipherText[32] = {0xfd,0x3e,0x17,0xf4,0xde,0x33,0xe2,0x96,0xf9,0x9e,0x37,0x92,0x45,0x6b,0x76,0x2b,0x9e,0xe7,0x13,0x44,0x5d,0x91,0x95,0xf6,0x4b,0x34,0x1b,0x3a,0xe7,0x5c,0x68,0x75};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;

		printf("   %02d| SSF33_MAC | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		//标准数据计算MAC测试
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_CalculateMAC(hSessionHandle, hKeyHandle, SGD_SSF33_MAC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv != SDR_OK)
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：标准数据计算MAC错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;			
		}

		//销毁对称密钥
		SDF_DestroyKey(hSessionHandle, hKeyHandle);

		//与标准MAC比较
		if((ulTempDataLen != 16) || (memcmp(&pbCipherText[16], pbTempData, 16) != 0))
		{
			printf("运算结果：标准数据计算MAC结果值与标准MAC值不相等。\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;			
		}
		else
		{
			printf("标准数据计算MAC值及结果比较均正确。\n");
		}
	}

	if (stDeviceInfo.SymAlgAbility & SGD_SM4_CBC & SGD_SYMM_ALG_MASK)
	{
		//与标准数据比较
		unsigned char pbKeyValue[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
		unsigned char pbIV[16] = {0xeb,0xee,0xc5,0x68,0x58,0xe6,0x04,0xd8,0x32,0x7b,0x9b,0x3c,0x10,0xc9,0x0c,0xa7};
		unsigned char pbPlainText[32] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x29,0xbe,0xe1,0xd6,0x52,0x49,0xf1,0xe9,0xb3,0xdb,0x87,0x3e,0x24,0x0d,0x06,0x47};
		unsigned char pbCipherText[32] = {0x3f,0x1e,0x73,0xc3,0xdf,0xd5,0xa1,0x32,0x88,0x2f,0xe6,0x9d,0x99,0x6c,0xde,0x93,0x54,0x99,0x09,0x5d,0xde,0x68,0x99,0x5b,0x4d,0x70,0xf2,0x30,0x9f,0x2e,0xf1,0xb7};
		unsigned char pbTempData[128] = {0};
		unsigned int  ulTempDataLen;
		
		printf("   %02d| SM4_MAC   | ", num++);

		rv = SDF_ImportKey(hSessionHandle, pbKeyValue, 16, &hKeyHandle);
		if(rv != SDR_OK)
		{
			printf("导入明文会话密钥错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		//标准数据计算MAC测试
		nInlen = 32;

		memset(pbTempData, 0, sizeof(pbTempData));
		ulTempDataLen = sizeof(pbTempData);

		rv = SDF_CalculateMAC(hSessionHandle, hKeyHandle, SGD_SM4_MAC, pbIV, pbPlainText, nInlen, pbTempData, &ulTempDataLen);
		if(rv != SDR_OK)
		{
			SDF_DestroyKey(hSessionHandle, hKeyHandle);

			printf("运算结果：标准数据计算MAC错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;			
		}

		//销毁对称密钥
		SDF_DestroyKey(hSessionHandle, hKeyHandle);

		//与标准MAC比较
		if((ulTempDataLen != 16) || (memcmp(&pbCipherText[16], pbTempData, 16) != 0))
		{
			printf("运算结果：标准数据计算MAC结果值与标准MAC值不相等。\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;			
		}
		else
		{
			printf("标准数据计算MAC值及结果比较均正确。\n");
		}
	}

	printf("\n按任意键继续...");
	GETCH();

	return nMyPos;
}

#if 0
int InSymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	SGD_HANDLE hKeyHandle;
	int step = 0;
	int i = 1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen, nEnclen, nOutlen;
	int nKeyIndex;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}

			printf("\n");
			printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)][下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为16K)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 8, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n输入对称密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nKeyIndex = GetInputLength(1, 1, 100);

			if(nKeyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndex == OPT_RETURN)
				return nMyPos;

			if(nKeyIndex == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndex < 1) || (nKeyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);
			
			rv = SDF_GetSymmKeyHandle(hSessionHandle, nKeyIndex, &hKeyHandle);
			if(rv != SDR_OK)
			{
				printf("获取对称密钥句柄失败，0x%08x\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pIv, 0, 16);

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				rv = SDF_Encrypt(hSessionHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
				if(rv == SDR_OK)
				{
					memset(pIv, 0, 16);

					rv = SDF_Decrypt(hSessionHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
					if(rv == SDR_OK)
					{
						if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
						{
							printf("运算结果：加密、解密及结果比较均正确。\n");

							SDF_DestroyKey(hSessionHandle, hKeyHandle);
						}
						else
						{
							SDF_DestroyKey(hSessionHandle, hKeyHandle);

							printf("运算结果：解密结果错误。\n");
						}
					}
					else
					{
						SDF_DestroyKey(hSessionHandle, hKeyHandle);

						printf("运算结果：解密错误，[%08x]\n", rv);
					}
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：加密错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

#if 0
int InSymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	SGD_HANDLE hKeyHandle;
	int step = 0;
	int i = 1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen, nEnclen, nOutlen;
	int nKeyIndex;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[16384], pEncdata[16384], pOutdata[16384];

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %02d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %02d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %02d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %02d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %02d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %02d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & 0xFFFFFF00)
			{
				printf("  %02d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %02d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)][下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为16K)。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 8, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n输入对称密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nKeyIndex = GetInputLength(1, 1, 100);

			if(nKeyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndex == OPT_RETURN)
				return nMyPos;

			if(nKeyIndex == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndex < 1) || (nKeyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);
			
			rv = SDF_GetSymmKeyHandle(hSessionHandle, nKeyIndex, &hKeyHandle);
			if(rv != SDR_OK)
			{
				printf("获取对称密钥句柄失败，0x%08x\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pIv, 0, 16);

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				rv = SDF_Encrypt(hSessionHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
				if(rv == SDR_OK)
				{
					memset(pIv, 0, 16);

					rv = SDF_Decrypt(hSessionHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
					if(rv == SDR_OK)
					{
						if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
						{
							printf("运算结果：加密、解密及结果比较均正确。\n");

							SDF_DestroyKey(hSessionHandle, hKeyHandle);
						}
						else
						{
							SDF_DestroyKey(hSessionHandle, hKeyHandle);

							printf("运算结果：解密结果错误。\n");
						}
					}
					else
					{
						SDF_DestroyKey(hSessionHandle, hKeyHandle);

						printf("运算结果：解密错误，[%08x]\n", rv);
					}
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：加密错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}
#endif

int InSymmEncDecTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	SGD_HANDLE hKeyHandle;
	int step = 0;
	int i = 1;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int nInlen, nEnclen, nOutlen;
	int nKeyIndex;
	DEVICEINFO stDeviceInfo;
	unsigned char pIv[16], pIndata[MAX_SYMM_DATA_LENGTH], pEncdata[MAX_SYMM_DATA_LENGTH], pOutdata[MAX_SYMM_DATA_LENGTH];

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_SM1_ECB\n\n", i);
				puiAlg[i++]=SGD_SM1_ECB;
				printf("  %02d | SGD_SM1_CBC\n\n", i);
				puiAlg[i++]=SGD_SM1_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_SSF33_ECB\n\n", i);
				puiAlg[i++]=SGD_SSF33_ECB;
				printf("  %02d | SGD_SSF33_CBC\n\n", i);
				puiAlg[i++]=SGD_SSF33_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_AES_ECB\n\n", i);
				puiAlg[i++]=SGD_AES_ECB;
				printf("  %02d | SGD_AES_CBC\n\n", i);
				puiAlg[i++]=SGD_AES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_DES_ECB\n\n", i);
				puiAlg[i++]=SGD_DES_ECB;
				printf("  %02d | SGD_DES_CBC\n\n", i);
				puiAlg[i++]=SGD_DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_3DES_ECB\n\n", i);
				puiAlg[i++]=SGD_3DES_ECB;
				printf("  %02d | SGD_3DES_CBC\n\n", i);
				puiAlg[i++]=SGD_3DES_CBC;
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_SM4_ECB\n\n", i);
				puiAlg[i++]=SGD_SM4_ECB;
				printf("  %02d | SGD_SM4_CBC\n\n", i);
				puiAlg[i++]=SGD_SM4_CBC;

				if(stDeviceInfo.SymAlgAbility & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK)
				{
					printf("  %02d | SGD_SM4_XTS\n\n", i);
					puiAlg[i++]=SGD_SM4_XTS;
				}
			}
			if(stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
			{
				printf("  %02d | SGD_SM7_ECB\n\n", i);
				puiAlg[i++]=SGD_SM7_ECB;
				printf("  %02d | SGD_SM7_CBC\n\n", i);
				puiAlg[i++]=SGD_SM7_CBC;
			}

			printf("\n");
			printf("\n选择加密算法(默认[%d])，或 [退出(Q)] [返回(R)][下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("请选择输入数据的长度，必须为分组长度的整数倍(程序支持的最大长度为%dK)。\n", MAX_SYMM_DATA_LENGTH / 1024);
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 8, MAX_SYMM_DATA_LENGTH);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------------\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n输入对称密钥索引(默认[1])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nKeyIndex = GetInputLength(1, 1, 100);

			if(nKeyIndex == OPT_EXIT)
				return OPT_EXIT;

			if(nKeyIndex == OPT_RETURN)
				return nMyPos;

			if(nKeyIndex == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//密钥索引参数检查
			if((nKeyIndex < 1) || (nKeyIndex > 100))
			{
				printf("\n密钥索引输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("内部对称密钥加解密运算测试:\n");
			printf("---------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);
			
			rv = SDF_GetSymmKeyHandle(hSessionHandle, nKeyIndex, &hKeyHandle);
			if(rv != SDR_OK)
			{
				printf("获取对称密钥句柄失败，0x%08x\n", rv);
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;
			}

			memset(pIv, 0, 16);

			memset(pIndata, 0, sizeof(pIndata));

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				memset(pEncdata, 0, sizeof(pEncdata));
				nEnclen = sizeof(pEncdata);

				if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
				{
					rv = SDF_Encrypt(hSessionHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen);
				}
				else
				{
					rv = SDF_Encrypt_Ex(hSessionHandle, hKeyHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pIndata, nInlen, pEncdata, &nEnclen, nInlen);
				}

				if(rv == SDR_OK)
				{
					memset(pIv, 0, 16);

					memset(pOutdata, 0, sizeof(pOutdata));
					nOutlen = sizeof(pOutdata);

					if(!(puiAlg[nSelAlg] & SGD_SM4_XTS & SGD_SYMM_ALG_MODE_MASK))
					{
						rv = SDF_Decrypt(hSessionHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen);
					}
					else
					{
						rv = SDF_Decrypt_Ex(hSessionHandle, hKeyHandle, hKeyHandle, puiAlg[nSelAlg], pIv, pEncdata, nEnclen, pOutdata, &nOutlen, nEnclen);
					}

					if(rv == SDR_OK)
					{
						if((nOutlen == nInlen) && (memcmp(pOutdata, pIndata, nInlen) == 0))
						{
							printf("运算结果：加密、解密及结果比较均正确。\n");

							SDF_DestroyKey(hSessionHandle, hKeyHandle);
						}
						else
						{
							SDF_DestroyKey(hSessionHandle, hKeyHandle);

							printf("运算结果：解密结果错误。\n");
						}
					}
					else
					{
						SDF_DestroyKey(hSessionHandle, hKeyHandle);

						printf("运算结果：解密错误，[%08x]\n", rv);
					}
				}
				else
				{
					SDF_DestroyKey(hSessionHandle, hKeyHandle);

					printf("运算结果：加密错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				SDF_DestroyKey(hSessionHandle, hKeyHandle);

				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

int HashFuncTest(int nMyPos, int nDefaultSelect)
{
	int rv;
	int nSel;
	SGD_HANDLE hSessionHandle;

	if((nDefaultSelect < 1) || (nDefaultSelect > 2)) 
		nSel = 1;
	else
		nSel = nDefaultSelect;

	//创建会话句柄
	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(rv != SDR_OK)
	{
		printf("打开会话句柄错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("杂凑算法测试:\n");
		printf("-------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|杂凑算法运算测试\n");
	else
		printf("   1|杂凑算法运算测试\n");
		printf("    |    对输入数据进行杂凑运算并输出结果。\n");
		printf("\n");
	if(nSel == 2)
		printf(" ->2|杂凑算法正确性测试\n");
	else
		printf("   2|杂凑算法正确性测试\n");
		printf("    |    使用标准数据验证杂凑算法的正确性。\n");
		printf("\n");
		printf("\n");
		printf("选择测试项目 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetSelect(nSel, 2);

		switch(nSel)
		{
		case 1:
			nSel = HashTest(1, hSessionHandle);
			break;
		case 2:
			nSel = HashCorrectnessTest(2, hSessionHandle);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
		{
			SDF_CloseSession(hSessionHandle);

			return OPT_EXIT;
		}

		if(nSel == OPT_RETURN)
		{
			SDF_CloseSession(hSessionHandle);

			return nMyPos;
		}
	}

	return nMyPos;
}

int HashTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	int rv;
	int step = 0;
	unsigned int puiAlg[20];
	int nSelAlg = 1;
	int i = 1;
	int nInlen, nOutlen;
	DEVICEINFO stDeviceInfo;
	unsigned char pIndata[16384], pOutdata[128];

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("哈希算法运算测试:\n");
			printf("-------------\n");
			printf("\n");
			printf("从以下支持的算法中选择一项进行测试。\n");
			printf("\n");

			i=1;

			if(stDeviceInfo.HashAlgAbility & SGD_SM3 & 0xFF)
			{
				printf("  %d | SGD_SM3\n\n", i);
				puiAlg[i++]=SGD_SM3;
			}
			if(stDeviceInfo.HashAlgAbility & SGD_SHA1 & 0xFF)
			{
				printf("  %d | SGD_SHA1\n\n", i);
				puiAlg[i++]=SGD_SHA1;
			}
			if(stDeviceInfo.HashAlgAbility & SGD_SHA224 & 0xFF)
			{
				printf("  %d | SGD_SHA224\n\n", i);
				puiAlg[i++]=SGD_SHA224;
			}
			if(stDeviceInfo.HashAlgAbility & SGD_SHA256 & 0xFF)
			{
				printf("  %d | SGD_SHA256\n\n", i);
				puiAlg[i++]=SGD_SHA256;
			}
			if(stDeviceInfo.HashAlgAbility & SGD_SHA384 & 0xFF)
			{
				printf("  %d | SGD_SHA384\n\n", i);
				puiAlg[i++]=SGD_SHA384;
			}
			if(stDeviceInfo.HashAlgAbility & SGD_SHA512 & 0xFF)
			{
				printf("  %d | SGD_SHA512\n\n", i);
				puiAlg[i++]=SGD_SHA512;
			}
			if(stDeviceInfo.HashAlgAbility & SGD_MD5 & 0xFF)
			{
				printf("  %d | SGD_MD5\n\n", i);
				puiAlg[i++]=SGD_MD5;
			}

			printf("\n");
			printf("\n选择杂凑算法(默认[%d])，或 [退出(Q)] [返回(R)] [下一步(N)]>", 1);
			nSelAlg = GetInputLength(1, 1, i-1);

			if(nSelAlg == OPT_EXIT)
				return OPT_EXIT;

			if(nSelAlg == OPT_RETURN)
				return nMyPos;

			step++;

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("哈希算法运算测试:\n");
			printf("-------------\n");
			printf("\n");
			printf("请选择输入数据的长度，程序支持的数据长度范围为1-16K。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据长度(默认[1024])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(1024, 1, 16384);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("哈希算法运算测试:\n");
			printf("-------------\n");
			printf("\n");
			printf("算法标识：0x%08x\n", puiAlg[nSelAlg]);
			printf("数据长度：%d\n", nInlen);

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, pIndata);
			if(rv == SDR_OK)
			{
				rv = SDF_HashInit(hSessionHandle, puiAlg[nSelAlg], NULL, NULL, 0);
				if(rv == SDR_OK)
				{
					rv = SDF_HashUpdate(hSessionHandle, pIndata, nInlen);
					if(rv == SDR_OK)
					{
						rv = SDF_HashFinal(hSessionHandle, pOutdata, &nOutlen);
						if(rv == SDR_OK)
						{
							PrintData("运算结果", pOutdata, nOutlen, 16);
						}
						else
						{
							printf("运算结果：SDF_HashFinal()错误，[0x%08x]\n", rv);
						}
					}
					else
					{
						printf("运算结果：SDF_HashUpdate()错误，[0x%08x]\n", rv);
					}
				}
				else
				{
					printf("运算结果：SDF_HashInit()错误，[0x%08x]\n", rv);
				}
			}
			else
			{
				printf("运算结果：产生随机加密数据错误，[0x%08x]\n", rv);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

int HashCorrectnessTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	unsigned int rv;
	int num = 1;

	DEVICEINFO stDeviceInfo;

	memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));

	rv = SDF_GetDeviceInfo(hSessionHandle, &stDeviceInfo);
	if(rv != SDR_OK)
	{
		printf("\n获取设备信息错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	printf("\n");
	printf("\n");
	printf("\n");
	printf("\n");
	printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
	printf("\n");
	printf("杂凑算法正确性测试:\n");
	printf("---------------------\n");
	printf("\n");
	printf("\n");

	if(stDeviceInfo.HashAlgAbility & SGD_SM3)
	{
		unsigned char bHashData[64] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								   0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

		unsigned char bHashStdResult[32] = {0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
										0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};
		unsigned char bHashResult[256];
		unsigned int uiHashResultLen;

		printf("   %02d|   SM3运算   | ", num++);

		rv = SDF_HashInit(hSessionHandle, SGD_SM3, NULL, NULL, 0);
		if(rv != SDR_OK)
		{
			printf("SDF_HashInit函数错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		rv = SDF_HashUpdate(hSessionHandle, bHashData, 64);
		if(rv != SDR_OK)
		{
			printf("SDF_HashUpdate函数错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		memset(bHashResult, 0x0, sizeof(bHashResult));
		uiHashResultLen = sizeof(bHashResult);

		rv = SDF_HashFinal(hSessionHandle, bHashResult, &uiHashResultLen);
		if(rv != SDR_OK)
		{
			printf("SDF_HashFinal函数错误，错误码[0x%08x]\n", rv);
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}

		//哈希值与标准哈希值比对
		if((uiHashResultLen != 32) || (memcmp(bHashStdResult, bHashResult, 32) != 0))
		{
			printf("杂凑值与标准数据杂凑值比较失败\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
		else
		{
			printf("标准数据杂凑运算验证成功。\n");
		}
	}

	printf("\n\n按任意键继续...");
	GETCH();

	return nMyPos;
}

int FileFuncTest(int nMyPos, int nDefaultSelect)
{
	int nSel, rv;
	SGD_HANDLE hSessionHandle;

	if((nDefaultSelect < 1) || (nDefaultSelect > 4)) 
		nSel = 1;
	else
		nSel = nDefaultSelect;

	//创建会话句柄
	rv = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(rv != SDR_OK)
	{
		printf("打开会话句柄错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键继续...");
		GETCH();

		return nMyPos;
	}

	while(1)
	{
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
		printf("\n");
		printf("用户文件操作函数测试:\n");
		printf("---------------------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|创建用户文件测试\n");
	else
		printf("   1|创建用户文件测试\n");
		printf("    |    根据指定的文件名和大小，创建用户文件。\n");
		printf("\n");
	if(nSel == 2)
		printf(" ->2|写文件测试\n");
	else
		printf("   2|写文件测试\n");
		printf("    |    指定文件名，偏移量，将数据写入用户文件。\n");
		printf("\n");
	if(nSel == 3)
		printf(" ->3|读文件测试\n");
	else
		printf("   3|读文件测试\n");
		printf("    |    指定文件名，偏移量，和数据长度读取用户文件。\n");
		printf("\n");
	if(nSel == 4)
		printf(" ->4|删除用户文件测试\n");
	else
		printf("   4|删除用户文件测试\n");
		printf("    |    根据指定的文件名删除用户文件。\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("选择测试项目 或 [退出(Q)] [返回(R)] [下一步(N)]>");
		nSel = GetSelect(nSel, 4);

		switch(nSel)
		{
		case 1:
			nSel = CreateFileTest(1, hSessionHandle);
			break;
		case 2:
			nSel = WriteFileTest(2, hSessionHandle);
			break;
		case 3:
			nSel = ReadFileTest(3, hSessionHandle);
			break;
		case 4:
			nSel = DeleteFileTest(4, hSessionHandle);
			break;
		default:
			break;
		}

		if(nSel == OPT_EXIT)
		{
			SDF_CloseSession(hSessionHandle);

			return OPT_EXIT;
		}

		if(nSel == OPT_RETURN)
		{
			SDF_CloseSession(hSessionHandle);

			return nMyPos;
		}
	}

	return nMyPos;
}

int CreateFileTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	char filename[256];
	int nInlen;
	int step = 0;
	unsigned int rv;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("创建用户文件测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请输入文件名，长度不超过100个字符。\n");
			printf("\n");
			printf("\n");
			printf("\n输入文件名，或 [退出(Q)] [返回(R)]>");
			nInlen = GetString(&filename[0], sizeof(filename));

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if((strlen(filename) < 1) || (strlen(filename) > 100))
			{
				printf("\n无效的文件名，请重新输入");
			}
			else
			{
				step++;
			}

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("创建用户文件测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("请输入文件的最大长度，程序支持的文件长度范围为1-64K，以后的文件读写操作必须在该范围内进行。\n");
			printf("\n");
			printf("\n");
			printf("\n输入文件大小(默认[32])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(32, 1, 65536);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
			{
				step--;

				break;
			}

			//文件大小参数检查
			if((nInlen < 1) || (nInlen > 65536))
			{
				printf("\n文件大小输入参数无效，请重新输入");

				break;
			}
			
			step++;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("创建用户文件测试:\n");
			printf("-----------------\n");
			printf("\n");
			printf("文件名称：%s\n", filename);
			printf("文件大小：%d\n", nInlen);

			rv = SDF_CreateFile(hSessionHandle, filename, (unsigned int)strlen(filename), nInlen);
			if(rv != SDR_OK)
			{
				printf("执行结果：创建文件错误，[0x%08x]\n", rv);
			}
			else
			{
				printf("执行结果：创建文件成功\n");
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}

int WriteFileTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	char filename[256];
	int nInlen, nOffset;
	unsigned char inData[65536];
	int step = 0;
	unsigned int rv;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("写文件测试:\n");
			printf("-----------\n");
			printf("\n");
			printf("请输入文件名，长度不超过100个字符。\n");
			printf("\n");
			printf("\n");
			printf("\n输入文件名，或 [退出(Q)] [返回(R)]>");
			nInlen = GetString(&filename[0], sizeof(filename));

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if((strlen(filename) < 1) || (strlen(filename) > 100))
			{
				printf("\n无效的文件名，请重新输入");
			}
			else
			{
				step++;
			}

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("写文件测试:\n");
			printf("-----------\n");
			printf("\n");
			printf("请输入写文件的起始位置。\n");
			printf("\n");
			printf("\n");
			printf("\n输入起始位置(默认[0])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nOffset = GetInputLength(0, 0, 65536);

			if(nOffset == OPT_EXIT)
				return OPT_EXIT;

			if(nOffset == OPT_RETURN)
				return nMyPos;

			if(nOffset == OPT_PREVIOUS)
				step--;
			else
				step++;

			if(nOffset == 65536)
				nOffset = 0;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("写文件测试:\n");
			printf("-----------\n");
			printf("\n");
			printf("向文件中写入指定长度的随机数据。\n");
			printf("\n");
			printf("\n");
			printf("\n输入数据大小(默认[32])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(32, 1, 65536);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("写文件测试:\n");
			printf("-----------\n");
			printf("\n");

			rv = SDF_GenerateRandom(hSessionHandle, nInlen, inData);
			if(rv != SDR_OK)
			{
				printf("产生随机数据错误，[0x%08x]\n", rv);
				printf("\n");
				printf("\n按任意键继续...");
				GETCH();

				return nMyPos;	
			}

			printf("文件名称：%s\n", filename);
			printf("起始位置：%d\n", nOffset);
			printf("数据大小：%d\n", nInlen);

			rv = SDF_WriteFile(hSessionHandle, filename, (unsigned int)strlen(filename), nOffset, nInlen, inData);
			if(rv != SDR_OK)
			{
				printf("执行结果：写文件错误，[0x%08x]\n", rv);
			}
			else
			{
				printf("执行结果：写文件成功\n");

				PrintData("写入数据", inData, nInlen, 16);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;	
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;	
		}
	}

	return nMyPos;
}

int ReadFileTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	char filename[256];
	int nInlen, nOffset;
	unsigned char inData[65536];
	int step = 0;
	unsigned int rv;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("读文件测试:\n");
			printf("-----------\n");
			printf("\n");
			printf("请输入文件名，长度不超过100个字符。\n");
			printf("\n");
			printf("\n");
			printf("\n输入文件名，或 [退出(Q)] [返回(R)]>");
			nInlen = GetString(&filename[0], sizeof(filename));

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if((strlen(filename) < 1) || (strlen(filename) > 100))
			{
				printf("\n无效的文件名，请重新输入");

			}
			else
			{
				step++;
			}

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("读文件测试:\n");
			printf("-----------\n");
			printf("\n");
			printf("请输入读文件的起始位置。\n");
			printf("\n");
			printf("\n");
			printf("\n输入起始位置(默认[0])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nOffset = GetInputLength(0, 0, 65536);

			if(nOffset == OPT_EXIT)
				return OPT_EXIT;

			if(nOffset == OPT_RETURN)
				return nMyPos;

			if(nOffset == OPT_PREVIOUS)
				step--;
			else
				step++;

			if(nOffset == 65536)
				nOffset = 0;

			break;
		case 2:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("读文件测试:\n");
			printf("-----------\n");
			printf("\n");
			printf("从文件中读取指定长度的随机数据。\n");
			printf("\n");
			printf("\n");
			printf("\n输入大小(默认[32])，或 [退出(Q)] [返回(R)] [上一步(P)] [下一步(N)]>");
			nInlen = GetInputLength(32, 1, 65536);

			if(nInlen == OPT_EXIT)
				return OPT_EXIT;

			if(nInlen == OPT_RETURN)
				return nMyPos;

			if(nInlen == OPT_PREVIOUS)
				step--;
			else
				step++;

			break;
		case 3:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("读文件测试:\n");
			printf("-----------\n");
			printf("\n");

			printf("文件名称：%s\n", filename);
			printf("起始位置：%d\n", nOffset);
			printf("数据大小：%d\n", nInlen);

			rv = SDF_ReadFile(hSessionHandle, filename, (unsigned int)strlen(filename), nOffset, &nInlen, inData);
			if(rv != SDR_OK)
			{
				printf("执行结果：读文件错误，[0x%08x]\n", rv);
			}
			else
			{
				printf("执行结果：读文件成功\n");

				PrintData("读取数据", inData, nInlen, 16);
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;	
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;	
		}
	}

	return nMyPos;
}

int DeleteFileTest(int nMyPos, SGD_HANDLE hSessionHandle)
{
	char filename[256];
	int nSel;
	int step = 0;
	unsigned int rv;

	while(1)
	{
		switch(step)
		{
		case 0:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("删除文件测试:\n");
			printf("-------------\n");
			printf("\n");
			printf("请输入文件名，长度不超过100个字符。\n");
			printf("\n");
			printf("\n");
			printf("\n输入文件名，或 [退出(Q)] [返回(R)]>");
			nSel = GetString(&filename[0], sizeof(filename));

			if(nSel == OPT_EXIT)
				return OPT_EXIT;

			if(nSel == OPT_RETURN)
				return nMyPos;

			if((strlen(filename) < 1) || (strlen(filename) > 100))
			{
				printf("\n无效的文件名，请重新输入\n");
			}
			else
			{
				step++;
			}

			break;
		case 1:
			printf("\n");
			printf("\n");
			printf("\n");
			printf("\n");
			printf("<-------------------三未信安密码卡测试程序 [%s]-------------------->\n", TESTSDS_VERSION);
			printf("\n");
			printf("删除文件测试:\n");
			printf("-------------\n");
			printf("\n");

			rv = SDF_DeleteFile(hSessionHandle, filename, (unsigned int)strlen(filename));
			if(rv != SDR_OK)
			{
				printf("执行结果：删除文件错误，错误码[%08x]\n", rv);
			}
			else
			{
				printf("执行结果：删除文件成功\n");
			}

			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		default:
			printf("\n");
			printf("\n按任意键继续...");
			GETCH();

			return nMyPos;
		}
	}

	return nMyPos;
}