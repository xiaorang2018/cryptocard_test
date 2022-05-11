#include "TestSDS.h"

SGD_HANDLE hDeviceHandle; /*全局设备句柄*/
unsigned int g_nTestRepeat;

int main(int argc, char *argv[])
{
	int rv;
	int nSel = 1;

	//连接设备
	rv = SDF_OpenDevice(&hDeviceHandle);
	if(rv != SDR_OK)
	{
		printf("打开设备错误，错误码[0x%08x]\n", rv);
		printf("\n按任意键退出...");
		GETCH();

		return rv;
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
		printf("欢迎使用:\n");
		printf("---------\n");
		printf("\n");
		printf("请选择要测试的内容。\n");
		printf("\n");

	if(nSel == 1)
		printf(" ->1|功能测试模式\n");
	else
		printf("   1|功能测试模式\n");
		printf("    |    测试密码设备API提供的各接口函数是否能够正确执行。\n");
		printf("\n");
		printf("\n");
		printf("\n");
		printf("选择测试模式 或 [退出(Q)] [下一步(N)]>");
		nSel = GetSelect(nSel, 1);

		switch(nSel)
		{
		case 1:
			rv = FunctionTest(1, 1);
			break;
		default:
			break;
		}

		if((nSel == OPT_EXIT) || (rv == OPT_EXIT))
		{
			SDF_CloseDevice(hDeviceHandle);

			return OPT_EXIT;
		}
	}

	return OPT_EXIT;
}