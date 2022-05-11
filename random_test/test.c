#include <stdio.h>
#include <stdlib.h>

#include "libPciGUOMI.h"

int main(int argc, char * argv[])
{
	void *  hDeviceHandle;
	void *  hSessionHandle;
	int a,i,j,uiLength,ulRes;
	unsigned char buff[64 * 1024];


	while(1)
	{
		dmsdebug( YELLOW "***********************Device Open/Close*************************\n");
                dmsdebug("1.dmsPCI_OpenDevice\n");
                dmsdebug("2.dmsPCI_CloseDevice\n");
		dmsdebug( YELLOW "**************************Random Test****************************\n");
                dmsdebug("3.FactoryAcceptanceTesting\n");
                dmsdebug("4.CycleTesting\n");
		dmsdebug("5.PowerOnSelfTesing\n");
                dmsdebug("6.Singledetection\n");
                dmsdebug("7.SDF_GenerateRandom\n");
		dmsdebug("***************************End Test*****************************\n" NONE);
		dmsdebug("please input cmd():");
                
		scanf("%x",&a);
		switch(a)
		{
			case 0x01:
                                ulRes = dmsPCI_OpenDevice(&hDeviceHandle, &hSessionHandle);
                                if(ulRes != SDR_OK)
                                {
                                        dmsdebug(UNDERLINE   "dmsPCI_OpenDevice error %x\n" NONE, ulRes);
                                }
                                else
                                        dmsdebug("dmsPCI_OpenDevice ok\n");
                                break;

                        case 0x02:
                                ulRes = dmsPCI_CloseDevice(hDeviceHandle, hSessionHandle);
                                if(ulRes != SDR_OK)
                                {
                                        dmsdebug(UNDERLINE "dmsPCI_CloseDevice error\n" NONE);
                                }
                                else
                                        dmsdebug("dmsPCI_CloseDevice ok\n");
                                break;
			
			case 0x03:
				for(i=0,j=0; i<1000; i++)
				{
					ulRes = FactoryAcceptanceTesting(hSessionHandle);
                                	if(ulRes == SDR_OK)
                                	{
                                        	dmsdebug(UNDERLINE   "FactoryAcceptanceTesting error %x\n" NONE, ulRes);
                                	}
                                	else
					{
                                        	dmsdebug("FactoryAcceptanceTesting ok\n");
						j+=1;
					}
                                }
				dmsdebug("FactoryAcceptanceTesting success time is %d\n", j);
				break;

			case 0x04:
				for(i=0,j=0; i<500; i++)
				{
					ulRes = CycleTesting(hSessionHandle);
                                	if(ulRes == SDR_OK)
                                	{
                                        	dmsdebug(UNDERLINE   "CycleTesting error %x\n" NONE, ulRes);
                                	}
                                	else
					{
                                        	dmsdebug("CycleTesting ok\n");
						j+=1;
					}
                                }
				dmsdebug("CycleTesting success time is %d\n", j);
				break;

			case 0x05:
				for(i=0,j=0; i<1000; i++)
				{
					ulRes = PowerOnSelfTesing(hSessionHandle);
                                	if(ulRes == SDR_OK)
                                	{
                                        	dmsdebug(UNDERLINE   "PowerOnSelfTesing error %x\n" NONE, ulRes);
                                	}
                                	else
					{
                                        	dmsdebug("PowerOnSelfTesing ok\n");
						j+=1;
					}
				}
				dmsdebug("PowerOnSelfTesing success time is %d\n", j);
                                break;

			case 0x06:
				for(i=0,j=0; i<1000; i++)
				{
					ulRes = Singledetection(hSessionHandle);
                                	if(ulRes == SDR_OK)
                                	{
                                        	dmsdebug(UNDERLINE "Singledetection error %x\n" NONE, ulRes);
                                	}
                                	else
					{
                                        	dmsdebug("Singledetection ok\n");
						j+=1;
					}
				}
                                dmsdebug("Singledetection success time is %d\n", j);
				break;
			
			case 0x07:
				dmsdebug("please input rangdomLength(1~1024):\n");
				scanf("%d",&uiLength);
				//char *tmpbuff = malloc(uiLength);
                                ulRes = SDF_GenerateRandom(hSessionHandle, uiLength, buff);
                                if(ulRes != SDR_OK)
                                {
                                        dmsdebug(UNDERLINE "SDF_GenerateRandom error %02x\n" NONE, ulRes);
					return -1;
                                }
                                else
				{
                                        dmsdebug("GenerateRandom success!the random is:\n");
					for(i = 0;i < uiLength;i++)
						dmsdebug("%02x ",buff[i]);
					dmsdebug("\n");
				}
				//free(tmpbuff);
                                break;



		}


	}


}


