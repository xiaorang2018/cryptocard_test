#include "randomTest.h"
//#include "data.h"
#include <stdio.h>
#include <sys/io.h>
#include <unistd.h>
#include <math.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>
#include <stdlib.h>



//#define RAND_OPENSSL      //openssl产生的随机数
//#define  RAND_TRUE          //真随机数
//#define  RAND_DEV           //dev/random产生


#define DRNG_NO_SUPPORT	0x0		/* A convenience symbol */
#define DRNG_HAS_RDRAND	0x1
#define DRNG_HAS_RDSEED	0x2
#define RDRAND_RETRIES 10

#ifdef RAND_OPENSSL
#include "openssl/rand.h"
#include "openssl/bio.h"
#include <time.h>
#endif

//#define  RandomSuccess    1
#define  RandomFault      0
#define  NormalFlag       1
#define  CycleFlag        0

int OldRandomFlag = 0;
int NewRandomFlag = 0;
int Per;


static int speaker(unsigned   int   freq, unsigned   int   delay)
{
	static   int   flag = 0, bit;
	if (flag == 0)
	{
		flag = 1;
		iopl(3);
	}
	outb(0xb6, 0x43);
	outb((freq & 0xff), 0x42);
	outb((freq >> 8), 0x42);
	bit = inb(0x61);
	outb(3 | bit, 0x61);
	usleep(10000 * delay);
	outb(0xfc | bit, 0x61);

	return 0;
}

static void play(unsigned   int*   freq, unsigned   int*   time)
{
	int   i;
	for (i = 0; freq[i] != 0; i++)
	{
		speaker(freq[i], time[i]);
	}
}

//如果蜂鸣器在鸣叫时程序被ctrl+c或者其他情况意外终止,蜂鸣器就会一直不停的叫
//下面这个函数让蜂鸣器不发声
static void Stop()
{
	static    int    flag = 0;
	if (flag == 0)
	{
		flag = 1;
		iopl(3);
	}
	outb(0xfc, 0x61);
	return;
}

void voice(int type)
{
	int   i;
	unsigned   int   freq[]={   330   ,   392   ,   330   ,   294   ,   330   ,   392   ,
		330   ,   394   ,   330   ,   330   ,   392   ,   330   ,
		294   ,   262   ,   294   ,   330   ,   392   ,   294   ,
		262   ,   262   ,   220   ,   196   ,   196   ,   220   ,
		262   ,   294   ,   330   ,   262   ,   0   }   ;

	unsigned   int   time[]={   50   ,   50   ,   50   ,   25   ,   25   ,   50   ,
		25   ,   25   ,   100,   50   ,   50   ,   25   ,
		25   ,   50   ,   50   ,   25   ,   25   ,   100,
		50   ,   25   ,   25   ,   50   ,   25   ,   25   ,
		50   ,   25   ,   25   ,   100   };

	unsigned   int   freq2[]={
		196,262,262,262,330,294,262,294,330,294,262,
		330,394,440,440,394,330,330,262,294,262,294,
		330,294,262,230,230,196,262,440,394,330,330,
		262,294,262,294,440,394,330,330,394,440,523,
		394,330,330,262,294,262,294,330,294,262,230,
		230,196,262,440,394,330,330,262,294,262,294,
		440,394,330,330,394,440,523,394,330,330,262,
		294,262,294,330,294,262,230,230,196,262,0
	};

	unsigned   int   time2[]={
		25,38,12,25,25,38,12,25,12,12,56,25,25,50,25,
		38,12,12,12,38,12,25,12,12,38,12,25,25,100,25,
		38,12,12,12,38,12,25,25,38,12,25,25,100,25,38,
		12,12,12,38,12,25,12,12,38,12,25,25,100,25,38,
		12,12,12,38,12,25,25,38,12,25,25,100,25,38,12,
		12,12,38,12,25,12,12,38,12,25,25,100
	};
	unsigned   int   freq_alert[]={
		2000,   2400,   0
	};
	unsigned   int   time_alert[]={
		50,   60
	};

	unsigned   int   a[]={
		1000,   3000,   0
	};
	unsigned   int   b[]={
		50,   60
	};
	unsigned   int   c[]={
		1000,   1000,   0
	};
	unsigned   int   d[]={
		50,   50
	};
	//循环5次播放警告音
	for(i = 0; i<type; i++)
	{
		//play(freq_alert,   time_alert);
	//	if(type==1)
			play(a,b);
	//	else
	//		play(c,d);
	}
	//播放歌曲1
//	play(freq,   time);
	//播放歌曲2
//	play(freq2,   time2);

	//下面这句用来关闭蜂鸣器,不然老叫，吵死了
	speaker( 0,   0 );
}


int sdf_genrandom(void *hSession, int byteT, char *ptr);
double CaleValue(int group);
int  DMSRT_FrequancyDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_BlockFrequencyDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_RankDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_UniversalDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_DiscreteFourierTransformDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_LinearComplexityDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_ApproximateEntropyDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_SerialDms(char *buf, int Groupbit, int GatherGroup);
int  DMSRT_CumulativeSumsDms(char *buf, int Groupbit, int GatherGroup);
int DMSRT_RunsDms(char *buf, int Groupbit, int GatherGroup);
int DMSRT_LongestRunOfOnesDms(char *buf, int Groupbit, int GatherGroup);
int DMSRT_PokerDms(char *buf, int Groupbit, int GatherGroup);
int DMSRT_BinaryDerivativeDms(char *buf, int Groupbit, int GatherGroup);
int DMSRT_RunsDistributionDms(char *buf, int Groupbit, int GatherGroup);
int DMSRT_autoDetectionDms(char *buf, int Groupbit, int GatherGroup);

int  RT_RandTest(void* hSession,char* buf, int Groupbit, int GatherGroup, int flag)
{
	int ret;
	int value = 0;
	char *buf1;

//	FILE *fp=NULL;


	buf1 = (char*)malloc(Groupbit*GatherGroup/8);
    if(buf1 == NULL)
		return 0;
	memcpy(buf1, buf, Groupbit*GatherGroup/8); 
	ret = DMSRT_FrequancyDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_FrequancyDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{	
			goto Error;
		}
	}


	ret = DMSRT_BlockFrequencyDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_BlockFrequencyDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{	
			goto Error;
		}
	}

	ret = DMSRT_RankDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_RankDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	if (flag != CycleFlag)
	{
		ret = DMSRT_DiscreteFourierTransformDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
			ret = DMSRT_DiscreteFourierTransformDms(buf1, Groupbit, GatherGroup);
			if (!ret)
			{
				goto Error;
			}
		}

		ret = DMSRT_UniversalDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
			ret = DMSRT_UniversalDms(buf1, Groupbit, GatherGroup);
			if (!ret)
			{
				goto Error;
			}
		}

		ret = DMSRT_LinearComplexityDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
			ret = DMSRT_LinearComplexityDms(buf1, Groupbit, GatherGroup);
			if (!ret)
			{
				goto Error;
			}
		}
	}

	ret = DMSRT_ApproximateEntropyDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_ApproximateEntropyDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_SerialDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_SerialDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_CumulativeSumsDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_CumulativeSumsDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_RunsDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_RunsDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_LongestRunOfOnesDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_LongestRunOfOnesDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_PokerDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_PokerDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_BinaryDerivativeDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_BinaryDerivativeDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_RunsDistributionDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_RunsDistributionDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	ret = DMSRT_autoDetectionDms(buf1, Groupbit, GatherGroup);
	if (!ret)
	{
		sdf_genrandom(hSession, (Groupbit*GatherGroup / 8), buf1);
		ret = DMSRT_autoDetectionDms(buf1, Groupbit, GatherGroup);
		if (!ret)
		{
			goto Error;
		}
	}

	free(buf1);
	return 1;

Error:
	free(buf1);
	return 0;
}



#if !defined(RAND_TRUE) && !defined(RAND_OPENSSL) && !defined(RAND_DEV)

int sdf_genrandom(void *hSession, int byteT, char *ptr)
{
	int posx;
	int posy;
	int i=0;
	posx = (byteT / 2000);
	posy = (byteT % 2000);
	for (i = 0; i < posx; i++)
	{
		SDF_GenerateRandom(hSession, 2000, ptr);
		ptr += 2000;
	}
	if (posy)
		SDF_GenerateRandom(hSession, posy, ptr);

	return 1;
}

#endif



#ifdef RAND_TRUE
void GenerateRandom(void * hSessionHandle,unsigned int uiLength,unsigned char *pucRandom)
{
	rdrand_get_bytes(uiLength,pucRandom);
}

int sdf_genrandom(void *hSession, int byteT, char *ptr)
{
	unsigned int drng_features;
	uint64_t rand64;
	uint16_t rand16;

	drng_features=get_drng_support();
	if(drng_features ==DRNG_NO_SUPPORT){
		return 0;
	}

	if ( ! rdrand64_step(&rand64) ) {
			fprintf(stderr, "rdrand64_step: random number not available\n");
			return 0;
		} else {
			printf("rand64 = %llu\n", (unsigned long long) rand64);
		}

	if ( ! rdrand64_retry(RDRAND_RETRIES, &rand64) ) {
		fprintf(stderr, "rdrand64_retry: random number not available\n");
		return 0;
	} else {
		printf("rand64 = %llu\n", (unsigned long long) rand64);
	}


	int posx;
	int posy;
	int i=0, j = 0;
	posx = (byteT / 2000);
	posy = (byteT % 2000);
	for (i = 0; i < posx; i++)
	{
		GenerateRandom(hSession, 2000, ptr);
		ptr += 2000;
	}
	if (posy)
		GenerateRandom(hSession, posy, ptr);

	return 1;
}
#endif




#ifdef RAND_OPENSSL
int sdf_genrandom(void *hSession, int byteT, char *ptr)
{
	int posx;
	int posy;
	int i=0;
	unsigned int seed;

	posx = (byteT / 2000);
	posy = (byteT % 2000);
	for (i = 0; i < posx; i++)
	{
		RAND_pseudo_bytes(ptr, 2000);
		ptr += 2000;
	}
	if (posy)
	{
		RAND_pseudo_bytes(ptr, posy);
	}

	return 1;
}
#endif



#ifdef RAND_DEV
static int get_random_fd(void)
{
	static int fd=-2;

	if(fd==-2)
	{
		fd=open("/dev/random",O_RDONLY|O_NONBLOCK);
		if(fd==-1)
		{
			fd=open("/dev/urandom",O_RDONLY|O_NONBLOCK);
		}
	}

	return fd;
}
int sdf_genrandom(void *hSession, int byteT, char *ptr)
{
	  int i, fd = get_random_fd();
	  int lose_counter = 0;
	  struct timeval tv;
	  static unsigned seed = 0;
	  extern int errno;


	   if(fd>=0)
	   {
		   while(byteT>0)
		   {

			   i=read(fd,ptr,byteT);
			   printf("i=%d\n",i);
			   //if(i<0 &&
	    		//	((errno == EINTR)||(errno == EAGAIN)))
			   byteT -= i;
			   ptr += i;
		      lose_counter = 0;
		   }
	   }

	   for (i = 0; i < byteT; i++)
	   {
	      if (seed == 0)
	      {
	         gettimeofday(&tv, 0);
	         seed = (getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec;
	      }
          *ptr++ = rand_r(&seed) & 0xFF;
       }


	   return 1;
}
#endif



//出厂随机数检测，该接口成功返回1
int FactoryAcceptanceTesting(void *hSession)
{
	int GatherGroup = 50;
	int Groupbit = 1000000;

	int ret;
	char *buf;

	buf = (char*)malloc(Groupbit* GatherGroup/8);
    if(buf == NULL)
	   return 0;
	//生成随机数
	sdf_genrandom(hSession, Groupbit*GatherGroup/8, buf);

	//随机数检测
	ret = RT_RandTest(hSession,buf, Groupbit, GatherGroup, NormalFlag);


	//释放
	free(buf);

	return ret;
}


//上电自检，该接口成功返回1
int PowerOnSelfTesing(void *hSession)
{
	int GatherGroup = 20;
	int Groupbit = 1000000;

	int ret;
	char *buf;

	buf = (char*)malloc(Groupbit* GatherGroup/8);
    if(buf == NULL)
	  return 0;
    //生成随机数
    sdf_genrandom(hSession,(Groupbit*GatherGroup/8), buf);

	//测试
	ret = RT_RandTest(hSession,buf, Groupbit, GatherGroup, NormalFlag);

	//释放
	free(buf);

	return ret;
}


//循环检测，该接口成功返回1
int CycleTesting(void *hSession)
{
	int GatherGroup = 20;
	int Groupbit = 20000;
	int ret;
	char *buf;

	buf = (char*)malloc(Groupbit* GatherGroup/8);
    if(buf == NULL)
	  return 0;
	//生成随机数
	sdf_genrandom(hSession, (Groupbit*GatherGroup/8), buf);

	//测试
	ret = RT_RandTest(hSession,buf, Groupbit, GatherGroup, CycleFlag);

	//释放
	free(buf);

	return ret;
}



int Singledetection(void *hSession)
{
  int ret;
  int m = 0;
  int n = 256;
  int Pokernew;
  int Pokerold;
  int By;
  char * ptr ;


  if (n < 128)
    return 0;
  
  By = (n % 8) ? (n / 8 + 1) : (n / 8);
  ptr = (char*)malloc(By);
  if(ptr == NULL)
	  return 0;
  if (n < 320)
  {
    m = 2;
    SDF_GenerateRandom(hSession, By, ptr);
    ret = RT_PokerDms(ptr, m, n);
    if (ret)
    {
		goto Success;
    }
    else
    {
       SDF_GenerateRandom(hSession, By, ptr);
      ret = RT_PokerDms(ptr, m, n);
      if (ret)
      {
         goto Success;
	  }
      else
      {
		 goto Error;
	  }
    }

  }
  else
  {
    m = 4;
    SDF_GenerateRandom(hSession, By, ptr);
    ret = RT_PokerDms(ptr, m, n);
    if (ret)
    {
		goto Success;
	}
    else
    {
       SDF_GenerateRandom(hSession, By, ptr);
      ret = RT_PokerDms(ptr, m, n);
      if (ret)
      {
		  goto Success;
      }
      else
      {
		  goto Error;
      }
    }

  }

Error:
  free(ptr);
  return 0;

Success:
  free(ptr);
  return 1;

}


double CaleValue(int group)
{
	double n;

	n = 3 * sqrt(0.01 * (1 - 0.01) * group);

	return (group - 0.01 * group -n);
}

int DMSRT_FrequancyDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_FrequancyDms(buf, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	//接口
	Calenum = CaleValue(GatherGroup);
	
	if(SussessNum > Calenum )
	  return 1;
	else
	  return 0;
}


int DMSRT_BlockFrequencyDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_BlockFrequencyDms(buf, 100, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	//接口
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
	  return 1;
	else
	  return 0;
}


int DMSRT_RankDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_RankDms(buf,  Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_DiscreteFourierTransformDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;

	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_DiscreteFourierTransformDms(buf, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_UniversalDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_UniversalDms(buf, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	
	}

	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_LinearComplexityDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_LinearComplexityDms(buf, 500, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_ApproximateEntropyDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_ApproximateEntropyDms(buf, 2, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}

	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_SerialDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_SerialDms(buf, 2, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
		
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_CumulativeSumsDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_CumulativeSumsDms(buf, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}

int DMSRT_RunsDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_RunsDms(buf, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}

int DMSRT_LongestRunOfOnesDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_LongestRunOfOnesDms(buf, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_PokerDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_PokerDms(buf, 4,Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}

int DMSRT_BinaryDerivativeDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_BinaryDerivativeDms(buf , 7, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_RunsDistributionDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_RunsDistributionDms(buf,  Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


int DMSRT_autoDetectionDms(char *buf, int Groupbit, int GatherGroup)
{
	int i;
	int ret;
	double SussessNum = 0.0;
	double Calenum = 0.0;
	for (i = 0; i < GatherGroup; i++)
	{
		ret = RT_autoDetectionDms(buf, 1, Groupbit);
		if (ret)
		{
			SussessNum++;
		}
		buf += (Groupbit / 8);
	}
	
	Calenum = CaleValue(GatherGroup);
	if(SussessNum > Calenum )
		return 1;
	else
		return 0;
}


