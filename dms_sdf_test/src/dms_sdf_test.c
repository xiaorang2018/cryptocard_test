/*
 * @File name: 
 * @Descripttion: 
 * @Version: 
 * @Author: 
 * @Date : 2021-08-25 14:14:26
 * @Others:  // 其它内容的说明
 * @History:  // 修改历史记录列表，每条修改记录应包括修改日期、修改者及修改内容简述
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdint.h>
#include <string.h>
#include "dms_sdf.h"
#include "dms_mgr_sdf.h"
#include "debug.h"
#include "sm3.h"
#include "sm4.h"

#define MAX_SESSION_PCS 200
#define MAX_PTHREAD_T   1024
#define MAX_KEY_PAIR    KEY_POOL_SIZE_MAX
typedef void (*test_signle_pthread)(void *ses,void *p) ;
typedef void (*p_cmd)(void); 
struct test_box{
    char name[256] ;
    p_cmd p_test_cmd ;
};

struct time_ctl{
    struct timeval  g_start ;
    struct timeval  g_end ;
    char start  ;
    char end ; 
    pthread_mutex_t mutex ; 
    volatile int sync ;  //同步开始计时 
};
struct pthread_test_src{
    pthread_t pthread_t;
    int thread_idx ;
    test_signle_pthread task ;
    void *p_data ;
    struct pthread_test_src *head ; 
};
struct sm4_ctl{
    int pthread_pcs  ;    //总共线程的数量,必须定义在最前面
    unsigned int sm4_mode ; 
    unsigned int data_size ;
    unsigned int test_count;
    struct time_ctl time ;
    struct time_ctl dec_time ;
    int status ;
};
struct sm3_ctl{
    int pthread_pcs  ;    //总共线程的数量,必须定义在最前面
    unsigned int data_size ;
    struct time_ctl time ;
    struct time_ctl soft_time ;
    int status ;
};
struct random_ctl{
    int pthread_pcs  ;    //总共线程的数量,必须定义在最前面
    unsigned int data_size ;
    struct time_ctl time ;
    int status ;
};
struct sm2_ctl{
    int pthread_pcs ;   //总共线程的数量,必须定义在最前面
    struct time_ctl sign_time ;
    struct time_ctl verify_time ;
    int pcs ;  //签名验签的次数
    int status ;
};
struct sm2_enc_dec_ctl{
    int pthread_pcs ; //总共线程的数量,必须定义在最前面
    struct time_ctl enc_time ;
    struct time_ctl dec_time ;
    int pcs ;
    int length ;
    int status ;
};
struct ecc_key_pair_ctl{
    int pthread_pcs ; //总共线程的数量,必须定义在最前面
    int pcs;
    int status;
    struct time_ctl time ;
};
struct iki_alg_struct{
    unsigned int region;
    unsigned int id_len;
    unsigned int optimize_flag;
    char id[128];
    char manufacturer[128];
    char takeffect_date[64];
    char loseffect_date[64];
};

struct password{
    unsigned int pin_len;
    char pin[32];
    unsigned int new_pin_len;
    char new_pin[32];
};

struct device_info{
    unsigned int type;
    unsigned int status;
    struct password pin;
};

struct prikey_password{
    unsigned int index;
    struct password pw;
};

struct backup_recovery{
    unsigned int backup_grp;
    unsigned int recovery_grp;
    unsigned int device_pin_len;
    unsigned int enc_pin_len;
    unsigned int dec_pin_len;
    unsigned char enc_pin[16];
    unsigned char dec_pin[16];
    unsigned char device_pin[16];
};

struct threshold_ctl_st{
    unsigned int key_index;
    int backup_grp;
    int recovery_grp;
    unsigned int device_pin_len;
    unsigned char device_pin[16];
    unsigned int prikey_pin_len;
    unsigned char prikey_pin[16];
};

struct kek_ctl_st{
    unsigned int bit_len;
    unsigned int index;
};

struct file_ctl_st{
    unsigned int offset;
    unsigned int length;
    unsigned char *buffer;
    unsigned int file_size;
    unsigned char file_name[128];
};

struct iki_caculat_person_key_ctl{
    int pthread_pcs ; //总共线程的数量,必须定义在最前面
    struct time_ctl time ;
    int pcs ;
    int status ;
    unsigned int index;
    int pid_len;
    char *pid;
};

struct skid_sign_ctl{
    int pthread_pcs ; //总共线程的数量,必须定义在最前面
    struct time_ctl time ;
    int pcs ;
    int status ;
    unsigned int optimize_flag;
    unsigned int data_len;
    int pid_len;
    char *pid;
};

struct sess_key_agreement_ctl{
    unsigned int key_bit_len;
    unsigned int sponsor_index;
    unsigned char sponsor_id[32];
    unsigned int response_index;
    unsigned char response_id[32];
};

/*全局变量*/
void *handle_dev ;  //设备句柄
int ecc_key_idx = 383 ; //使用ecc密钥对位置

void showHexData(unsigned char *dataPtr, unsigned int nSize, char *sTitle)
{
	if (!dataPtr || !sTitle)
	{
		return;
	}
	printf("%s:\n", sTitle);

	for (unsigned int i = 0; i < nSize; ++i)
	{
		printf("0x%02x,", dataPtr[i]);
		if (((i + 1) % 16) == 0) printf("\n");
	}
	printf("\n");

	return;
}

/**
 * @brief:测试前初始化 
 * @param []
 * @return []
 */
static int test_init(){
    int ret = 0 ;
    debug_init();
    ret = SDF_OpenDevice(&handle_dev);
    if(ret !=SDR_OK){
        Debug_err("open device error !\n");
    }
    return ret ;
}
/**
 * @brief: 单个线程测试
 * @param [test_signle_pthread] test_function
 * @param [void] *p
 * @return []
 */
static void signle_pthread_test(test_signle_pthread test_function,void *p){
    void *ses ;
    int ret = 0 ;
    ret = SDF_OpenSession(handle_dev,&ses);
    if(ret != SDR_OK){
        Debug_err("SDF_OpenSession failed return 0x%08x \n",ret);
        return ;
    }
    if(test_function){
        test_function(ses,p);
    }
    ret = SDF_CloseSession(ses);
    if(ret != SDR_OK){
        Debug_err("SDF_CloseSession failed return 0x%08x !\n",ret);
    }
}
/**
 * @brief: 多线程测试的线程task
 * @param [void] *p
 * @return []
 */
static void *mult_pthread_task(void *p){
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    if(pthread_source != NULL){
        signle_pthread_test(pthread_source->task,p);
    }
    return NULL ;      
}
/**
 * @brief:  多线程测试函数
 * @param [test_signle_pthread] test_function
 * @param [void] *p
 * @return []
 */
static void mult_pthread_test(test_signle_pthread test_function,void *p){
    struct pthread_test_src pthread_source[MAX_PTHREAD_T];
    int pthread_pcs = *((int *)p) ;
    memset(pthread_source,0,sizeof(struct pthread_test_src)*MAX_PTHREAD_T);
    for(int i = 0 ; i < pthread_pcs;i++){
        pthread_source[i].thread_idx = i ;
        pthread_source[i].task = test_function ;
        pthread_source[i].p_data = p ;
        pthread_source[i].head = pthread_source ;
        pthread_create(&pthread_source[i].pthread_t,NULL,mult_pthread_task,(void *)&pthread_source[i]);
    }
    for(int i = 0 ; i <pthread_pcs;i++ ){
        pthread_join(pthread_source[i].pthread_t,NULL);
    }  
}
/**
 * @brief:统计时间 
 * @param [time_ctl] *time
 * @return []统计的毫秒数
 */
static double cal_time_ms(  struct timeval  *g_start ,struct timeval  *g_end ){
    double ms = 1000.0*(g_end->tv_sec -g_start->tv_sec) + (g_end->tv_usec -g_start->tv_usec)/1000.0;
    return ms ;
}
/**
 * @brief: 测试会话的打开和关闭
 * @param []
 * @return []
 */
static void test_session(){
    int session_pcs = 0 ;
    int ret = 0 ;
    void *handle_ses[MAX_SESSION_PCS];
    Printf_with_color(BLUE,"输入创建的会话个数(1~100):");
    scanf("%d",&session_pcs);
    getchar();
    if(session_pcs > MAX_SESSION_PCS){
        Debug_err("MAX SESSION IS %d \n",MAX_SESSION_PCS);
        return ;
    }
   // Printf_with_color(RED,"输入的会话个数为 %d \n",session_pcs);
    /*打开会话测试*/
    for(int i = 0 ;i < session_pcs ;i++){
        ret = SDF_OpenSession(handle_dev,&handle_ses[i]);
        if(ret != SDR_OK){
            Debug_err("open index %d session failed 0x%08x !\n",i + 1,ret);
        }
    } 
    /*关闭会话测试*/
    for(int i = 0 ; i < session_pcs;i++){
        ret = SDF_CloseSession(handle_ses[i]);
        if(ret != SDR_OK){
            Debug_err("close index %d session failed 0x%08x !\n",i + 1,ret);
        }
    }  
}
static void while_start_time( struct time_ctl *time,int pthread_pcs){ 
    pthread_mutex_lock(&time->mutex);
    time->sync ++ ;
    pthread_mutex_unlock(&time->mutex);
    while(time->sync < pthread_pcs){
    //    printf("time->sync %d\n",time->sync);
    };
}
static void  get_start_time(struct time_ctl *time){
    /*从第一个开始计时*/
    pthread_mutex_lock(&time->mutex);
    if(time->start){
        gettimeofday(&time->g_start, NULL);
        time->start = 0 ;
    }
    pthread_mutex_unlock(&time->mutex);
}
static void get_end_time(struct time_ctl *time,int pthread_pcs){
    pthread_mutex_lock(&time->mutex);
    time->end++;
    /*最后一个结束就结束计时*/
    if(time->end == pthread_pcs){
        gettimeofday(&time->g_end, NULL);  
    }
    pthread_mutex_unlock(&time->mutex);
}
 /**
  * @brief: 
  * @param [void *] p
  * @return []
  */
 void test_random_signle_task(void *ses,void * p){
     int ret = 0 ;
     struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
     struct random_ctl *random_ctl = (struct random_ctl *)pthread_source->p_data ;
     unsigned char *buffer = malloc(random_ctl->data_size + 16);
     if(buffer == NULL){
        Debug_err("malloc buffer no space !\n");
        return ;
    }
    while_start_time(&random_ctl->time,random_ctl->pthread_pcs);
    get_start_time(&random_ctl->time);
    ret = SDF_GenerateRandom(ses,random_ctl->data_size,buffer);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom error !\n");
        return ;
    }
    get_end_time(&random_ctl->time,random_ctl->pthread_pcs);
    free(buffer);
 } 
/**
 * @brief: 随机数测试
 * @param []
 * @return []
 */
static void test_random(){
    struct random_ctl random_ctl ;
    memset(&random_ctl,0,sizeof(struct random_ctl));
    printf("请输入测试的数据大小(KB):"); 
    scanf("%d",&random_ctl.data_size); 
    getchar();
    random_ctl.data_size *=1024 ;
    if(random_ctl.data_size == 0){
         Debug_err("输入的数据长度不应该等于0\n");  
         return ;    
    }
    printf("请输入创建线程个数:"); 
    scanf("%d",&random_ctl.pthread_pcs); 
    getchar();
    if( random_ctl.pthread_pcs > MAX_PTHREAD_T){
         Debug_err("输入的线程数应该在(1~%d)\n",MAX_PTHREAD_T);  
         return ;  
    }
    random_ctl.time.start = 1 ;
    pthread_mutex_init(&random_ctl.time.mutex,NULL);
    mult_pthread_test(test_random_signle_task,(void *)&random_ctl);
    double performace = ((long)random_ctl.pthread_pcs*random_ctl.data_size*8*1000)/cal_time_ms(&random_ctl.time.g_start,&random_ctl.time.g_end) ;
    Printf_with_color(BLUE,"随机数性能为%lfMbps\n",performace/(1024*1024)); 
}
/**
 * @brief: 
 * @param [void] *p
 * @return []
 */
static void __test_ecc_pki(void *ses,void *p){
    int index = 0 ;
    int ret = 0 ;
    unsigned int key_flag = 0;
    printf("请输入生成的位置(0-%d):", MAX_KEY_PAIR - 1); 
    scanf("%d",&index); 
    getchar();
    if(index > MAX_KEY_PAIR - 1 ){
        Debug_err("MAX ecc index  IS %d \n",MAX_KEY_PAIR -1);
        return ;   
    }
    printf("请选择在该位置想要生成的密钥对类型：\n");
    printf("1. 加密密钥对   2. 签名密钥对\n");
    printf("3. 加密密钥对与签名密钥对\n");
    scanf("%d", &key_flag);
    getchar();
    if((1 != key_flag) && (2 != key_flag) && (3 != key_flag)){
        Debug_err("请选择正确的密钥对类型\n");
        return ;
    }
    #if 0
    for(int i = 0; i < MAX_KEY_PAIR; i++){
        ret = SDF_dmsGenerate_PKIKeyPair(ses,i,3);
        if(ret != SDR_OK){
            Debug_err("SDF_dmsGenerate_PKIKeyPair failed return 0x%08x\n",ret);
        } 
    }
    #else
    ret = SDF_dmsGenerate_PKIKeyPair(ses,index,key_flag);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsGenerate_PKIKeyPair failed return 0x%08x\n",ret);
    }     
    #endif
}

/**
 * @brief: 测试生成密钥对
 * @param []
 * @return []
 */
static void test_set_ecc_key_pair(void){
    signle_pthread_test(__test_ecc_pki,NULL);    
}
static void printf_key_poolstate(KeyPoolStateInfo *pKeyPoolStInfo ){
    int next_line = 0 ;
    Printf_with_color(BLUE,"密钥池的大小为:%d\n",pKeyPoolStInfo->uiKeyPoolSize); 
    Printf_with_color(BLUE,"存在秘密值和保护密钥的是:\n");
    for(int i = 0 ; i < pKeyPoolStInfo->uiKeyPoolSize ;i++){
        if(pKeyPoolStInfo->ucKeyPoolStates[i] == 1){
            Printf_with_color(BLUE,"%d ",i); 
            next_line ++ ; 
            if(next_line %16 == 0 ){
                printf("\n");   
            }
        }
    }
    if(next_line %16){
        printf("\n"); 
    }
    next_line = 0 ;
    Printf_with_color(BLUE,"存在用iki算法生成的:\n");
    for(int i = 0 ; i < pKeyPoolStInfo->uiKeyPoolSize ;i++){
        if(pKeyPoolStInfo->ucKeyPoolStates[i] == 2){
            Printf_with_color(BLUE,"%d ",i); 
            next_line ++ ; 
            if(next_line %16 == 0 ){
                printf("\n");   
            }
        }
    }
    if(next_line %16){
        printf("\n"); 
    }
    next_line = 0 ;
    Printf_with_color(BLUE,"存在本地生成的加密密钥对:\n");
    for(int i = 0 ; i < pKeyPoolStInfo->uiKeyPoolSize ;i++){
        if(pKeyPoolStInfo->ucKeyPoolStates[i] == 3){
            Printf_with_color(BLUE,"%d ",i); 
            next_line ++ ; 
            if(next_line %16 == 0 ){
                printf("\n");   
            }
        }
    }
    if(next_line %16){
        printf("\n"); 
    }    
    next_line = 0 ;
    Printf_with_color(BLUE,"存在本地生成的签名密钥对:\n");
    for(int i = 0 ; i < pKeyPoolStInfo->uiKeyPoolSize ;i++){
        if(pKeyPoolStInfo->ucKeyPoolStates[i] == 4){
            Printf_with_color(BLUE,"%d ",i); 
            next_line ++ ; 
            if(next_line %16 == 0 ){
                printf("\n");   
            }
        }
    }
    if(next_line %16){
        printf("\n"); 
    }    
    next_line = 0 ;
    Printf_with_color(BLUE,"存在本地生成的加密以及签名密钥对:\n");
    for(int i = 0 ; i < pKeyPoolStInfo->uiKeyPoolSize ;i++){
        if(pKeyPoolStInfo->ucKeyPoolStates[i] == 5){
            Printf_with_color(BLUE,"%d ",i); 
            next_line ++ ; 
            if(next_line %16 == 0 ){
                printf("\n");   
            }
        }
    }
    printf("\n"); 
}
static void __test_get_key_pairs_state(void *ses,void *p){
    KeyPoolStateInfo KeyPoolStInfo ;
    memset(&KeyPoolStInfo,0,sizeof(KeyPoolStateInfo));
    int ret = SDF_dmsPCI_GetKeyPoolState(ses,&KeyPoolStInfo);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_GetKeyPoolState failed return 0x%08x\n",ret);
    }
    printf_key_poolstate(&KeyPoolStInfo);
}
/**
 * @brief: 获取密钥池状态
 * @param []
 * @return []
 */
static void test_get_key_pairs_state(void){
    signle_pthread_test(__test_get_key_pairs_state,NULL);
}

static void __test_sm4_ecb(void *ses,void *p ){
    int ret =  0 ;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct sm4_ctl *sm4_ctl = pthread_source->p_data ;
    void *p_keyhadle = 0 ;
    unsigned char ses_key[16] = {0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C};
    ECCrefPublicKey PublicKey ;
    unsigned char buffer[256] ;
    unsigned char *random_buffer ;
    ECCCipher *pucEncData  ;
    memset(buffer,0,256);
    memset(&PublicKey,0,sizeof(ECCrefPublicKey));
    random_buffer = (unsigned char *)malloc(3*sm4_ctl->data_size + 16);
    if(random_buffer == NULL){
        Debug_err("没有内存空间分配 \n");
        sm4_ctl->status = 1 ;  
        return ;
    }
    /*导出公钥*/
    ret = SDF_ExportEncPublicKey_ECC(ses,ecc_key_idx,&PublicKey);
    if(ret != SDR_OK){
        Debug_err("SDF_ExportEncPublicKey_ECC failed return 0x%08x \n",ret);
        goto end ;  
    } 
    pucEncData = (ECCCipher *)buffer ;
    /*外部公钥加密数据*/
    ret = SDF_ExternalEncrypt_ECC(ses,SGD_SM2_3,&PublicKey,ses_key,16,pucEncData);
    if(ret !=SDR_OK){
        Debug_err("SDF_ExternalEncrypt_ECC failed return 0x%08x \n",ret);
        goto end ;    
    }
    /*获取私钥使用权限*/
    ret = SDF_GetPrivateKeyAccessRight(ses,ecc_key_idx,(unsigned char *)"dms123456",strlen("dms123456"));
    if(ret != SDR_OK ){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x \n",ret);
        goto end ;     
    }
    /*内部私钥解密*/
    ret = SDF_ImportKeyWithISK_ECC(ses,ecc_key_idx,pucEncData,&p_keyhadle);
     if(ret !=SDR_OK){
        Debug_err("SDF_ImportKeyWithISK_ECC failed return 0x%08x \n",ret);
       goto end ;     
    }
    for(unsigned int  i = 0 ; i < (sm4_ctl->data_size/sizeof(unsigned int)) ;i++){
        *((unsigned int*)random_buffer + i) = i;
    }    
    unsigned int length = sm4_ctl->data_size ;
    unsigned char iv[16] = {0};
    /*等到线程都到达此位置*/
    while_start_time(&sm4_ctl->time,sm4_ctl->pthread_pcs);
    get_start_time(&sm4_ctl->time);
    /*数据加密*/
#if 1
    for(unsigned int i = 0; i < sm4_ctl->test_count; i++){
        ret= SDF_Encrypt(ses,p_keyhadle,sm4_ctl->sm4_mode,iv,random_buffer,sm4_ctl->data_size,random_buffer + sm4_ctl->data_size,&length);
        if(ret != SDR_OK){
            Debug_err("SDF_Encrypt failed return 0x%08x \n",ret);
            goto end ;      
        }
    }
#else
    ret= SDF_Encrypt(ses,p_keyhadle,sm4_ctl->sm4_mode,iv,random_buffer,sm4_ctl->data_size,random_buffer + sm4_ctl->data_size,&length);
    if(ret != SDR_OK){
        Debug_err("SDF_Encrypt failed return 0x%08x \n",ret);
        goto end ;      
    }
#endif
    get_end_time(&sm4_ctl->time,sm4_ctl->pthread_pcs);
    while_start_time(&sm4_ctl->dec_time,sm4_ctl->pthread_pcs);
    get_start_time(&sm4_ctl->dec_time);
    /*数据解密*/
    for(unsigned int i = 0; i < sm4_ctl->test_count; i++){
        ret = SDF_Decrypt(ses,p_keyhadle,sm4_ctl->sm4_mode,iv,random_buffer + sm4_ctl->data_size,sm4_ctl->data_size,random_buffer + sm4_ctl->data_size*2,&length);
        if(ret != SDR_OK){
            Debug_err("SDF_Encrypt failed return 0x%08x \n",ret);
            goto end ;      
        }
    }

    get_end_time(&sm4_ctl->dec_time,sm4_ctl->pthread_pcs);

    if(memcmp(random_buffer,random_buffer+sm4_ctl->data_size*2,sm4_ctl->data_size)!=0){
        Debug_err("memcmp failed  \n");
        goto end ;    
    }
    free(random_buffer);
    return ;
 end : 
    sm4_ctl->status = 1 ;  
    free(random_buffer);
}
/**
 * @brief: 
 * @param []
 * @return []
 */
static void test_sm4_ecb(struct sm4_ctl *sm4_ctl){
    printf("请输入测试的线程个数:");
    scanf("%d",&sm4_ctl->pthread_pcs);
    getchar();
    sm4_ctl->time.start = 1 ;
    sm4_ctl->time.end = 0 ;
    sm4_ctl->dec_time.start = 1 ;
    sm4_ctl->dec_time.end = 0  ;
    pthread_mutex_init(&sm4_ctl->time.mutex,NULL);
    pthread_mutex_init(&sm4_ctl->dec_time.mutex,NULL);
    mult_pthread_test(__test_sm4_ecb,sm4_ctl);
    if(sm4_ctl->status ){
        Debug_err("函数返回错误\n");     
        return ;    
    }
    double performace = ((long)sm4_ctl->pthread_pcs*sm4_ctl->data_size*8*1000*sm4_ctl->test_count)/((double)1024*1024*cal_time_ms(&sm4_ctl->time.g_start,&sm4_ctl->time.g_end))  ;
   // Printf_with_color(BLUE,"pthread %d,size %d,use time %ld(ms)\n",sm4_ctl->pthread_pcs,sm4_ctl->data_size,cal_time_ms(&sm4_ctl->time.g_start,&sm4_ctl->time.g_end));
    double dec_performace = ((long)sm4_ctl->pthread_pcs*sm4_ctl->data_size*8*1000*sm4_ctl->test_count)/((double)1024*1024*cal_time_ms(&sm4_ctl->dec_time.g_start,&sm4_ctl->dec_time.g_end))  ;
    Printf_with_color(BLUE,"sm4 ecb加密性能%lf(Mbps),sm4 ecb解密性能%lf(Mbps)\n",performace,dec_performace); 
}
#define roundup(x,mod)  (((x + mod -1 )/mod) *mod)
static void __test_sm4_older(void *ses,void *p ){
    int ret =  0 ; 
    struct sm4_ctl *sm4_ctl = p ;
    void *p_keyhadle = 0 ;
    unsigned char ses_key[16] ;
    ECCrefPublicKey PublicKey ;
    unsigned char buffer[256] ;
    unsigned char *random_buffer ;
    ECCCipher *pucEncData  ;
    memset(buffer,0,256);
    memset(&PublicKey,0,sizeof(ECCrefPublicKey));
    memset(ses_key,0,16);
    random_buffer = (unsigned char *)malloc(3*roundup(sm4_ctl->data_size,16) + 16);
    if(random_buffer == NULL){
        Debug_err("没有内存空间分配 \n");
        sm4_ctl->status = 1 ;
        return ;
    }
#if 0 // 按照协议，标准加密接口仅支持16字节对齐的数据
    /*多用几个字节测试ctr模式*/
    if(sm4_ctl->sm4_mode == SGD_SM4_CTR ){
        sm4_ctl->data_size  += 7 ;
    }
#endif
    unsigned char *plain = random_buffer ; 
    unsigned char *cipher = random_buffer +  roundup(sm4_ctl->data_size,16) ;
    unsigned char *plain_dec = random_buffer +  2*roundup(sm4_ctl->data_size,16) ;
    ret = SDF_GenerateRandom(ses,16,ses_key);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        goto end ;     
    }
    /*导出公钥*/
    ret = SDF_ExportEncPublicKey_ECC(ses,ecc_key_idx,&PublicKey);
    if(ret != SDR_OK){
        Debug_err("SDF_ExportEncPublicKey_ECC failed return 0x%08x \n",ret);
        goto end ;  
    } 
    pucEncData = (ECCCipher *)buffer ;
    /*外部公钥加密数据*/
    ret = SDF_ExternalEncrypt_ECC(ses,SGD_SM2_3,&PublicKey,ses_key,16,pucEncData);
    if(ret !=SDR_OK){
        Debug_err("SDF_ExternalEncrypt_ECC failed return 0x%08x \n",ret);
        goto end ;    
    }
    /*获取私钥使用权限*/
    ret = SDF_GetPrivateKeyAccessRight(ses,ecc_key_idx,(unsigned char *)"dms123456",strlen("dms123456"));
    if(ret != SDR_OK ){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x \n",ret);
        goto end ;     
    }
    /*内部私钥解密*/
    ret = SDF_ImportKeyWithISK_ECC(ses,ecc_key_idx,pucEncData,&p_keyhadle);
     if(ret !=SDR_OK){
        Debug_err("SDF_ImportKeyWithISK_ECC failed return 0x%08x \n",ret);
       goto end ;     
    }
    /*生成数据*/
#if 0 
    ret = SDF_GenerateRandom(ses,sm4_ctl->data_size,plain);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        goto end ;     
    }
#endif 
#if 1  
    for(unsigned int  i = 0 ; i < (sm4_ctl->data_size/sizeof(unsigned int)) ;i++){
        *((unsigned int*)plain + i) = i;
    } 
#endif    
    unsigned int length = sm4_ctl->data_size ;
    unsigned char iv[16] ;
    for(int i = 0 ; i < 16 ;i++){
        iv[i] = i ;
    }
    gettimeofday(&sm4_ctl->time.g_start,NULL);
    /*数据加密*/
    for(unsigned int i = 0; i < sm4_ctl->test_count; i++){
        ret= SDF_Encrypt(ses,p_keyhadle,sm4_ctl->sm4_mode,iv,plain,sm4_ctl->data_size,cipher,&length);
        if(ret != SDR_OK){
            Debug_err("SDF_Encrypt failed return 0x%08x \n",ret);
            goto end ;      
        }
        for(int i = 0 ; i < 16 ;i++){
            iv[i] = i ;
        }
    }
    gettimeofday(&sm4_ctl->time.g_end,NULL);

    gettimeofday(&sm4_ctl->dec_time.g_start,NULL);
    for(unsigned int i = 0; i < sm4_ctl->test_count; i++){
        ret = SDF_Decrypt(ses,p_keyhadle,sm4_ctl->sm4_mode,iv,cipher,sm4_ctl->data_size,plain_dec,&length);
        if(ret != SDR_OK){
            Debug_err("SDF_Decrypt failed return 0x%08x \n",ret);
            goto end ;      
        }
        for(int i = 0 ; i < 16 ;i++){
            iv[i] = i ;
        }
    }

    gettimeofday(&sm4_ctl->dec_time.g_end,NULL);
    /*数据解密*/
    if(memcmp(plain_dec,plain,sm4_ctl->data_size)!=0){
        Debug_err("memcmp failed  \n");
        goto end ;    
    }
    free(random_buffer);
    return ;
end:
    sm4_ctl->status = 1 ;
    free(random_buffer);
}
/**
 * @brief: 
 * @param []
 * @return []
 */
static void test_sm4_older(struct sm4_ctl *sm4_ctl){
    signle_pthread_test(__test_sm4_older,(void *)sm4_ctl); 
    if(sm4_ctl->status != 0 ){
        Debug_err("函数返回错误\n");     
        return ;
    } 
    
    double performace = ((long)sm4_ctl->data_size*8*1000*sm4_ctl->test_count)/((double)1024*1024*cal_time_ms(&sm4_ctl->time.g_start,&sm4_ctl->time.g_end))  ;
   // Printf_with_color(BLUE,"pthread %d,size %d,use time %ld(ms)\n",sm4_ctl->pthread_pcs,sm4_ctl->data_size,cal_time_ms(&sm4_ctl->time.g_start,&sm4_ctl->time.g_end));
    double dec_performace = ((long)sm4_ctl->data_size*8*1000*sm4_ctl->test_count)/((double)1024*1024*cal_time_ms(&sm4_ctl->dec_time.g_start,&sm4_ctl->dec_time.g_end))  ;
    Printf_with_color(BLUE,"sm4 加密性能%lf(Mbps),sm4 解密性能%lf(Mbps)\n",performace,dec_performace);
}

static void __test_sm4_mac(void *ses,void *p ){
    int ret =  0 ;
    struct sm4_ctl *sm4_ctl = p ;
    void *p_keyhadle = 0 ;
    unsigned char ses_key[16] ;
    ECCrefPublicKey PublicKey ;
    unsigned char buffer[256] ;
    unsigned char *random_buffer ;
    ECCCipher *pucEncData  ;
    memset(buffer,0,256);
    memset(&PublicKey,0,sizeof(ECCrefPublicKey));
    memset(ses_key,0,16);
    random_buffer = (unsigned char *)malloc(2*sm4_ctl->data_size + 16);
    if(random_buffer == NULL){
        Debug_err("没有内存空间分配 \n");
        sm4_ctl->status = 1 ;
        return ;
    }
#if 1
    ret = SDF_GenerateRandom(ses,16,ses_key);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        goto end ;     
    }
#else
    for (int i = 0; i < 16; i++) {
        ses_key[i] = i;
    }
#endif
    /*导出公钥*/
    ret = SDF_ExportEncPublicKey_ECC(ses,ecc_key_idx,&PublicKey);
    if(ret != SDR_OK){
        Debug_err("SDF_ExportEncPublicKey_ECC failed return 0x%08x \n",ret);
        goto end ;  
    } 
    pucEncData = (ECCCipher *)buffer ;
    /*外部公钥加密数据*/
    ret = SDF_ExternalEncrypt_ECC(ses,SGD_SM2_3,&PublicKey,ses_key,16,pucEncData);
    if(ret !=SDR_OK){
        Debug_err("SDF_ExternalEncrypt_ECC failed return 0x%08x \n",ret);
        goto end ;    
    }
    /*获取私钥使用权限*/
    ret = SDF_GetPrivateKeyAccessRight(ses,ecc_key_idx,(unsigned char *)"dms123456",strlen("dms123456"));
    if(ret != SDR_OK ){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x \n",ret);
        goto end ;     
    }
    /*内部私钥解密*/
    ret = SDF_ImportKeyWithISK_ECC(ses,ecc_key_idx,pucEncData,&p_keyhadle);
     if(ret !=SDR_OK){
        Debug_err("SDF_ImportKeyWithISK_ECC failed return 0x%08x \n",ret);
       goto end ;     
    }
    /*生成数据*/
#if 1
    ret = SDF_GenerateRandom(ses,sm4_ctl->data_size,random_buffer);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        goto end ;     
    }
#else
    sm4_ctl->data_size = 16;
    for (int i = 0; i < sm4_ctl->data_size; i++) {
        random_buffer[i] = i;
    }
#endif
    unsigned int length = 128 ;
    unsigned char iv[16] ;
    for(int i = 0 ; i < 16 ;i++){
        iv[i] = i ;
    }
    //print_data_in_hex(iv, 16, "iv");
    gettimeofday(&sm4_ctl->time.g_start,NULL);
    /*数据加密*/
    for(unsigned int i = 0; i < sm4_ctl->test_count; i++){
        ret = SDF_CalculateMAC(ses, p_keyhadle, SGD_SM4_MAC, iv, random_buffer, sm4_ctl->data_size, random_buffer + sm4_ctl->data_size , &length);
        if(ret != SDR_OK){
            Debug_err("SDF_CalculateMAC failed return 0x%08x \n",ret);
            goto end ;     
        }
        for(int i = 0 ; i < 16 ;i++){
            iv[i] = i ;
        }
    }
    gettimeofday(&sm4_ctl->time.g_end,NULL);
    unsigned char soft_mac_buf[16] = {0};
    MAC_SM4(iv, ses_key, random_buffer, sm4_ctl->data_size/16, soft_mac_buf);
    // MyMAC(ses_key, iv , 16, random_buffer, sm4_ctl->data_size, soft_mac_buf, 16);
    if (memcmp(soft_mac_buf, random_buffer + sm4_ctl->data_size, length) != 0) {
        Debug_err("SDF_CalculateMAC  failed:\n");
        print_data_in_hex(ses_key, 16, "key:");
        print_data_in_hex(random_buffer, sm4_ctl->data_size, "rand buf:");
        print_data_in_hex(iv, 16, "iv:");
        print_data_in_hex(soft_mac_buf, length, "soft mac:");
        print_data_in_hex(random_buffer + sm4_ctl->data_size, length, "pcie mac:");
    }
    free(random_buffer);
    return ;
end:
    sm4_ctl->status = 1 ;
    free(random_buffer);
}
/**
 * @brief: 
 * @param []
 * @return []
 */
static void test_sm4_mac(struct sm4_ctl *sm4_ctl){
    signle_pthread_test(__test_sm4_mac,(void *)sm4_ctl);
    if(sm4_ctl->status != 0 ){
        Debug_err("函数返回错误\n");     
        return ;
    } 
   double performace = (long)(sm4_ctl->data_size*8*1000*sm4_ctl->test_count)/(double)cal_time_ms(&sm4_ctl->time.g_start,&sm4_ctl->time.g_end) ;
   Printf_with_color(BLUE,"SM4 性能%lf(Mbps)\n",performace/(1024*1024));  
}
/**
 * @brief:测试SM4算法 
 * @param []
 * @return []
 */
static void test_sm4(void){
    char key = 0 ;
    struct sm4_ctl sm4_ctl;
    
    int mode = 0 ;
    memset(&sm4_ctl,0,sizeof(struct sm4_ctl));
    Printf_with_color(BLUE,"调用此接口前，需要保证(%d)号位置上有公私钥对\n",ecc_key_idx);
    printf("确定/不确定:y/n");
    scanf("%c",&key);
    getchar();
    if(key == 'n'){
        return ;
    }
    Printf_with_color(BLUE,"ECB 1 ,CBC 2 ,0FB 3 ,CFB 4 ,MAC 5,CTR 6\n");
    printf("请输入测试的模式:");
    scanf("%d",&mode);
    getchar();
#if 1
    printf("请输入测试数据的大小(kB):");
    scanf("%d",&sm4_ctl.data_size);
    getchar();
    sm4_ctl.data_size *=1024 ;
#else
    printf("请输入测试数据的大小:");
    scanf("%d",&sm4_ctl.data_size);
    getchar();
#endif
    if(sm4_ctl.data_size == 0){
         Debug_err("输入的数据长度不应该等于0\n");  
         return ;    
    }
    printf("请输入测试次数:");
    scanf("%d",&sm4_ctl.test_count);
    getchar();
    switch(mode){
        case 1:
            sm4_ctl.sm4_mode = SGD_SM4_ECB ;
            test_sm4_ecb(&sm4_ctl);
            break ;
        case 2:
            sm4_ctl.sm4_mode = SGD_SM4_CBC ;
            test_sm4_older(&sm4_ctl);
            break ;
        case 3:
            sm4_ctl.sm4_mode = SGD_SM4_OFB ;
            test_sm4_older(&sm4_ctl);
            break ;
        case 4:  
            sm4_ctl.sm4_mode = SGD_SM4_CFB ;
            test_sm4_older(&sm4_ctl);
            break ;
        case 5:
            sm4_ctl.sm4_mode = SGD_SM4_MAC ;
            test_sm4_mac(&sm4_ctl);
            break ;
        case 6:
            sm4_ctl.sm4_mode = SGD_SM4_CTR ;
            test_sm4_older(&sm4_ctl);
            break ;    
        default:
            Debug_err("输入的模式(%d)错误 \n",mode);
            break ;    
    } 
}
static void __test_sm2(void *ses,void * p){
    int ret =  0 ;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct sm2_ctl *sm2_ctl = pthread_source->p_data ;
    unsigned char buffer[256] ;
    ECCSignature pucSignature ;
    /*获取私钥使用权限*/
    ret = SDF_GetPrivateKeyAccessRight(ses,ecc_key_idx,(unsigned char *)"dms123456",strlen("dms123456"));
    if(ret != SDR_OK ){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x \n",ret);
        sm2_ctl->status = 1 ;
        return  ;      
    }
    ret = SDF_GenerateRandom(ses,32,buffer);
    if(ret != SDR_OK ){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        sm2_ctl->status = 1 ;
        return  ;     
    }

    /*签名性能测试*/
    while_start_time(&sm2_ctl->sign_time,sm2_ctl->pthread_pcs);
    get_start_time(&sm2_ctl->sign_time);
    for(int i = 0 ; i < sm2_ctl->pcs;i++){ 
        ret = SDF_InternalSign_ECC(ses,ecc_key_idx,buffer,32,&pucSignature);
        if(ret != SDR_OK){
            Debug_err("SDF_InternalSign_ECC failed return 0x%08x \n",ret);
            sm2_ctl->status = 1 ;
            return  ; 
        }
    }
    get_end_time(&sm2_ctl->sign_time,sm2_ctl->pthread_pcs);
    /*验签性能测试*/
    while_start_time(&sm2_ctl->verify_time,sm2_ctl->pthread_pcs);
    get_start_time(&sm2_ctl->verify_time);
    for(int i = 0 ; i < sm2_ctl->pcs;i++){
        ret = SDF_InternalVerify_ECC(ses,ecc_key_idx,buffer,32,&pucSignature);
        if(ret != SDR_OK){
            Debug_err("SDF_InternalSign_ECC failed return 0x%08x \n",ret);
            sm2_ctl->status = 1 ;
            return ;
        }
    }
    get_end_time(&sm2_ctl->verify_time,sm2_ctl->pthread_pcs);
}
/**
 * @brief: 
 * @param []
 * @return []
 */
static void test_sm2(void){
    char key = 0 ;
    struct sm2_ctl sm2_ctl ;
    memset(&sm2_ctl,0,sizeof(struct sm2_ctl));
    Printf_with_color(BLUE,"调用此接口前，需要保证(%d)号位置上有公私钥对\n",ecc_key_idx);
    printf("确定/不确定:y/n");
    scanf("%c",&key);
    getchar();
    if(key == 'n'){
        return ;
    }
    printf("请输入测试的线程数量:");
    scanf("%d",&sm2_ctl.pthread_pcs);
    getchar();

    printf("请输入单个线程测试的签名验签次数:");
    scanf("%d",&sm2_ctl.pcs);
    getchar();
    pthread_mutex_init(&sm2_ctl.sign_time.mutex,NULL);
    pthread_mutex_init(&sm2_ctl.verify_time.mutex,NULL);
    sm2_ctl.sign_time.start = 1 ;
    sm2_ctl.verify_time.start = 1 ;
    mult_pthread_test(__test_sm2,(void *)&sm2_ctl); 
    if(sm2_ctl.status !=0){
        Debug_err("函数返回错误\n");  
        return ;
    }
    unsigned int  performace_sign = ((long)sm2_ctl.pthread_pcs*sm2_ctl.pcs*1000)/cal_time_ms(&sm2_ctl.sign_time.g_start,&sm2_ctl.sign_time.g_end) ;
    unsigned int  performace_verify = ((long)sm2_ctl.pthread_pcs*sm2_ctl.pcs*1000)/cal_time_ms(&sm2_ctl.verify_time.g_start,&sm2_ctl.verify_time.g_end) ; 
    Printf_with_color(BLUE,"SM2 签名性能%d(tps)，SM2 验签性能 %d(tps)\n",performace_sign,performace_verify);  
}

static void __test_sm3(void *ses,void *p ){
    int ret =  0;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct sm3_ctl *sm3_ctl = pthread_source->p_data;
    void *p_keyhadle = 0 ;
    unsigned int out_len = 0;
    unsigned char soft_hash_buf[SM3_DIGEST_SIZE] = {0};
    unsigned char pcie_hash_buf[SM3_DIGEST_SIZE] = {0};
    unsigned char *random_buffer ;
    random_buffer = (unsigned char *)malloc(sm3_ctl->data_size + 16);
    if(random_buffer == NULL){
        Debug_err("没有内存空间分配 \n");
        sm3_ctl->status = 1 ;
        return ;
    }
    ret = SDF_GenerateRandom(ses, sm3_ctl->data_size, random_buffer);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        goto end ;     
    }
    /*等到线程都到达此位置*/
    while_start_time(&sm3_ctl->time,sm3_ctl->pthread_pcs);
    get_start_time(&sm3_ctl->time);
    /* 通过pcie卡计算hash */
    ret = SDF_HashInit(ses, SGD_SM3, NULL, NULL, 0);
    ret = SDF_HashUpdate(ses, random_buffer, sm3_ctl->data_size);
    ret = SDF_HashFinal(ses, pcie_hash_buf, &out_len);
    get_end_time(&sm3_ctl->time, sm3_ctl->pthread_pcs);
    /*等到线程都到达此位置*/
    while_start_time(&sm3_ctl->soft_time, sm3_ctl->pthread_pcs);
    get_start_time(&sm3_ctl->soft_time);
    /* 通过软算法计算hash */
    sm3(random_buffer, sm3_ctl->data_size, soft_hash_buf);
    get_end_time(&sm3_ctl->soft_time, sm3_ctl->pthread_pcs);
    if (memcmp(soft_hash_buf, pcie_hash_buf, SM3_DIGEST_SIZE) != 0) {
        Debug_err("sm3 hash  failed:\n");
        // print_data_in_hex(random_buffer, sm3_ctl->data_size, "rand buf:");
        print_data_in_hex(pcie_hash_buf, out_len, "pcie hash:");
        print_data_in_hex(soft_hash_buf, SM3_DIGEST_SIZE, "soft hash:");
    }
    free(random_buffer);
    return ;
end:
    sm3_ctl->status = 1 ;
    free(random_buffer);
}

static void test_sm3_all(struct sm3_ctl *sm3_ctl){
    printf("请输入测试的线程个数:");
    scanf("%d",&sm3_ctl->pthread_pcs);
    getchar();
    sm3_ctl->time.start = 1 ;
    sm3_ctl->time.end = 0 ;
    sm3_ctl->soft_time.start = 1 ;
    sm3_ctl->soft_time.end = 0  ;
    pthread_mutex_init(&sm3_ctl->time.mutex,NULL);
    pthread_mutex_init(&sm3_ctl->soft_time.mutex,NULL);
    mult_pthread_test(__test_sm3, sm3_ctl);
    if(sm3_ctl->status ){
        Debug_err("函数返回错误\n");     
        return ;    
    }
    double performace = ((long)sm3_ctl->pthread_pcs*sm3_ctl->data_size*8*1000)/((double)1024*1024*cal_time_ms(&sm3_ctl->time.g_start,&sm3_ctl->time.g_end))  ;
   // Printf_with_color(BLUE,"pthread %d,size %d,use time %ld(ms)\n",sm4_ctl->pthread_pcs,sm4_ctl->data_size,cal_time_ms(&sm4_ctl->time.g_start,&sm4_ctl->time.g_end));
    double soft_performance = ((long)sm3_ctl->pthread_pcs*sm3_ctl->data_size*8*1000)/((double)1024*1024*cal_time_ms(&sm3_ctl->soft_time.g_start,&sm3_ctl->soft_time.g_end))  ;
    Printf_with_color(BLUE,"sm3 pcie性能%lf(Mbps),sm3 软算法性能%lf(Mbps)\n",performace,soft_performance); 
}

/**
 * @brief:测试SM3算法 
 * @param []
 * @return []
 */
static void test_sm3(void){
    char key = 0 ;
    struct sm3_ctl sm3_ctl;
    
    int mode = 0 ;
    memset(&sm3_ctl,0,sizeof(struct sm3_ctl));
#if 1
    printf("请输入测试数据的大小(kB):");
    scanf("%d",&sm3_ctl.data_size);
    getchar();
    sm3_ctl.data_size *=1024 ;
#else
    printf("请输入测试数据的大小:");
    scanf("%d",&sm3_ctl.data_size);
    getchar();
#endif
    if(sm3_ctl.data_size == 0){
         Debug_err("输入的数据长度不应该等于0\n");  
         return ;    
    }
    test_sm3_all(&sm3_ctl);
}

static void __test_sm2_enc_dec(void *ses,void * p){
    int ret = 0 ;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct sm2_enc_dec_ctl *sm2_ctl_enc_dec = pthread_source->p_data ;
    ECCrefPublicKey pucPublicKey;
    ECCrefPrivateKey pucPrivateKey ;
    uint8_t cipher[128*1024] = {0};
    uint8_t plain[128*1024] = {0} ;
    uint8_t plain_dec[128*1024] = {0};
    ret = SDF_GenerateRandom(ses,sm2_ctl_enc_dec->length,plain);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        sm2_ctl_enc_dec->status = 1 ;
        return ;
    }
    ret = SDF_GenerateKeyPair_ECC(ses,SGD_SM2,256,&pucPublicKey,&pucPrivateKey);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateKeyPair_ECC failed return 0x%08x \n",ret);
        sm2_ctl_enc_dec->status = 1 ;

        return ;
    }
    int i = 0 ;
    ECCCipher *ecccipher = (ECCCipher *)cipher ;
    while_start_time(&sm2_ctl_enc_dec->enc_time,sm2_ctl_enc_dec->pthread_pcs);
    get_start_time(&sm2_ctl_enc_dec->enc_time);
    for(i = 0 ; i < sm2_ctl_enc_dec->pcs ;i++){
        ret = SDF_ExternalEncrypt_ECC(ses,SGD_SM2_3,&pucPublicKey,plain,sm2_ctl_enc_dec->length,ecccipher);
        if(ret != SDR_OK){
            Debug_err("SDF_ExternalEncrypt_ECC failed return 0x%08x \n",ret);
            sm2_ctl_enc_dec->status = 1 ;
       
            return ;
        }
    }
    get_end_time(&sm2_ctl_enc_dec->enc_time,sm2_ctl_enc_dec->pthread_pcs);
    unsigned int length = 0 ;
    while_start_time(&sm2_ctl_enc_dec->dec_time,sm2_ctl_enc_dec->pthread_pcs);
    get_start_time(&sm2_ctl_enc_dec->dec_time);
    for(i = 0 ; i < sm2_ctl_enc_dec->pcs;i++){
        ret = SDF_ExternalDecrypt_ECC(ses,SGD_SM2_3,&pucPrivateKey,ecccipher,plain_dec,&length);
        if(ret != SDR_OK){
            Debug_err("SDF_ExternalDecrypt_ECC failed return 0x%08x \n",ret);
            sm2_ctl_enc_dec->status = 1 ;
            return ;
        }
    }
    get_end_time(&sm2_ctl_enc_dec->dec_time,sm2_ctl_enc_dec->pthread_pcs);
    if(memcmp(plain_dec,plain,length) !=0){
            Debug_err("memcmp failed \n");
            sm2_ctl_enc_dec->status = 1 ;
        
            return ;  
    }
}

/**
 * @brief:测试SM2加解密接口性能 
 * @param []
 * @return []
 */
static void test_sm2_enc_dec(void){

    struct sm2_enc_dec_ctl sm2_enc_dec_ctl ;
    memset(&sm2_enc_dec_ctl,0,sizeof(struct sm2_enc_dec_ctl));

    printf("请输入测试的线程数量(1~%d):",MAX_PTHREAD_T);
    scanf("%d",&sm2_enc_dec_ctl.pthread_pcs);
    getchar();

    printf("请输入单个线程测试的次数:");
    scanf("%d",&sm2_enc_dec_ctl.pcs);
    getchar();

    printf("请输入单个线程测试的数据的长度（数据长度需为16的整数倍）:");
    scanf("%d",&sm2_enc_dec_ctl.length);
    getchar();
    
    pthread_mutex_init(&sm2_enc_dec_ctl.dec_time.mutex,NULL);
    pthread_mutex_init(&sm2_enc_dec_ctl.enc_time.mutex,NULL);
    sm2_enc_dec_ctl.dec_time.start = 1 ;
    sm2_enc_dec_ctl.enc_time.start = 1 ;
    mult_pthread_test(__test_sm2_enc_dec,(void *)&sm2_enc_dec_ctl); 
    if(sm2_enc_dec_ctl.status !=0 ){
        Debug_err("函数返回错误\n");  
        return ;
    }
    double  performace_enc = ((long)sm2_enc_dec_ctl.length*sm2_enc_dec_ctl.pthread_pcs*sm2_enc_dec_ctl.pcs*1000*8)/cal_time_ms(&sm2_enc_dec_ctl.enc_time.g_start,&sm2_enc_dec_ctl.enc_time.g_end) ;
    double  performace_dec = ((long)sm2_enc_dec_ctl.length*sm2_enc_dec_ctl.pthread_pcs*sm2_enc_dec_ctl.pcs*1000*8)/cal_time_ms(&sm2_enc_dec_ctl.dec_time.g_start,&sm2_enc_dec_ctl.dec_time.g_end) ;
    Printf_with_color(BLUE,"SM2 加密性能%f(Mbps)，SM2 解密性能 %f(Mbps)\n",performace_enc/(1024*1024),performace_dec/(1024*1024));  
    double  performace_enc_tps = ((long)sm2_enc_dec_ctl.pthread_pcs*sm2_enc_dec_ctl.pcs*1000)/cal_time_ms(&sm2_enc_dec_ctl.enc_time.g_start,&sm2_enc_dec_ctl.enc_time.g_end) ;
    double  performace_dec_tps = ((long)sm2_enc_dec_ctl.pthread_pcs*sm2_enc_dec_ctl.pcs*1000)/cal_time_ms(&sm2_enc_dec_ctl.dec_time.g_start,&sm2_enc_dec_ctl.dec_time.g_end) ;
    Printf_with_color(BLUE,"SM2 加密(%dB)性能%f(tps)，SM2 解密(%dB)性能 %f(tps)\n",sm2_enc_dec_ctl.length,performace_enc_tps,sm2_enc_dec_ctl.length,performace_dec_tps);  
    
}

static void __generate_key_matrix(void *sess, void *p){
    int ret = SDF_dmsPCI_PCICardGenerateMatrix(sess);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_PCICardGenerateMatrix err, ret = 0x%08x !\n", ret);
    }
}

static void test_generate_key_matrix(void){
    signle_pthread_test(__generate_key_matrix, NULL);
}

static void __generate_person_key(void *sess, void *p){
    int ret = 0;
    unsigned int key_index;
    char id[128] = {0};
    ECCrefPublicKey pkx = {0,{0x00},{0x00}}, pubH = {0,{0x00},{0x00}};
    unsigned char env[1024] = {0};
    unsigned char ske_pke[256] = {0};
    printf("请输入密钥位索引：");
    scanf("%d", &key_index);
    printf("请输入用户密钥生产的实体标识(标识长度范围为0~128): \n");
    scanf("%s", id);
    /* 1. 生成秘密值密钥对及保护密钥对 */
    ret = SDF_dmsPCI_GenECCKeyPair(sess, key_index, &pkx, &pubH);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_GenECCKeyPair err, ret = 0x%08x \n", ret);
        return ;
    }

    /* 2. 根据标识计算用户个人密钥对 */
    ret = SDF_dmsPCI_CalculatePersonKey(sess, 0, id, "ahdms", 
                                        "2021-09-06", "2022-09-06", 
                                        &pkx, &pubH, 
                                        (CkiEnvelope *)env, (EnvelopedKeyBlob *)ske_pke);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_CalculatePersonKey err, ret = 0x%08x \n", ret);
        return ;
    }
    /* 3. 导入加密密钥对，合成签名密钥对 */
    ret = SDF_dmsPCI_ImportKeyWithECCKeyPair(sess, key_index, (EnvelopedKeyBlob *)ske_pke);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_ImportKeyWithECCKeyPair err, ret = 0x%08x \n", ret);
        return ;
    }
}

static void test_generate_iki_person_key(void){
    signle_pthread_test(__generate_person_key, NULL);
}

static void __calculate_skid_pkid(void *sess, void *p){
    int ret = 0;
    unsigned int data_len, hash_len = 32;
    struct iki_alg_struct *iki_param = (struct iki_alg_struct *)p;
    unsigned char data[BUFFER_LENGTH] = {0};
    unsigned char hash[32] = {0};
    ECCSignature signature ;
    ECCrefPublicKey pkid = {0};
    char sign_id[] = "1234567812345678";
    memset(&signature,0,sizeof(ECCSignature));
    printf("输入待签名数据长度(1~1024)：");
    scanf("%d", &data_len);
    if(data_len > BUFFER_LENGTH){
        data_len = BUFFER_LENGTH;
    }
    /* 生成随机数，作为待签名原文 */
    ret = SDF_GenerateRandom(sess, data_len, data);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        return ;
    }
    // showHexData(data, data_len, "data");
    /* 计算标识私钥并签名 */
    if(iki_param->optimize_flag == 1){
        /* 升级前 */
        ret = SDF_dmsPCI_IdentifyECCSignForEnvelope(sess, iki_param->region, iki_param->id, iki_param->id_len, sign_id, strlen(sign_id), 
                                                data, data_len, &signature);
        if(ret != SDR_OK){
            Debug_err("SDF_dmsPCI_IdentifyECCSignForEnvelope failed return 0x%08x \n",ret);
            return ;
        }
    }
    else{
        /* 升级后 */
        ret = SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize(sess, iki_param->region, iki_param->id, iki_param->id_len, sign_id, strlen(sign_id), 
                                                data, data_len, &signature);
        if(ret != SDR_OK){
            Debug_err("SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize failed return 0x%08x \n",ret);
            return ;
        }
    }
    /* 计算标识公钥 */
    if(iki_param->optimize_flag == 1){
        /* 升级前 */
        ret = SDF_dmsPCI_CalculatePubKey(sess, iki_param->region, iki_param->id, iki_param->id_len, &pkid);
        if(ret != SDR_OK){
            Debug_err("SDF_dmsPCI_CalculatePubKey failed return 0x%08x \n",ret);
            return ;
        } 
    }
    else{
        /* 升级后 */
        ret = SDF_dmsPCI_CalculatePubKey_Optimize(sess, iki_param->region, iki_param->id, iki_param->id_len, &pkid);
        if(ret != SDR_OK){
            Debug_err("SDF_dmsPCI_CalculatePubKey_Optimize failed return 0x%08x \n",ret);
            return ;
        } 
    }
    //showHexData(pkid.x + 32, 32, "pkid.x");
    //showHexData(pkid.y + 32, 32, "pkid.y");
#if 1
	//对待签数据做预处理
	ret = SDF_HashInit(sess, SGD_SM3, &pkid, (unsigned char *)sign_id, strlen(sign_id));
	if (ret != SDR_OK)
	{
        Debug_err("SDF_HashInit failed return 0x%08x \n",ret);
        return ;
    }
	ret = SDF_HashUpdate(sess, data, data_len);
	if (ret != SDR_OK)
	{
        Debug_err("SDF_HashInit failed return 0x%08x \n",ret);
        return ;
    }
	ret = SDF_HashFinal(sess, hash, &hash_len);
	if (ret != SDR_OK)
	{
        Debug_err("SDF_HashInit failed return 0x%08x \n",ret);
        return ;
    }
#else
    sm3_id_pub(data, data_len, sign_id, strlen(sign_id), pkid.x + 32, pkid.y + 32, hash);
#endif
	// showHexData(hash, hash_len, "hash result");

    /* 验签 */  
    ret = SDF_ExternalVerify_ECC(sess, SGD_SM2_1, &pkid, hash, 32, &signature); 
    if(ret != SDR_OK){
        Debug_err("SDF_ExternalVerify_ECC failed return 0x%08x \n",ret);
        return ;
    }
}

static void test_calculate_skid_pkid(void){
    struct iki_alg_struct iki_param = {0};
    printf("请输入想要测试的IKI版本: \n");
    printf("1. IKI V2.0(升级前)    2. IKI V3.0(升级后) \n");
    scanf("%d", &iki_param.optimize_flag);
    if((iki_param.optimize_flag != 1) && (iki_param.optimize_flag != 2)){
        printf("请选择正确的IKI版本! \n");
        return ;
    }
    printf("输入实体标识：");
    scanf("%s", iki_param.id);
    iki_param.id_len = strlen(iki_param.id);
    signle_pthread_test(__calculate_skid_pkid, (void *)&iki_param);
}



int get_index_from_buffer(){
    uint8_t buffer[256] = {0} ;
    scanf("%s",buffer);
    getchar();
    uint8_t str[32] = {0} ;
    int i = 0,j = 0 ;
    while(buffer[i++] !='_');
    while(buffer[i] != '{'){
        str[j++] = buffer[i];
        i++ ;
    } 
     printf("str %s,data %d \n",str,atoi((const char *)str))  ;
     return 0 ; 
}

static void __generate_ecc_key_pair(void *sess, void *p){
    ECCrefPublicKey pucPublicKey;
    ECCrefPrivateKey pucPrivateKey;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct ecc_key_pair_ctl *ctl = (struct ecc_key_pair_ctl *)pthread_source->p_data ;
    while_start_time(&ctl->time,ctl->pthread_pcs); 
    get_start_time(&ctl->time);
    int ret = SDR_OK;
    for(int i = 0; i <ctl->pcs; i++){
        ret = SDF_GenerateKeyPair_ECC(sess,SGD_SM2_3,256,&pucPublicKey,&pucPrivateKey);
        if(ret != SDR_OK){
            Debug_err("SDF_GenerateKeyPair_ECC failed return 0x%08x \n",ret);
            ctl->status = 1 ;
            return ;
        }   
   }
   get_end_time(&ctl->time,ctl->pthread_pcs);
}

static void test_generate_ecc_key_pair(void){
    struct ecc_key_pair_ctl ecc_key_pair_ctl;
    memset(&ecc_key_pair_ctl, 0, sizeof(struct ecc_key_pair_ctl));
    printf("请输入测试的线程数量(1~%d):",MAX_PTHREAD_T);
    scanf("%d",&ecc_key_pair_ctl.pthread_pcs);
    getchar();
    printf("请输入单个线程测试次数:");
    scanf("%d",&ecc_key_pair_ctl.pcs);
    getchar(); 
    ecc_key_pair_ctl.time.start = 1;
    pthread_mutex_init(&ecc_key_pair_ctl.time.mutex, NULL);
    mult_pthread_test(__generate_ecc_key_pair,(void *)&ecc_key_pair_ctl); 
    if(ecc_key_pair_ctl.status !=0 ){
        Debug_err("函数返回错误\n");  
        return ;
    }
    int  performace = ((long)ecc_key_pair_ctl.pthread_pcs*ecc_key_pair_ctl.pcs*1000)/cal_time_ms(&ecc_key_pair_ctl.time.g_start,&ecc_key_pair_ctl.time.g_end) ;
    Printf_with_color(WHITE,"SM2 生成密钥对性能 %d (tps)\n",performace);  
}

static void __export_import_pub_matrix(void *ses, void *p){
    unsigned int pub_matrix_len = 0;
    unsigned char pub_matrix[32788] = {0};
    int ret = 0;
    /* 导出公钥矩阵 */
    ret = SDF_dmsPCI_ExportPubMatrix(ses, pub_matrix, &pub_matrix_len);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_ExportPubMatrix failed return 0x%08x \n",ret);
        return ; 
    }
    Printf_with_color(WHITE, "pub matrix len: %d \n", pub_matrix_len);
    showHexData(pub_matrix, 1024, "exported pub matrix");
    /* PCIE密码卡初始化 */
    ret = SDF_dmsPCICardInit(ses, 2, "dms123456", strlen("dms123456"));
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCICardInit failed return 0x%08x \n",ret);
        return ; 
    }    
    /* 导入公钥矩阵 */
    ret = SDF_dmsPCI_ImportPubMatrix(ses, pub_matrix, pub_matrix_len);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_ImportPubMatrix failed return 0x%08x \n",ret);
        return ; 
    }
}

static void test_export_import_pub_matrix(void){
    signle_pthread_test(__export_import_pub_matrix, NULL);
}

static void __pcie_card_init(void *sess, void *p){
    struct device_info *info = (struct device_info *)p;
    int ret = SDF_dmsPCICardInit(sess, info->type, info->pin.pin, info->pin.pin_len);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCICardInit failed return 0x%08x \n",ret);
        return ; 
    }
}

static void pcie_card_init(void){
    struct device_info info = {0};
    printf("请输入设备PIN码：");
    scanf("%s", info.pin.pin);
    info.pin.pin_len = strlen(info.pin.pin);
    printf("请输入需设置的卡的类型：\n");
    printf("1. 生产型密码卡     2. 服务型密码卡 \n");
    scanf("%d", &info.type);
    if((info.type != 1) && (info.type != 2)){
        printf("请选择正确的卡的类型");
        return ;
    }
    signle_pthread_test(__pcie_card_init, (void *)&info);
}

static void __clear_container(void *sess, void *p){
    unsigned int *index = (unsigned int *)p;
    int ret = SDF_dmsPCI_SVSClearContainer(sess, *index);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_SVSClearContainer failed return 0x%08x \n",ret);
        return ;
    }
}

static void test_clear_container(void ){
    unsigned int index = 0;
    printf("请输入密钥位索引(0~%d)：", MAX_KEY_PAIR - 1);
    scanf("%d", &index);
    if(index > MAX_KEY_PAIR - 1){
        Debug_err("MAX  index  IS %d \n",MAX_KEY_PAIR -1);
        return ; 
    }
    signle_pthread_test(__clear_container, (void *)&index);
}

static void __change_key_password(void *sess, void *p){
    struct prikey_password *key_pw = (struct prikey_password *)p;
    int ret = SDF_dmsPCI_ChangeKeyPIN(sess, key_pw->index, 
                                key_pw->pw.pin, key_pw->pw.new_pin);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_ChangeKeyPIN failed return 0x%08x \n",ret);
        return ;
    }
}

static void test_change_key_password(void){
    struct prikey_password key_pw = {0};
    printf("请输入欲修改的私钥权限码对应的密钥位索引(0~%d)：",
             MAX_KEY_PAIR - 1);
    scanf("%d", &key_pw.index);
    if(key_pw.index > MAX_KEY_PAIR - 1){
        Debug_err("MAX  index  IS %d \n",MAX_KEY_PAIR -1);
        return ; 
    }  
    printf("请输入原来的私钥使用权限码："); 
    scanf("%s", key_pw.pw.pin); 
    key_pw.pw.pin_len = strlen(key_pw.pw.pin);
    printf("请输入新的私钥使用权限码 \n");
    printf("(8~16字节，且至少含数字、大写字母、小写字母及其他特殊字符中的两种): \n");
    scanf("%s", key_pw.pw.new_pin);
    key_pw.pw.new_pin_len = strlen(key_pw.pw.new_pin);
    signle_pthread_test(__change_key_password, (void *)&key_pw);
}

static void __change_device_pin(void *sess, void *p){
    struct password *dev_pin = (struct password *)p;
    int ret = SDF_dmsPCI_ChangeCardPIN(sess, dev_pin->pin, dev_pin->new_pin);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_ChangeCardPIN failed return 0x%08x \n",ret);
        return ;
    }
}

static void test_change_device_pin(void){
    struct password dev_pin = {0};
    printf("请输入原来的设备PIN码："); 
    scanf("%s", dev_pin.pin); 
    dev_pin.pin_len = strlen(dev_pin.pin);
    printf("请输入新的设备PIN码 \n");
    printf("(8~16字节，且至少含数字、大写字母、小写字母及其他特殊字符中的两种): \n");
    scanf("%s", dev_pin.new_pin);
    dev_pin.new_pin_len = strlen(dev_pin.new_pin);
    signle_pthread_test(__change_device_pin, (void *)&dev_pin);    
}

static void __key_backup_and_recovery(void *sess, void *p){
    unsigned int key_seg_len = 0;
    unsigned char *key_seg = (unsigned char *)malloc(147456*1024);
    if(NULL == key_seg){
        Debug_err("malloc space err\n");
        return ;
    }
    unsigned int offset = 0;
    struct backup_recovery *pctl = (struct backup_recovery *)p;
    /* 1. 备份初始化 */
    int ret = SDF_dmsPCI_SegMentKeyInit(sess, pctl->backup_grp, pctl->device_pin, pctl->device_pin_len);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_SegMentKeyInit failed return 0x%08x \n",ret);
        return ;
    }
    /* 2. 导出密钥分量 */
    for(int i = 0; i < pctl->backup_grp; i++){
        ret = SDF_dmsPCI_GetSegMentKey(sess, pctl->enc_pin, pctl->enc_pin_len, &key_seg_len, key_seg + offset);
        if(SDR_OK != ret){
            Debug_err("SDF_dmsPCI_GetSegMentKey failed return 0x%08x \n",ret);
            return ;
        }
        offset += key_seg_len;
    }
    /* 3. 密钥备份结束 */
    ret = SDF_dmsPCI_SegMentKeyFinal(sess);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_SegMentKeyFinal failed return 0x%08x \n",ret);
        return ;
    }
    #if 1
    /* 4. 密码卡初始化 */
    ret = SDF_dmsPCICardInit(sess, 2, pctl->device_pin, pctl->device_pin_len);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCICardInit failed return 0x%08x \n",ret);
        return ;
    } 
    printf("SDF_dmsPCICardInit success\n");
    getchar();
    #endif
    /* 5. 密钥恢复初始化 */
    ret = SDF_dmsPCI_KeyRecoveryInit(sess);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_KeyRecoveryInit failed return 0x%08x \n",ret);
        return ;
    } 
    offset = 0;
    /* 6. 导入密钥分量 */
    for(int i = 0; i < pctl->recovery_grp; i++){
        ret = SDF_dmsPCI_ImportSegmentKey(sess, pctl->dec_pin, pctl->dec_pin_len, key_seg + offset, key_seg_len);
        if(SDR_OK != ret){
            Debug_err("SDF_dmsPCI_ImportSegmentKey failed return 0x%08x \n",ret);
            return ;
        }
        offset += key_seg_len;
    }
    /* 7. 密钥恢复 */
    ret = SDF_dmsPCI_KeyRecovery(sess, pctl->recovery_grp);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_KeyRecovery failed return 0x%08x \n",ret);
        return ;
    }
    printf("SDF_dmsPCI_KeyRecovery success\n");
}

static void test_key_backup_and_recovery(void){
    struct backup_recovery ctl = {0};
    printf("请输入设备PIN码以校验您的身份：");
    scanf("%s", ctl.device_pin); 
    getchar();
    ctl.device_pin_len = strlen(ctl.device_pin);
    printf("请输入密钥备份组数(2~9)：");
    scanf("%d", &ctl.backup_grp);
    getchar();
    printf("请输入用于密钥加密的PIN(长度为8~16字节)：");
    scanf("%s", ctl.enc_pin);
    getchar();
    ctl.enc_pin_len = strlen(ctl.enc_pin);
    printf("请输入密钥恢复组数：");
    scanf("%d", &ctl.recovery_grp);
    getchar();
    printf("请输入用于密钥解密的PIN：");
    scanf("%s", ctl.dec_pin);
    getchar();
    ctl.dec_pin_len = strlen(ctl.dec_pin);
    signle_pthread_test(__key_backup_and_recovery, (void *)&ctl); 
}

static void __key_backup_and_recovery_threshold(void *sess, void *p){
    int ret = 0, i = 0;
    unsigned int all_key_total_len = 0, sess_key_seg_len = 0;
    struct threshold_ctl_st *p_ctl = (struct threshold_ctl_st *)p;
    ECCrefPublicKey enc_pub = {0}, dec_pub = {0};
    unsigned char sess_key_seg[9][256] = {0};
    unsigned char env_digital_exchange[9][256] = {0};
    /* 1. 获取全密钥数据长度 */
    ret = SDF_dmsPCI_Backup_Threshold(sess, 0, 0, 0, NULL, NULL, &all_key_total_len);
    if(SDR_OK != ret){
        Debug_err("get all key len failed return 0x%08x \n",ret);
        return ;
    } 
    /* 2. 分配空间用于存储全密钥数据 */
    unsigned char *all_key = (unsigned char *)malloc(all_key_total_len);
    if(NULL == all_key){
        Debug_err("malloc space err\n");
        return ;
    }
    /* 3. 导出全密钥数据 */
    ret = SDF_dmsPCI_Backup_Threshold(sess, p_ctl->backup_grp, p_ctl->recovery_grp, 
            p_ctl->device_pin_len, p_ctl->device_pin, all_key, &all_key_total_len);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_Backup_Threshold failed return 0x%08x \n",ret);
        goto end;        
    }
    /* 4. 导出用于会话密钥分量的公钥 */
    ret = SDF_ExportEncPublicKey_ECC(sess, p_ctl->key_index, &enc_pub);
    if(SDR_OK != ret){
        Debug_err("SDF_ExportEncPublicKey_ECC failed return 0x%08x \n",ret);
        goto end;        
    }
    /* 5. 导出会话密钥分量 */
    for(i = 0; i < p_ctl->backup_grp; i++){
        ret = SDF_dmsPCI_ExportSegmentKey_Threshold(sess, &enc_pub, sess_key_seg[i], &sess_key_seg_len);
        if(SDR_OK != ret){
            Debug_err("i = %d, SDF_dmsPCI_ExportSegmentKey_Threshold failed return 0x%08x \n", i, ret);
            goto end;        
        }
    }
    /* 6. 密钥恢复初始化 */
    ret = SDF_dmsPCI_GetEncPubKey_Threshold(sess, &dec_pub);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_GetEncPubKey_Threshold failed return 0x%08x \n",ret);
        goto end;        
    } 
    /* 7. 获取私钥使用权限 */
    ret = SDF_GetPrivateKeyAccessRight(sess, p_ctl->key_index, p_ctl->prikey_pin, p_ctl->prikey_pin_len);
    if(SDR_OK != ret){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x \n",ret);
        goto end;        
    }     
    /* 7. 数字信封转换 */   
    for(i = 0; i < p_ctl->recovery_grp; i++){
        ret = SDF_ExchangeDigitEnvelopeBaseOnECC(sess, p_ctl->key_index, SGD_SM2_3, 
                &dec_pub, sess_key_seg[i], env_digital_exchange[i]);
        if(SDR_OK != ret){
            Debug_err("i = %d, SDF_ExchangeDigitEnvelopeBaseOnECC failed return 0x%08x \n", i, ret);
            goto end;        
        } 
    }
#if 1
    /* 8. pcie密码卡初始化 */
    ret = SDF_dmsPCICardInit(sess, 2, p_ctl->device_pin, p_ctl->device_pin_len);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCICardInit failed return 0x%08x \n",ret);
        goto end;
    } 
    printf("SDF_dmsPCICardInit success\n");
    getchar();    
#endif
    /* 9. 导入会话密钥分量 */
    for(i = 0; i < p_ctl->recovery_grp; i++){
        ret = SDF_dmsPCI_ImportSegmentKey_Threshold(sess, env_digital_exchange[i], sess_key_seg_len);
        if(SDR_OK != ret){
            Debug_err("i = %d, SDF_dmsPCI_ImportSegmentKey_Threshold failed return 0x%08x \n", i, ret);
            goto end;        
        }         
    }
    /* 10. 密钥恢复 */
    ret = SDF_dmsPCI_Restore_Threshold(sess, p_ctl->recovery_grp, all_key, all_key_total_len);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_Restore_Threshold failed return 0x%08x \n",ret);
        goto end;
    }  
    printf("SDF_dmsPCI_Restore_Threshold success \n");
end:
    if (all_key) {
        free(all_key);
    }
    return;
}

void test_key_backup_and_recovery_threshold(void){
    char choice = 0;
    struct threshold_ctl_st ctl = {1, 5, 3, 9, "dms123456", 9, "dms123456"};
    printf("是否自动化测试(y/n)：");
    scanf("%c", &choice);
    getchar();
    if('n' == choice){
        printf("请输入设备PIN码以校验您的身份：");
        scanf("%s", ctl.device_pin); 
        getchar();
        ctl.device_pin_len = strlen(ctl.device_pin);
        printf("请输入欲分割的组数：");
        scanf("%d", &ctl.backup_grp);
        getchar();
        printf("请输入用于恢复的密钥分量组数：");
        scanf("%d", &ctl.recovery_grp);
        getchar();
        printf("请输入本次测试中，所需使用到的密钥位对应索引(0~%d)：", KEY_POOL_SIZE_MAX - 1);
        scanf("%d", &ctl.key_index);
        getchar();
        printf("请确定此密钥中存在完整的加密密钥对(y/n)：");
        scanf("%c", &choice);
        getchar();
        if('n' == choice){
            return ;
        }
        printf("请输入%d号密钥位对应的私钥使用权限码：", ctl.key_index);
        scanf("%s", ctl.prikey_pin); 
        getchar();
        ctl.prikey_pin_len = strlen(ctl.prikey_pin);
    }
    signle_pthread_test(__key_backup_and_recovery_threshold, (void *)&ctl);   
}

void test_self(void) {
    void *ses ;
    int ret = 0 ;
    ret = SDF_OpenSession(handle_dev,&ses);
    if(ret != SDR_OK){
        Debug_err("SDF_OpenSession failed return 0x%08x \n",ret);
        return ;
    }
    ret = SDF_dmsPCI_TestSelf(ses);
    if(ret != SDR_OK){
        Debug_err("SDF_dmsPCI_TestSelf failed return 0x%08x !\n",ret);
    }
    ret = SDF_CloseSession(ses);
    if(ret != SDR_OK){
        Debug_err("SDF_CloseSession failed return 0x%08x !\n",ret);
    }
    printf("SDF_dmsPCI_TestSelf success \n");
}

static void _generate_kek(void *ses,void *p){
    int ret = 0;
    struct kek_ctl_st *p_ctl = (struct kek_ctl_st *)p;
    ret = SDF_dmsPCI_GenerateKEK(ses, p_ctl->bit_len, &p_ctl->index);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_GenerateKEK failed return 0x%08x \n",ret);
        return ;        
    }  
    printf("SDF_dmsPCI_GenerateKEK success, index: %d\n", p_ctl->index);   
}

static void test_generate_kek(void){
    struct kek_ctl_st ctl = {0};
    printf("请输入密钥位长：");
    scanf("%d", &ctl.bit_len);
    getchar();
    signle_pthread_test(_generate_kek, &ctl);
}

static void _generate_kek_by_index(void *ses,void *p){
    int ret = 0;
    struct kek_ctl_st *p_ctl = (struct kek_ctl_st *)p;
    ret = SDF_dmsPCI_GenerateKEKByIndex(ses, p_ctl->index, p_ctl->bit_len);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_GenerateKEKByIndex failed return 0x%08x \n",ret);
        return ;        
    }  
    printf("SDF_dmsPCI_GenerateKEKByIndex success\n");   
}

static void test_generate_kek_by_index(void){
    char ch = 0;
    struct kek_ctl_st ctl = {0};
    printf("请输入密钥位长：");
    scanf("%d", &ctl.bit_len);
    getchar();
    printf("请输入KEK索引值(1~%d)：", MAX_KEKSTATELEN);
    scanf("%d", &ctl.index);
    getchar(); 
    printf("是否确认该位置目前不存在KEK(y/n): ");   
    scanf("%c", &ch);
    getchar(); 
    if('n' == ch){
        return ;
    }
    signle_pthread_test(_generate_kek_by_index, &ctl);
}

static void _generate_all_kek(void *ses,void *p){
    int ret = 0;
    struct kek_ctl_st *p_ctl = (struct kek_ctl_st *)p;
    for(int i = 1; i <= MAX_KEKSTATELEN; i++){
        ret = SDF_dmsPCI_GenerateKEKByIndex(ses, i, p_ctl->bit_len);
        if(SDR_OK != ret){
            Debug_err("SDF_dmsPCI_GenerateKEKByIndex failed return 0x%08x \n",ret);
            return ;        
        }          
    }    
}

static void test_generate_all_kek(void){
    char ch = 0;
    struct kek_ctl_st ctl = {0};
    printf("请输入密钥位长：");
    scanf("%d", &ctl.bit_len);
    getchar();
    printf("是否确认目前卡中不存在任何KEK(y/n): ");   
    scanf("%c", &ch);
    getchar(); 
    if('n' == ch){
        return ;
    }
    signle_pthread_test(_generate_all_kek, &ctl);
}

static void _delete_kek_by_index(void *ses,void *p){
    int ret = 0;
    struct kek_ctl_st *p_ctl = (struct kek_ctl_st *)p;
    ret = SDF_dmsPCI_DeleteKEK(ses, p_ctl->index);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_DeleteKEK failed return 0x%08x \n",ret);
        return ;        
    }    
}

static void test_delete_kek_by_index(void){
    char ch = 0;
    struct kek_ctl_st ctl = {0};
    printf("请输入KEK索引值(1~%d)：", MAX_KEKSTATELEN);
    scanf("%d", &ctl.index);
    getchar(); 
    printf("是否确认该位置存在KEK(y/n): ");   
    scanf("%c", &ch);
    getchar(); 
    if('n' == ch){
        return ;
    }
    signle_pthread_test(_delete_kek_by_index, &ctl);
}

static void __test_get_kek_state(void *ses,void *p){
    int ret = 0;
    unsigned int size = MAX_KEKSTATELEN;
    unsigned char state[MAX_KEKSTATELEN] = {0};
    ret = SDF_dmsPCI_GetKEKPoolState(ses, state, &size);
    if(SDR_OK != ret){
        Debug_err("SDF_dmsPCI_GetKEKPoolState failed return 0x%08x \n",ret);
        return ;        
    } 
    int next_line = 0 ;
    Printf_with_color(BLUE,"密钥池的大小为:%d\n", size); 
    Printf_with_color(BLUE,"存在对称密钥的是:\n");
    for(int i = 0 ; i <  size; i++){
        if(state[i] == 1){
            Printf_with_color(BLUE,"%d ",i+1); 
            next_line ++ ; 
            if(next_line %16 == 0 ){
                printf("\n");   
            }
        }
    }
    printf("\n");
}
/**
 * @brief: 获取密钥池状态
 * @param []
 * @return []
 */
static void test_get_kek_state(void){
    signle_pthread_test(__test_get_kek_state,NULL);
}

static void exit_test(void){
    return ;
}

static void _create_file(void *ses,void *p){
    int ret = 0;
    struct file_ctl_st *p_ctl = (struct file_ctl_st *)p;
    ret = SDF_CreateFile(ses, p_ctl->file_name, strlen(p_ctl->file_name), p_ctl->file_size);
    if(SDR_OK != ret){
        Debug_err("SDF_CreateFile failed return 0x%08x \n",ret);
        return ;        
    }     
}

static void test_create_file(void){
    struct file_ctl_st ctl = {0};
    printf("请输入欲生成文件的文件名(不超过%d字节)：", MAX_FILE_NAME_LEN);
    scanf("%s", ctl.file_name);
    getchar(); 
    printf("请输入欲生成文件的文件大小(1~64k)：");
    scanf("%d", &ctl.file_size);
    getchar(); 
    signle_pthread_test(_create_file, &ctl);
}

static void _read_file(void *ses,void *p){
    int ret = 0;
    struct file_ctl_st *p_ctl = (struct file_ctl_st *)p;
    ret = SDF_ReadFile(ses, p_ctl->file_name, strlen(p_ctl->file_name), p_ctl->offset, &p_ctl->length, p_ctl->buffer);
    if(SDR_OK != ret){
        Debug_err("SDF_ReadFile failed return 0x%08x \n",ret);
        return ;        
    }  
    printf("实际读出的长度：%d\n", p_ctl->length);
    printf("读出的数据：%s\n", p_ctl->buffer);        
}

static void test_read_file(void){
    char ch = 0;
    struct file_ctl_st ctl = {0};
    unsigned char *buffer = (unsigned char *)malloc(64*1024);
    if(NULL == buffer){
        printf("malloc space to store data err\n");
        return ;
    }
    memset(buffer, 0, 64*1024);
    ctl.buffer = buffer;
    printf("请输入欲读取文件的名称(不超过%d字节)：", MAX_FILE_NAME_LEN);
    scanf("%s", ctl.file_name);
    getchar();
    printf("是否确认此文件已存在(y/n): ");   
    scanf("%c", &ch);
    getchar(); 
    if('n' == ch){
        free(buffer);
        return ;
    }
    printf("请输入读取文件的起始偏移：");
    scanf("%d", &ctl.offset);
    getchar();
    printf("请输入读取文件的长度(最大不超过64K)：");
    scanf("%d", &ctl.length);
    getchar();        
    signle_pthread_test(_read_file, &ctl);
    free(buffer);
}

static void _write_file(void *ses,void *p){
    int ret = 0;
    struct file_ctl_st *p_ctl = (struct file_ctl_st *)p;
    ret = SDF_WriteFile(ses, p_ctl->file_name, strlen(p_ctl->file_name), p_ctl->offset, p_ctl->length, p_ctl->buffer);
    if(SDR_OK != ret){
        Debug_err("SDF_WriteFile failed return 0x%08x \n",ret);
        return ;        
    }    
}

static void test_write_file(void){
    char ch = 0;
    struct file_ctl_st ctl = {0};
    unsigned char *buffer = (unsigned char *)malloc(64*1024);
    if(NULL == buffer){
        printf("malloc space to store data err\n");
        return ;
    }
    memset(buffer, 0, 64*1024);
    ctl.buffer = buffer;
    printf("请输入欲写文件的名称(不超过%d字节)：", MAX_FILE_NAME_LEN);
    scanf("%s", ctl.file_name);
    getchar();
    printf("是否确认此文件已存在(y/n): ");   
    scanf("%c", &ch);
    getchar(); 
    if('n' == ch){
        free(buffer);
        return ;
    }
    printf("请输入欲写入文件的数据：");
    scanf("%s", ctl.buffer);
    getchar();
    ctl.length = strlen(ctl.buffer);
    printf("请输入写文件的起始偏移：");
    scanf("%d", &ctl.offset);
    getchar();       
    signle_pthread_test(_write_file, &ctl);
    free(buffer);
}

static void _delete_file(void *ses,void *p){
    int ret = 0;
    struct file_ctl_st *p_ctl = (struct file_ctl_st *)p;
    ret = SDF_DeleteFile(ses, p_ctl->file_name, strlen(p_ctl->file_name));
    if(SDR_OK != ret){
        Debug_err("SDF_DeleteFile failed return 0x%08x \n",ret);
        return ;        
    }        
}

static void test_delete_file(void){
    char ch = 0;
    struct file_ctl_st ctl = {0};
    printf("请输入欲删除文件的文件名(不超过%d字节)：", MAX_FILE_NAME_LEN);
    scanf("%s", ctl.file_name);
    getchar(); 
    printf("是否确认指定文件已存在(y/n): ");   
    scanf("%c", &ch);
    getchar(); 
    if('n' == ch){
        return ;
    }
    signle_pthread_test(_delete_file, &ctl);
}

static void _enum_file(void *ses,void *p){
    char nameList[1024] = {0};
	unsigned int len, offset = 0, tmp_len = 0;
	char *p_list;
	int nameLen;
	int i;
	int ret = SDF_EnumFiles(ses, nameList, &len);
    if(SDR_OK != ret){
        Debug_err("SDF_EnumFiles failed return 0x%08x \n",ret);
        return ;        
    } 
    tmp_len =  len;
    while(tmp_len > 0){
        printf("%d.%s(%u)\n", *(unsigned int *)(nameList + offset), nameList + offset + 8 , *(unsigned int *)(nameList + offset + 8 + strlen(nameList + offset + 8) + 1));
        offset += 4*3 + strlen(nameList + offset + 8) + 1;
        tmp_len = len - offset;
    }
}

static void test_enum_file(void){
    signle_pthread_test(_enum_file, NULL);
}

struct test_box file_test_box[] = {
    {"创建文件", test_create_file},
    {"读文件", test_read_file},
    {"写文件", test_write_file},
    {"删除文件", test_delete_file},
    {"枚举文件", test_enum_file},
    {"退出", exit_test}
};

struct test_box kek_test_box[] = {
    {"生成KEK", test_generate_kek},
    {"通过索引生成KEK", test_generate_kek_by_index},
    {"在所有位置生成KEK", test_generate_all_kek},
    {"通过索引删除KEK", test_delete_kek_by_index},
    {"查询所有KEK状态", test_get_kek_state},
    {"退出", exit_test}
};

/**
 * @brief: 显示主命令
 * @param []
 * @return []
 */
static void  test_display(struct test_box *box, unsigned int num){
    printf(YELLOW"/**********测试*********************/\n");
    for(int i = 0 ; i < num;i++){
        printf("%d:%s\t",i ,box[i].name);
        if(i & 0x01){
            printf("\n\n");
        }
    }
    printf(NONE"\n");
}

static void run_test(struct test_box *box, unsigned int num){
    int key ; //按键输入值
    p_cmd p_test_cmd;
    while(1){
        test_display(box, num);
        printf("请输入命令号:");
        scanf("%d",&key);
        getchar();
        p_test_cmd = NULL ;
        if(key > num ){
            Debug_err("输入%d没有对应的执行命令\n",key);
            return ;   
        }
        p_test_cmd = box[key].p_test_cmd ; 
        if(p_test_cmd == NULL){
            Debug_err("输入%d没有对应的执行命令\n",key);
            return ;
        } 
        if(p_test_cmd == exit_test){
            break;
        }
        p_test_cmd();  
    } 
}

void test_kek(void){
    run_test(kek_test_box, sizeof(kek_test_box)/sizeof(struct test_box));
    return ;
}

static void test_file_operation(void){
    run_test(file_test_box, sizeof(file_test_box)/sizeof(struct test_box));
    return ;
}

static void __test_iki_calculate_person_key_performance(void *ses,void * p){
    int ret = 0 ;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct iki_caculat_person_key_ctl *ctl = pthread_source->p_data ;
    ECCrefPublicKey PKx = {0}, pubH = {0};
    CkiEnvelope env = {0};
    unsigned char ske_pke[1024] = {0};
    /* 1.导出两个公钥 */
    ret = SDF_ExportEncPublicKey_ECC(ses, ctl->index, &pubH);
    if(ret != SDR_OK){
        Debug_err("SDF_ExportEncPublicKey_ECC failed return 0x%08x \n",ret);
        ctl->status = 1 ;
        return ;
    }
    ret = SDF_ExportSignPublicKey_ECC(ses, ctl->index, &PKx);
    if(ret != SDR_OK){
        Debug_err("SDF_ExportSignPublicKey_ECC failed return 0x%08x \n",ret);
        ctl->status = 1 ;
        return ;
    }
    while_start_time(&ctl->time,ctl->pthread_pcs);
    get_start_time(&ctl->time);
    for(int i = 0 ; i < ctl->pcs ;i++){
        ret = SDF_dmsPCI_CalculatePersonKey(ses, 0, ctl->pid, "ahdms", "2021-11-15", "2022-11-15", &PKx, &pubH, &env, (EnvelopedKeyBlob* )ske_pke);
        if(ret != SDR_OK){
            Debug_err("SDF_dmsPCI_CalculatePersonKey failed return 0x%08x \n",ret);
            ctl->status = 1 ;
            return ;
        }
    }
    get_end_time(&ctl->time,ctl->pthread_pcs);
}

/**
 * @brief:测试SM2加解密接口性能 
 * @param []
 * @return []
 */
static void test_iki_calculate_person_key_performance(void){
    struct iki_caculat_person_key_ctl ctl = {.index = 1};
    char *pid = (char *)malloc(128);
    if(NULL == pid){
        Debug_err("未能分配空间\n");
        return ;
    }
    memset(pid, 0, 128);
    ctl.pid = pid;

    printf("请输入测试的线程数量(1~%d):",MAX_PTHREAD_T);
    scanf("%d",&ctl.pthread_pcs);
    getchar();
    printf("请输入单个线程测试的次数:");
    scanf("%d",&ctl.pcs);
    getchar();
    printf("请输入用于密钥生产的实体标识：");
    scanf("%s", ctl.pid);
    ctl.pid_len = strlen(ctl.pid);

    pthread_mutex_init(&ctl.time.mutex,NULL);
    ctl.time.start = 1 ;
    mult_pthread_test(__test_iki_calculate_person_key_performance,(void *)&ctl); 
    if(ctl.status !=0 ){
        Debug_err("函数返回错误\n");  
        free(pid);
        return ;
    }
    double  performace_tps = ((long)ctl.pthread_pcs*ctl.pcs*1000)/cal_time_ms(&ctl.time.g_start,&ctl.time.g_end) ;
    Printf_with_color(BLUE,"IKI根据标识计算个人密钥对性能%f(tps)\n",performace_tps);  
    free(pid);
}

static void __test_caculate_skid_and_sign_performance(void *ses,void * p){
    int ret = 0 ;
    struct pthread_test_src *pthread_source = (struct pthread_test_src *)(p) ;
    struct skid_sign_ctl *ctl = pthread_source->p_data ;
    unsigned char *data = (unsigned char *)malloc(ctl->data_len*2);
    if(NULL == data){
        Debug_err("为分配足够空间\n");
        return ;
    }
    ECCSignature signature = {0};
    /* 产生随机数作为待签名值 */
    ret = SDF_GenerateRandom(ses, ctl->data_len, data);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateRandom failed return 0x%08x \n",ret);
        ctl->status = 1 ;
        free(data);
        return ;
    }
    /*  */
    if(ctl->optimize_flag == 1){
        while_start_time(&ctl->time,ctl->pthread_pcs);
        get_start_time(&ctl->time);
        for(int i = 0 ; i < ctl->pcs ;i++){
            ret = SDF_dmsPCI_IdentifyECCSignForEnvelope(ses, 0, ctl->pid, ctl->pid_len, 
                        "1234567812345678", strlen("1234567812345678"), data, ctl->data_len, &signature);
            if(ret != SDR_OK){
                Debug_err("SDF_dmsPCI_IdentifyECCSignForEnvelope failed return 0x%08x \n",ret);
                ctl->status = 1 ;
                free(data);
                return ;
            }
        }
        get_end_time(&ctl->time,ctl->pthread_pcs);
    }
    else{
        while_start_time(&ctl->time,ctl->pthread_pcs);
        get_start_time(&ctl->time);
        for(int i = 0 ; i < ctl->pcs ;i++){
            ret = SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize(ses, 0, ctl->pid, ctl->pid_len, 
                        "1234567812345678", strlen("1234567812345678"), data, ctl->data_len, &signature);
            if(ret != SDR_OK){
                Debug_err("SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize failed return 0x%08x \n",ret);
                ctl->status = 1 ;
                free(data);
                return ;
            }
        }
        get_end_time(&ctl->time,ctl->pthread_pcs);        
    }
    free(data);
}

/**
 * @brief:测试计算标识私钥并签名接口性能 
 * @param []
 * @return []
 */
static void test_caculate_skid_and_sign_performance(void){
    struct skid_sign_ctl ctl = {0};
    char *pid = (char *)malloc(128);
    if(NULL == pid){
        Debug_err("未能分配空间\n");
        return ;
    }
    memset(pid, 0, 128);
    ctl.pid = pid;

    printf("请输入测试的线程数量(1~%d):",MAX_PTHREAD_T);
    scanf("%d",&ctl.pthread_pcs);
    getchar();
    printf("请输入单个线程测试的次数:");
    scanf("%d",&ctl.pcs);
    getchar();
    printf("请输入想要测试的IKI版本: \n");
    printf("1. IKI V2.0(升级前)    2. IKI V3.0(升级后) \n");
    scanf("%d", &ctl.optimize_flag);
    if((ctl.optimize_flag != 1) && (ctl.optimize_flag != 2)){
        printf("请选择正确的IKI版本! \n");
        return ;
    }
    printf("请输入实体标识：");
    scanf("%s", ctl.pid);
    getchar();
    ctl.pid_len = strlen(ctl.pid);    
    printf("请输入欲签名的数据长度：");
    scanf("%d", &ctl.data_len);
    getchar();

    pthread_mutex_init(&ctl.time.mutex,NULL);
    ctl.time.start = 1 ;
    mult_pthread_test(__test_caculate_skid_and_sign_performance,(void *)&ctl); 
    if(ctl.status !=0 ){
        Debug_err("函数返回错误\n"); 
        free(pid); 
        return ;
    }
    double  performace_tps = ((long)ctl.pthread_pcs*ctl.pcs*1000)/cal_time_ms(&ctl.time.g_start,&ctl.time.g_end) ;
    Printf_with_color(BLUE,"计算标识私钥并签名接口性能%f(tps)\n",performace_tps);
    free(pid);  
}

void __test_sess_key_agreement(void *ses, void *p){
    int ret = 0;
    struct sess_key_agreement_ctl *ctl = (struct sess_key_agreement_ctl *)p;
    ECCrefPublicKey SponsorPublicKey , SponsorTmpPublicKey;
    ECCrefPublicKey ResponsePublicKey , ResponseTmpPublicKey;
    void *pAgreementHandle = NULL;
    void *SponsorKeyHandle = NULL, *ResponseKeyHandle = NULL;
    /* 1. 发起方产生协商参数 */
    ret = SDF_GenerateAgreementDataWithECC(ses, ctl->sponsor_index, ctl->key_bit_len, ctl->sponsor_id, strlen(ctl->sponsor_id), 
                        &SponsorPublicKey, &SponsorTmpPublicKey, &pAgreementHandle);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateAgreementDataWithECC failed return 0x%08x \n",ret);
        return ;
    } 
    /* 获取私钥使用权限 */
    ret = SDF_GetPrivateKeyAccessRight(ses, ctl->response_index, "dms123456", strlen("dms123456"));
    if(ret != SDR_OK){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x, index: %d \n",ret, ctl->response_index);
        return ;
    }    
    /* 2. 响应方产生协商参数，并计算会话密钥 */
    ret = SDF_GenerateAgreementDataAndKeyWithECC(ses, ctl->response_index, ctl->key_bit_len,
                ctl->response_id, strlen(ctl->response_id), ctl->sponsor_id, strlen(ctl->sponsor_id),
                &SponsorPublicKey, &SponsorTmpPublicKey, &ResponsePublicKey, &ResponseTmpPublicKey, 
                &ResponseKeyHandle);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateAgreementDataAndKeyWithECC failed return 0x%08x \n",ret);
        return ;
    }        
    /* 获取私钥使用权限 */
    ret = SDF_GetPrivateKeyAccessRight(ses, ctl->sponsor_index, "dms123456", strlen("dms123456"));
    if(ret != SDR_OK){
        Debug_err("SDF_GetPrivateKeyAccessRight failed return 0x%08x, index: %d \n",ret, ctl->sponsor_index);
        return ;
    }       
    /* 3. 发起方计算会话密钥 */
    ret = SDF_GenerateKeyWithECC(ses, ctl->response_id, strlen(ctl->response_id), 
                &ResponsePublicKey, &ResponseTmpPublicKey, pAgreementHandle, &SponsorKeyHandle);
    if(ret != SDR_OK){
        Debug_err("SDF_GenerateKeyWithECC failed return 0x%08x \n",ret);
        return ;
    }
}

void test_sess_key_agreement(void){
    char ch = 0;
    struct sess_key_agreement_ctl ctl = {128, 1, "12345678", 1, "12345678"};
    printf("是否进行自动化测试(y/n)：");
    scanf("%d", &ch);
    getchar();
    if('n' == ch){
        printf("请输入发起方固定密钥的索引(0~%d)：", KEY_POOL_SIZE_MAX - 1);
        scanf("&d", &ctl.sponsor_index);
        getchar();
        printf("请输入发起方ID：");
        scanf("%s", ctl.sponsor_id);
        getchar();
        printf("请输入响应方固定密钥的索引(0~%d)：", KEY_POOL_SIZE_MAX - 1);
        scanf("&d", &ctl.response_index);
        getchar();
        printf("请输入响应方ID：");
        scanf("%s", ctl.response_id);
    }
    signle_pthread_test(__test_sess_key_agreement, (void *)&ctl);     
}

void __test_get_device_info(void *ses, void *p){
    int ret = 0;
    DEVICEINFO info = {0};
    ret = SDF_GetDeviceInfo(ses, &info);
    if(ret != SDR_OK){
        Debug_err("SDF_GetDeviceInfo failed return 0x%08x \n",ret);
        return ;
    }
    printf("IssuerName : %s\n",info.IssuerName);
    printf("DeviceName : %s\n",info.DeviceName);
    printf("DeviceSerial : %s\n", info.DeviceSerial);
    printf("DeviceVersion : %x\n",info.DeviceVersion);
    printf("StandardVersion : %x\n",info.StandardVersion);
    printf("AsymAlgAbility[0] : %x\n",info.AsymAlgAbility[0]);
    printf("AsymAlgAbility[1] : %x\n",info.AsymAlgAbility[1]);
    printf("SymAlgAbility : %x\n",info.SymAlgAbility);
    printf("HashAlgAbility : %x\n",info.HashAlgAbility);
    printf("BufferSize : %u\n",info.BufferSize);
}

void test_get_device_info(void){
    signle_pthread_test(__test_get_device_info, NULL);
}

void __test_get_dms_device_info(void *ses, void *p){
    int ret = 0;
    DMS_DEVICEINFO info = {0};
    ret = SDF_dmsPCI_GetDeviceInfo(ses, &info);
    if(ret != SDR_OK){
        Debug_err("SDF_GetDeviceInfo failed return 0x%08x \n",ret);
        return ;
    }
    printf("IssuerName : %s\n",info.IssuerName);
    printf("DeviceName : %s\n",info.DeviceName);
    printf("DeviceSerial : %s\n", info.DeviceSerial);
    printf("DeviceVersion : %x\n",info.DeviceVersion);
    printf("StandardVersion : %x\n",info.StandardVersion);
    printf("AsymAlgAbility[0] : %x\n",info.AsymAlgAbility[0]);
    printf("AsymAlgAbility[1] : %x\n",info.AsymAlgAbility[1]);
    printf("SymAlgAbility : %x\n",info.SymAlgAbility);
    printf("HashAlgAbility : %x\n",info.HashAlgAbility);
    printf("BufferSize : %u\n",info.BufferSize);
    printf("UserFileMaxNum : %u\n",info.UserFileMaxNum);
    printf("ProcessMaxNum : %x\n",info.ProcessMaxNum);
    printf("SessionMaxNum : %u\n",info.SessionMaxNum);
    printf("SessionTimeout_Sec : %us\n",info.SessionTimeout_Sec);
    printf("SessionKeyMaxNum : %x\n",info.SessionKeyMaxNum);
    printf("AsymKeyContainerMaxNum : %u\n",info.AsymKeyContainerMaxNum);
    printf("SymKeyMaxNum : %u\n",info.SymKeyMaxNum);
    printf("state: %x\n",info.State);
    printf("type: %x\n",info.Type);
}

void test_get_dms_device_info(void){
    signle_pthread_test(__test_get_dms_device_info, NULL);
}

void __test_generate_key_by_EPK(void *ses, void *p){
    int ret = 0;
    unsigned int index = 1,count = 0;
    void *sesskey_handle = NULL;
    ECCrefPublicKey pubkey = {0};
    unsigned char cipher[512] = {0};
    ECCCipher *p_cipher = (ECCCipher *)cipher;
    /* 导出加密公钥 */
    while(1){
        //count++;
      //  printf("count : %u\n", count);
        ret = SDF_ExportEncPublicKey_ECC(ses, index, &pubkey);
        if(SDR_OK != ret){
            Debug_err("SDF_ExportEncPublicKey_ECC failed return 0x%08x \n",ret);
            return ;
        }
        //print_data_in_hex(pubkey.x, 64, "pubkey.x");
        //print_data_in_hex(pubkey.y, 64, "pubkey.y");
        /* 生成会话密钥并用外部ECC公钥加密导出 */
        ret = SDF_GenerateKeyWithEPK_ECC(ses, 128, SGD_SM2_3, &pubkey, p_cipher, &sesskey_handle);
        if(SDR_OK != ret){
            Debug_err("SDF_GenerateKeyWithEPK_ECC failed return 0x%08x \n",ret);
            return ;
        }  
    }
    //print_data_in_hex(p_cipher->C, p_cipher->L, "sm4 cipher");  
    //print_data_in_hex(p_cipher->M, 32, "hash");
}

void test_generate_key_by_EPK(void){
    signle_pthread_test(__test_generate_key_by_EPK, NULL);
}

struct test_box test_box[] = {
    {"会话测试",test_session},
    { "测试随机数",test_random},
    {"生成ecc密钥对并明文导出的性能",test_generate_ecc_key_pair},
    {"生成PKI密钥对",test_set_ecc_key_pair},
    {"IKI个人密钥生产测试", test_generate_iki_person_key},
    {"根据标识计算标识密钥对测试", test_calculate_skid_pkid},
    {"导出导入公钥矩阵测试", test_export_import_pub_matrix},
    {"获取密钥对的状态位",test_get_key_pairs_state},
    {"SM4算法测试",test_sm4},
    {"测试SM2加解密运算性能",test_sm2_enc_dec},
    {"测试签名验签性能",test_sm2},
    {"生成公私钥矩阵",test_generate_key_matrix},
    {"pcie密码卡初始化", pcie_card_init},
    {"清空密钥位", test_clear_container},
    {"修改私钥使用权限码", test_change_key_password},
    {"修改设备PIN码", test_change_device_pin},
    {"测试普通密钥备份与恢复", test_key_backup_and_recovery},
    {"测试三五门限备份与恢复", test_key_backup_and_recovery_threshold},
    {"算法自检", test_self},
    {"用户文件测试", test_file_operation},
    {"KEK相关运算测试", test_kek},
    {"测试根据标识计算个人密钥对接口性能", test_iki_calculate_person_key_performance},
    {"测试计算标识私钥并签名接口性能", test_caculate_skid_and_sign_performance},
    {"SM3算法测试",test_sm3},
    {"密钥协商测试", test_sess_key_agreement},
    {"获取协议标准设备信息", test_get_device_info},
    {"获取完整设备信息", test_get_dms_device_info},
    {"生成会话密钥并用外部ECC公钥加密导出", test_generate_key_by_EPK}
};

/**
 * @brief: 
 * @param [int] argv
 * @param [char] *argc
 * @return []
 */
int main(int argv,char *argc[]){
     p_cmd p_test_cmd;
    /*初始化*/
    if(0!=test_init()){
        Debug_err("init error !\n");
        return -1 ;
    }
    run_test(test_box, sizeof(test_box)/sizeof(struct test_box));
    return  0 ;
}