#ifndef RANDOM_TEST_H
#define RANDOM_TEST_H

extern void voice(int type);

//出厂随机数检测，该接口成功返回1
extern int FactoryAcceptanceTesting(void *hSession);

//循环检测，该接口成功返回1
extern int CycleTesting(void *hSession);

//上电自检，该接口成功返回1
extern int PowerOnSelfTesing(void* hSession);

//随机数单次自检
extern int Singledetection(void *hSession);


#endif