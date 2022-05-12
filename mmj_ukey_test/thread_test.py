#!/usr/bin/python3
import os
import configparser
import sys
import time
from ctypes import *
from ctypes.util import *
import threading

# ****************数据长度定义************************
MAX_IV_LEN = 32  # 初始化向量的最大长度
MAX_FILE_NAME_LEN = 32  # 文件名最大长度
MAX_CONTAINER_NAME_LEN = 128  # 容器名最大长度
MIN_PIN_LEN = 6  # 最小的PIN长度
MAX_RSA_MODULUS_LEN = 256  # RSA算法模数的最大长度
MAX_RSA_EXPONENT_LEN = 4  # RSA算法指数的最大长度
ECC_MAX_XCOORDINATE_BITS_LEN = 512  # ECC算法X座标的最大长度
ECC_MAX_YCOORDINATE_BITS_LEN = 512  # ECC算法Y座标的最大长度
ECC_MAX_MODULUS_BITS_LEN = 512  # ECC算法模数的最大长度
RSAref_MAX_BITS = 2048
RSAref_MAX_LEN = ((RSAref_MAX_BITS + 7) / 8)
RSAref_MAX_PBITS = ((RSAref_MAX_BITS + 1) / 2)
RSAref_MAX_PLEN = ((RSAref_MAX_PBITS + 7) / 8)
SM3_BLOCK_SIZE = 64
SM3_DIGEST_SIZE = 32
ECCref_MAX_BITS = 512
ECCref_MAX_LEN = int((ECCref_MAX_BITS + 7) / 8)

# ******************算法标识符**************************
SGD_SM4_ECB = 0x00000401  # SMS4算法ECB加密模式
SGD_SM4_CBC = 0x00000402  # SMS4算法CBC加密模式
SGD_SM4_OFB = 0x00000408  # SMS4算法OFB加密模式
SGD_SM4_MAC = 0x00000410  # SMS4算法MAC运算
SGD_SM4 = 0x00000400
SGD_ECB = 0x00000001
SGD_CBC = 0x00000002
# ******************非对称算法标识************************
SGD_SM2 = 0x00020100  # SM2椭圆曲线密码算法
SGD_SM2_1 = 0x00020200  # SM2椭圆曲线签名算法
SGD_SM2_2 = 0x00020400  # SM2椭圆曲线密钥交换协议
SGD_SM2_3 = 0x00020800  # SM2椭圆曲线加密算法
# ******************杂凑算法标识**************************
SGD_SM3 = 0x00000001  # SM3杂凑算法
# ******************签名算法标识**************************
SGD_SM3_SM2 = 0x00020201


arr16 = c_ubyte * 16
arr32 = c_ubyte * 32
arr64 = c_ubyte * 64
arr1024 = c_ubyte * 1024
uiKeyBits = 256




# ECC公钥数据结构
class ECCrefPublicKey(Structure):
    _fields_ = [
        ('bits', c_uint),
        ('x', c_ubyte * ECCref_MAX_LEN),
        ('y', c_ubyte * ECCref_MAX_LEN)]


# ECC私钥数据结构
class ECCrefPrivateKey(Structure):
    _fields_ = [
        ('bits', c_uint),
        ('K', c_ubyte * ECCref_MAX_LEN)]


# ECC加密数据结构
class ECCCipher(Structure):
    _fields_ = [
        ('x', c_ubyte * ECCref_MAX_LEN),
        ('y', c_ubyte * ECCref_MAX_LEN),
        ('M', c_ubyte * 32),
        ('L', c_uint),
        ('C', c_ubyte * 1)]


# ECC签名数据结构
class ECCSignature(Structure):
    _fields_ = [
        ('r', c_ubyte * ECCref_MAX_LEN),
        ('s', c_ubyte * ECCref_MAX_LEN)]


# ECC加密密钥对保护结构
class EnvelopedKeyBlob(Structure):
    _fields_ = [
        ('Version', c_ulong),
        ('ulSymmAlgID', c_ulong),
        ('ECCCipehrBlob', ECCCipher),
        ('PubKey', ECCrefPublicKey),
        ('cbEncryptedPrivKey', c_ubyte * 64)]



hDeviceHandle = c_void_p()

def sign(testnum):
    hSessionHandle = c_void_p()
    pucSignature = ECCSignature()
    pucPublicKey = ECCrefPublicKey()
    pucPassword = "dms123456"
    uiPwdLength = 9
    hashData = arr32(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
              0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a)
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
    if ret != 0:
        print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword.encode(), uiPwdLength)
    if ret != 0:
        print("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)
        return -1
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_InternalSign_ECC(hSessionHandle, 1, hashData, 32, byref(pucSignature))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_InternalSign_ECC fail, ret = 0x%08x" % ret)
        if (i % 100) == 0:
            print("\r", end="")
            print("progress: {:.0%}".format(i/testnum), end='')
            sys.stdout.flush()

    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("")
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def verify(testnum):
    hSessionHandle = c_void_p()
    pucSignature = ECCSignature()
    pucPublicKey = ECCrefPublicKey()
    pucPassword = "dms123456"
    uiPwdLength = 9
    hashData = arr32(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
              0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a)
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
    if ret != 0:
        print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword.encode(), uiPwdLength)
    if ret != 0:
        print("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_InternalSign_ECC(hSessionHandle, 1, hashData, 32, byref(pucSignature))
    if ret != 0:
        print("SDF_InternalSign_ECC fail, ret = 0x%08x" % ret)
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_InternalVerify_ECC(hSessionHandle, 1, hashData, 32, byref(pucSignature))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_InternalVerify_ECC fail, ret = 0x%08x" % ret)
        # if (i % 100) == 0:
        #      print("·", end='')
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def calculatePersonKey(testnum):
    hSessionHandle = c_void_p()
    pucPublicKey = ECCrefPublicKey()
    pucIdentify = 'dms123456'
    uiRegion = 1
    pucLicenceIssuingAuthority = 'ahdms'
    pucTakeEffectDate = '2020-06-24'
    pucLoseEffectDate = '2022-06-24'
    pucPke = ECCrefPublicKey()
    pucPks = ECCrefPublicKey()
    pSke = EnvelopedKeyBlob()
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
    if ret != 0:
        print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        return -1
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_dmsPCI_CalculatePersonKey(hSessionHandle, uiRegion,
                                               pucIdentify.encode(),
                                               pucLicenceIssuingAuthority.encode(),
                                               pucTakeEffectDate.encode(),
                                               pucLoseEffectDate.encode(),
                                               byref(pucPublicKey), byref(pucPublicKey),
                                               byref(pucPke), byref(pucPks), byref(pSke))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_dmsPCI_CalculatePersonKey fail, ret = 0x%08x" % ret)
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def externalVerify(testnum):
    hSessionHandle = c_void_p()
    pucSignature = ECCSignature()
    pucPublicKey = ECCrefPublicKey()
    pucPassword = "dms123456"
    uiPwdLength = 9
    hashData = arr32(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
              0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a)
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
    if ret != 0:
        print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword.encode(), uiPwdLength)
    if ret != 0:
        print("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_InternalSign_ECC(hSessionHandle, 1, hashData, 32, byref(pucSignature))
    if ret != 0:
        print("SDF_InternalSign_ECC fail, ret = 0x%08x" % ret)
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, byref(pucPublicKey), hashData, 32, byref(pucSignature))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_ExternalVerify_ECC fail, ret = 0x%08x" % ret)
        # if (i % 100) == 0:
        #      print("·", end='')
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def externalEncrypt(testnum):
    hSessionHandle = c_void_p()
    pucPublicKey = ECCrefPublicKey()
    pucEncData = (c_ubyte * 180)()
    hashData = arr16(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda)
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
    if ret != 0:
        print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        return -1
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_ExternalEncrypt_ECC(hSessionHandle, SGD_SM2_3, byref(pucPublicKey), hashData, 16, pucEncData)
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_ExternalEncrypt_ECC fail, ret = 0x%08x" % ret)
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def internalDecrypt(testnum):
    hSessionHandle = c_void_p()
    symKeyHandle = c_void_p()
    phKeyHandle = c_void_p()
    pucPublicKey = ECCrefPublicKey()
    pCipherKey = (c_ubyte * 196)()
    pucPassword = "dms123456"
    uiPwdLength = 9
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, 1, 128, pCipherKey, byref(symKeyHandle))
    if ret != 0:
        print("SDF_GenerateKeyWithIPK_ECC fail, ret = 0x%08x" % ret)
    ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, 1, pucPassword.encode(), uiPwdLength)
    if ret != 0:
        print("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)
        return -1
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_ImportKeyWithISK_ECC(hSessionHandle, 1, pCipherKey, byref(phKeyHandle))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_ImportKeyWithISK_ECC fail, ret = 0x%08x" % ret)
        ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
        if ret != 0:
            print("SDF_DestroyKey phKeyHandle fail, ret = 0x%08x" % ret)
    ret = gm.SDF_DestroyKey(hSessionHandle, symKeyHandle)
    if ret != 0:
        print("SDF_DestroyKey symKeyHandle fail, ret = 0x%08x" % ret)
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def sm4Encrypt(testnum):
    hSessionHandle = c_void_p()
    symKeyHandle = c_void_p()
    pucPublicKey = ECCrefPublicKey()
    pCipherKey = (c_ubyte * 180)()
    nEncInSize = 1024 * 16
    pucIndata = (c_ubyte * nEncInSize)()
    nEncOutLen = 1024 * 16
    pucEncOutData = (c_ubyte * nEncOutLen)()
    pucIV = (c_ubyte * 16)()

    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    print(" hSessionHandle ID = %s" % hSessionHandle.value)
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GenerateRandom(hSessionHandle, nEncInSize, pucIndata)
    if ret != 0:
        print("SDF_GenerateRandom fail, ret = 0x%08x" % ret)
    ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, 1, 128, pCipherKey, byref(symKeyHandle))
    if ret != 0:
        print("SDF_GenerateKeyWithIPK_ECC fail, ret = 0x%08x" % ret)
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_Encrypt(hSessionHandle, symKeyHandle, SGD_SM4_ECB, pucIV, pucIndata, nEncInSize, pucEncOutData, byref(c_uint(nEncOutLen)))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_Encrypt fail, ret = 0x%08x" % ret)
    ret = gm.SDF_DestroyKey(hSessionHandle, symKeyHandle)
    if ret != 0:
        print("SDF_DestroyKey symKeyHandle fail, ret = 0x%08x" % ret)
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def sm4Decrypt(testnum):
    hSessionHandle = c_void_p()
    symKeyHandle = c_void_p()
    pucPublicKey = ECCrefPublicKey()
    pCipherKey = (c_ubyte * 180)()
    nEncInSize = 1024 * 16
    pucIndata = (c_ubyte * nEncInSize)()
    nEncOutLen = 1024 * 16
    pucEncOutData = (c_ubyte * nEncOutLen)()
    nDecOutSize = 1024 * 16
    pucDecOutData = (c_ubyte * nDecOutSize)()
    pucIV = (c_ubyte * 16)()
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GenerateRandom(hSessionHandle, nEncInSize, pucIndata)
    if ret != 0:
        print("SDF_GenerateRandom fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, 1, 128, pCipherKey, byref(symKeyHandle))
    if ret != 0:
        print("SDF_GenerateKeyWithIPK_ECC fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_Encrypt(hSessionHandle, symKeyHandle, SGD_SM4_ECB, pucIV, pucIndata, nEncInSize, pucEncOutData, byref(c_uint(nEncOutLen)))
    if ret != 0:
        print("SDF_Encrypt fail, ret = 0x%08x" % ret)
        return -1
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_Decrypt(hSessionHandle, symKeyHandle, SGD_SM4_ECB, pucIV, pucEncOutData, nEncOutLen, pucDecOutData, byref(c_uint(nDecOutSize)))
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_Encrypt fail, ret = 0x%08x" % ret)
        for j in range(nDecOutSize):
            if pucIndata[j] != pucDecOutData[j]:
                print("DecData is different from EncData!")
    ret = gm.SDF_DestroyKey(hSessionHandle, symKeyHandle)
    if ret != 0:
        print("SDF_DestroyKey symKeyHandle fail, ret = 0x%08x" % ret)
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def sm3Hash(testnum):
    hSessionHandle = c_void_p()
    symKeyHandle = c_void_p()
    pucPublicKey = ECCrefPublicKey()
    pucID = 'abcd1234'
    uiIDLength = 8
    pucHash = (c_ubyte * 32)()
    hashLen = 0
    hashIndataLen = 1024 * 16
    hashIndata = (c_ubyte * hashIndataLen)()
    total_time = 0
    ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
    if ret != 0:
        print("SDF_OpenSession fail, ret = 0x%08x" % ret)
        return -1
    ret = gm.SDF_GenerateRandom(hSessionHandle, hashIndataLen, hashIndata)
    if ret != 0:
        print("SDF_GenerateRandom fail, ret = 0x%08x" % ret)
    ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
    if ret != 0:
        print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        return -1
    for i in range(testnum):
        start_time = time.time_ns() / 1000
        ret = gm.SDF_HashInit(hSessionHandle, SGD_SM3, byref(pucPublicKey), pucID, uiIDLength)
        if ret != 0:
            print("SDF_HashInit fail, ret = 0x%08x" % ret)
            continue
        ret = gm.SDF_HashUpdate(hSessionHandle, hashIndata, hashIndataLen);
        if ret != 0:
            print("SDF_HashUpdate fail, ret = 0x%08x" % ret)
            continue
        ret = gm.SDF_HashFinal(hSessionHandle, pucHash, byref(c_uint(hashLen)))
        if ret != 0:
            print("SDF_HashFinal fail, ret = 0x%08x" % ret)
            continue;
        end_time = time.time_ns() / 1000
        if ret == 0:
            total_time += (end_time - start_time)
        else:
            print("SDF_Encrypt fail, ret = 0x%08x" % ret)
    ret = gm.SDF_CloseSession(hSessionHandle)
    if ret != 0:
        print("SDF_CloseSession fail, ret = 0x%08x" % ret)
    print("test_num %d cnt, total time = %d us"%( int(testnum), total_time,))
    total_time = 0

def testSign():
    print('testSign is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=sign, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testVerify():
    print('testVerify is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=verify, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testcalculatePersonKey():
    print('testcalculatePersonKey is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=calculatePersonKey, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testExternalVerify():
    print('testExternalVerify is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=externalVerify, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testExternalEncrypt():
    print('testExternalEncrypt is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=externalEncrypt, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testInternalDecrypt():
    print('testInternalDecrypt is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=internalDecrypt, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testsm4Encrypt():
    print('testsm4Encrypt is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=sm4Encrypt, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testsm4Decrypt():
    print('testsm4Decrypt is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=sm4Decrypt, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

def testsm3Hash():
    print('testsm3Hash is to start......')
    thread_list = []
    thread_num = int(input('please input the thread_num: '))
    testnum = int(input('please input the testnum: '))
    # create threads
    for i in range(thread_num):
        t = threading.Thread(target=sm3Hash, args=(testnum,))
        thread_list.append(t)
    for t in thread_list:
        t.start()
    for i in thread_list:
        t.join()

switch = {
    "1": testSign,
    "2": testVerify,
    "3": testcalculatePersonKey,
    "4": testExternalVerify,
    "5": testExternalEncrypt,
    "6": testInternalDecrypt,
    "7": testsm4Encrypt,
    "8": testsm4Decrypt,
    "9": testsm3Hash
    }

if __name__ == '__main__':
    gm = WinDLL('CipherMachineInterface.dll')
    ret = gm.SDF_OpenDevice(byref(hDeviceHandle))
    if ret != 0:
        print("SDF_Opendevice fail, ret = 0x%08x" % ret)
    while True:
        print("\033[1;33minput 1:TestSign\033[0m");
        print("\033[1;33minput 2:TestVerify\033[0m");
        print("\033[1;33minput 3:TestCalculatePersonKey\033[0m");
        print("\033[1;33minput 4:TestExternalVerify\033[0m");
        print("\033[1;33minput 5:TestExternalEncrypt\033[0m");
        print("\033[1;33minput 6:TestInternalDecrypt\033[0m");
        print("\033[1;33minput 7:Testsm4Encrypt\033[0m");
        print("\033[1;33minput 8:Testsm4Decrypt\033[0m");
        print("\033[1;33minput 9:Testsm3Hash\033[0m");
        value = input("\033[11;31mplease input the cmd to test: \033[0m")
        try:
            switch[value]()
        except KeyError as e:
            print('the cmd is error, please input again:')




