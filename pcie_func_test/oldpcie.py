#!/usr/bin/python3

from ctypes import *
import os
import sys
gm = cdll.LoadLibrary('./libPciGUOMI.so')

arr1 = c_ubyte * 1
arr2 = c_ubyte * 2
arr4 = c_ubyte * 4
arr16 = c_ubyte * 16
arr32 =  c_ubyte * 32
arr40 = c_ubyte * 40
arr50 = c_ubyte * 50
arr64 = c_ubyte * 64
arr512 = c_ubyte * 512
arr1024 = c_ubyte * 1024
ECCref_MAX_BITS = 512
ECCref_MAX_LEN = int((ECCref_MAX_BITS + 7) / 8)
ECC_MAX_XCOORDINATE_BITS_LEN = 512
ECC_MAX_YCOORDINATE_BITS_LEN = 512
ArrX = c_ubyte*(int(ECC_MAX_XCOORDINATE_BITS_LEN / 8))
ArrY = c_ubyte*(int(ECC_MAX_YCOORDINATE_BITS_LEN / 8))
KEY_POOL_SIZE_MAX = 50000

# ******************算法标识符**************************
SGD_SM1_ECB = 0x00000101  # SM1算法ECB加密模式
SGD_SM1_CBC = 0x00000102  # SM1算法CBC加密模式
SGD_SM1_CFB = 0x00000104  # SM1算法CFB加密模式
SGD_SM1_OFB = 0x00000108  # SM1算法OFB加密模式
SGD_SM1_MAC = 0x00000110  # SM1算法MAC运算
SGD_SSF33_ECB = 0x00000201  # SSF33算法ECB加密模式
SGD_SSF33_CBC = 0x00000202  # SSF33算法CBC加密模式
SGD_SSF33_CFB = 0x00000204  # SSF33算法CFB加密模式
SGD_SSF33_OFB = 0x00000208  # SSF33算法OFB加密模式
SGD_SSF33_MAC = 0x00000210  # SSF33算法MAC运算
SGD_SM4_ECB = 0x00000401  # SMS4算法ECB加密模式
SGD_SM4_CBC = 0x00000402  # SMS4算法CBC加密模式
SGD_SM4_CFB = 0x00000404  # SMS4算法CFB加密模式
SGD_SM4_OFB = 0x00000408  # SMS4算法OFB加密模式
SGD_SM4_MAC = 0x00000410  # SMS4算法MAC运算
SGD_SM4 = 0x00000400
SGD_ECB = 0x00000001
SGD_CBC = 0x00000002
# ******************非对称算法标识************************
SGD_RSA = 0x00010000
SGD_SM2 = 0x00020100  # SM2椭圆曲线密码算法
SGD_SM2_1 = 0x00020200  # SM2椭圆曲线签名算法
SGD_SM2_2 = 0x00020400  # SM2椭圆曲线密钥交换协议
SGD_SM2_3 = 0x00020800  # SM2椭圆曲线加密算法
# ******************杂凑算法标识**************************
SGD_SM3 = 0x00000001  # SM3杂凑算法
SGD_SHA1 = 0x00000002  # SHA1杂凑算法
SGD_SHA256 = 0x00000004  # SHA256杂凑算法
# ******************签名算法标识**************************
SGD_SM3_RSA = 0x00010001
SGD_SHA1_RSA = 0x00010002
SGD_SHA256_RSA = 0x00010004
SGD_SM3_SM2 = 0x00020201


# 设备信息定义
class DEVICEINFO(Structure):
    _fields_ = [
        ('IssuerName', c_ubyte * 40),
        ('DeviceName', c_ubyte * 16),
        ('DeviceSerial', c_ubyte * 16),
        ('DeviceVersion', c_uint),
        ('StandardVersion', c_uint),
        ('AsymAlgAbility', c_uint * 2),
        ('SymAlgAbility', c_uint),
        ('HashAlgAbility', c_uint),
        ('BufferSize', c_uint),
        ('State', c_uint),
        ('Type', c_uint),
]


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


# ECC加密数据，该结构定义在GM/T 0016
class ECCPUBLICKEYBLOB(Structure):
    _fields_ =[('BitLen', c_uint),
               ('XCoordinate', ArrX),
               ('YCoordinate', ArrY)]

# ECC公钥交换数据块，该结构体定义在GM/T 0016
class ECCCIPHERBLOB(Structure):
    _fields_ = [('XCoordinate', ArrX),
                ('YCoordinate', ArrY),
                ('HASH', c_ubyte * 32),
                ('CipherLen', c_uint),
                ('Cipher', c_ubyte * 16)]

# ECC加密密钥对保护结构
class ENVELOPEDKEYBLOB(Structure):
    _fields_ = [
	('ulAsymmAlgID', c_uint),
	('ulSymmAlgID', c_uint),
	('PubKey', ECCPUBLICKEYBLOB),
	('cbEncryptedPriKey', c_ubyte * 64),
	('ECCCipherBlob', ECCCIPHERBLOB)]

# 密钥池结构
class KeyPoolStateInfo(Structure):
    _fields_ = [
        ('uiKeyPoolSize', c_uint),
        ('ucKeyPoolStates', c_ubyte * KEY_POOL_SIZE_MAX)]

testPublic = arr64(0x09,0xF9,0xDF,0x31,0x1E,0x54,0x21,0xA1,0x50,0xDD,0x7D,0x16,0x1E,0x4B,0xC5,0xC6,0x72,0x17,0x9F,0xAD,0x18,0x33,0xFC,0x07,0x6B,0xB0,0x8F,0xF3,0x56,0xF3,0x50,0x20,0xCC,0xEA,0x49,0x0C,0xE2,0x67,0x75,0xA5,0x2D,0xC6,0xEA,0x71,0x8C,0xC1,0xAA,0x60,0x0A,0xED,0x05,0xFB,0xF3,0x5E,0x08,0x4A,0x66,0x32,0xF6,0x07,0x2D,0xA9,0xAD,0x13)
testPoint = arr64(0x1A, 0xB2, 0xAF, 0x2A, 0xF9, 0x64, 0x76, 0xA5, 0xFF, 0x61, 0xF8, 0x50, 0xFB, 0x1D, 0x3F, 0x12, 0x34, 0xEE, 0x04, 0xBA, 0x1B, 0x93, 0x14, 0xA5, 0xD6, 0x28, 0xE0, 0x98, 0xCF, 0xED, 0x40, 0x14,0x0B, 0x5E, 0x03, 0xE8, 0xC5, 0x90, 0x8E, 0x4B, 0xB9, 0xEC, 0x97, 0xF7, 0x69, 0x91, 0xFC, 0x7F, 0x2A, 0x86, 0x52, 0xB5, 0xC4, 0xF5, 0x12, 0x40, 0x31, 0xB0, 0x23, 0x0B, 0x66, 0x3A, 0xDC, 0xE5)

# 全局变量
hDeviceHandle = c_void_p()
hSessionHandle = c_void_p()
phKeyHandle = c_void_p()
phAgreementHandle = c_void_p()
pucKey = ECCCipher()

pucSponsorID = '1234567812345678'
uiSponsorIDLength = 16
pucResponseID = '1234567812345678'
uiResponseIDLength = 16

pucSponsorPublicKey = ECCrefPublicKey()
pucSponsorTmpPublicKey = ECCrefPublicKey()       
pucResponsePublicKey = ECCrefPublicKey()
pucResponseTmpPublicKey = ECCrefPublicKey()

sign = ECCSignature()
Hash  = arr64()
pucData = (c_ubyte * 16384)()
uiDataLength = c_uint()
pucIV = arr16()
pucEncData = (c_ubyte * 16384)()
puiEncDataLength = c_uint()
pucDecData = (c_ubyte * 16384)()
puiDecDataLength = c_uint()

puiMatLen = c_uint(32788)
pucPubMatrix = (c_ubyte * 32790)()


#**********************函数定义开始*************************
def PrintData(itemName, sourceData, dataLength, rowCount):
    if (sourceData ==None) and (rowCount == 0) and (dataLength == 0):
        return -1
    
    if itemName != None:
        print("%s[%d]:"%(itemName, dataLength))
    for i in range(dataLength/rowCount):
        print("%08x" % (i*rowCount))
        for j in range(rowCount):
            print("%02x" % byref(sourceData, i*rowCount + j))
    if dataLength % rowCount ==0:
        return 0
    print("%08x"%((dataLength/rowCount)*rowCount))
    for j in (dataLength%rowCount):
        print("%02x" % byref(sourceData + (dataLength/rowCount)*rowCount + j))
    return 0
                
def SDF_OpenDevice():
	ret = gm.SDF_OpenDevice(byref(hDeviceHandle))
	if ret == 0:
		print("SDF_Opendevice success，ret = " + hex(ret))
	else:
		print("SDF_Opendevice fail，ret = " + hex(ret))


def SDF_OpenDeviceWithCfg():
	pcCfgPath = c_char_p(b'/root/python/')
	ret = gm.SDF_OpenDeviceWithCfg(pcCfgPath, byref(hDeviceHandle))
	if ret == 0:
		print('SDF_OpenDeviceWithCfg success, ret = ' + hex(ret))
	else:
		print('SDF_OpenDeviceWithCfg fail, ret  = ' + hex(ret))

def SDF_CloseDevice():
	ret = gm.SDF_CloseDevice(hDeviceHandle)
	if ret == 0:
		print("SDF_CloseDevice success，ret = " + hex(ret))
	else:
		print("SDF_CloseDevice fail，ret = " + hex(ret))

def SDF_OpenSession():
	ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
	if ret == 0:
		print("SDF_OpenSession success, ret = " + hex(ret))
	else:
		print("SDF_OpenSession fail, ret = " + hex(ret)) 


def SDF_CloseSession():
	ret = gm.SDF_CloseSession(hSessionHandle)
	if ret == 0:
		print("SDF_CloseSession success, ret = " + hex(ret))
	else:
		print("SDF_CloseSession fail, ret = " + hex(ret))

def SDF_GetDeviceInfo():
	pstDeviceInfo = DEVICEINFO()
	ret = gm.SDF_GetDeviceInfo(hSessionHandle, byref(pstDeviceInfo))
	if ret == 0:
		print('SDF_GetDeviceInfo success, ret = ' + hex(ret))
		seq1 = []
		for i in range(40):
			seq1.append(chr(pstDeviceInfo.IssuerName[i]))
		print("IssuerName = %s" % (''.join(seq1)))
		seq2 = []
		for i in range(16):
			seq2.append(chr(pstDeviceInfo.DeviceName[i]))
		print("DeviceName = %s" % (''.join(seq2)))
		seq3 = []
		for i in range(16):
			seq3.append(chr(pstDeviceInfo.DeviceSerial[i]))
		print("DeviceSerial = %s" % (''.join(seq3)))
		print("DeviceVersion = %d" % pstDeviceInfo.DeviceVersion)
		print("StandardVersion = %d" % pstDeviceInfo.StandardVersion)
		print("AsymAlgAbility = 0x%08x, 最大模长 = %d" % (pstDeviceInfo.AsymAlgAbility[0], pstDeviceInfo.AsymAlgAbility[1]))
		print("SymAlgAbility = 0x%08x" % pstDeviceInfo.SymAlgAbility)
		print("HashAlgAbility = 0x%08x" % pstDeviceInfo.HashAlgAbility)
		print("BufferSize = %s" % pstDeviceInfo.BufferSize)
		print("State = %s" % pstDeviceInfo.State)
		print("Type = %s" % pstDeviceInfo.Type)
	else:
		print('SDF_GetDeviceInfo fail, ret = ' + hex(ret))

def SDF_GenerateRandom():
	uiLength = input('please enter random length（1~16K=16384）：')
	pucRandom = (c_ubyte * 65536)()
	ret = gm.SDF_GenerateRandom(hSessionHandle, int(uiLength), pucRandom)
	if ret == 0:
		print('SDF_GenerateRandom success, ret  = ' + hex(ret))
		for i in range(int(uiLength)):
			print(hex(pucRandom[i]), end=' ')
	else:
		print('SDF_GenerateRandom fail ret = ' + hex(ret))	

def SDF_GetPrivateKeyAccessRight():
	uiKeyIndex = input('please enter the index(0~49): ')
	pucPassword = input('please enter the private key access password: ')
	uiPwdLength = len(pucPassword)
	ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, int(uiKeyIndex), pucPassword.encode(), uiPwdLength)
	if ret == 0:
		print('SDF_GetPrivateKeyAccessRight success, ret = ' + hex(ret))
	else:
		print('SDf_GetPrivateKeyAccessRight fail, ret =' + hex(ret)) 
	
def SDF_ReleasePrivateKeyAccessRight():
	uiKeyIndex = input('please enter the index(0~49): ')
	ret = gm.SDF_ReleasePrivateKeyAccessRight(hSessionHandle, int(uiKeyIndex))
	if ret == 0:
		print('SDF_ReleasePrivateKeyAccessRight success, ret = ' + hex(ret))
	else:
		print('SDF_ReleasePrivateKeyAccessRight fail, ret = ' + hex(ret))

def SDF_ExportSignPublicKey_ECC():
	uiKeyIndex = input('please enter the index(0~49): ')
	pucPublicKey = ECCrefPublicKey()
	ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
	if ret == 0:
		print('SDF_ExportSignPublicKey_ECC success, ret = ' + hex(ret))
		print('pucPublicKey.x =')
		for i in range(64):
			print(hex(pucPublicKey.x[i]), end = ' ')
		print('\npucPublicKey.y =')
		for j in range(64):
			print(hex(pucPublicKey.y[j]), end = ' ') 
	else:
		print('SDF_ExportSignPublicKey_ECC fail, ret = ' + hex(ret))

def SDF_ExportEncPublicKey_ECC():
	uiKeyIndex = input('please enter the index(0~49): ')
	pucPublicKey = ECCrefPublicKey()
	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
	if ret == 0:
		print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
		print('pucPublicKey.x =')
		for i in range(64):
			print(hex(pucPublicKey.x[i]), end = ' ')
		print('\npucPublicKey.y =')
		for j in range(64):
			print(hex(pucPublicKey.y[j]), end = ' ')
	else:
		print('SDF_ExportEncPublicKey_ECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyPair_ECC():
	uiKeyBits = input('please input the KeyBits: ')
	uiAlgID = SGD_SM2
	pucPublicKey = ECCrefPublicKey()
	pucPrivateKey = ECCrefPrivateKey()
	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, int(uiKeyBits), byref(pucPublicKey), byref(pucPrivateKey))
	if ret == 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenerateKeyPair_ECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithIPK_ECC():
	uiIPKIndex = input('please input the index：')
	uiKeyBits = input('please input the keybits：')
	ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, int(uiIPKIndex), int(uiKeyBits), byref(pucKey), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithIPK_ECC success, ret = ' + hex(ret))
		print('sessionKey ID: %s'%phKeyHandle.value)
	else:
		print('SDF_GenerateKeyWithIPK_ECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithEPK_ECC():
	uiKeyIndex = input('please input tne index: ')
	uiKeyBits = input('please input the keybits：')
	uiAlgID = SGD_SM2_3 
	pucPublicKey = ECCrefPublicKey()
	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
	if ret == 0:
		print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExportEncPublicKey_ECC fail, ret = ' + hex(ret))
	ret  = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, int(uiKeyBits), uiAlgID, byref(pucPublicKey), byref(pucKey), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithEPK_ECC success, ret = ' + hex(ret))
		print('sessionKey ID: %s'%phKeyHandle.value)
	else:
		print('SDF_GenerateKeyWithEPK_ECC fail ret = ' + hex(ret))

def SDF_ImportKeyWithISK_ECC():
	uiISKIndex = input('please input the index:')
	phKeyHandle = c_void_p()
	ret = gm.SDF_ImportKeyWithISK_ECC(hSessionHandle, int(uiISKIndex), byref(pucKey), byref(phKeyHandle))
	if ret == 0:
		print('SDF_ImportKeyWithISK_ECC success, ret = ' + hex(ret))
		print('sessionKey ID: %s'%phKeyHandle.value)
	else:
		print('SDF_ImportKeyWithISK_ECC fail, ret = ' + hex(ret))

def SDF_GenerateAgreementDataWithECC():
	uiISKIndex = uiKeyIndex = input('please input the index: ')
	uiKeyBits = input('please input the keybits：')
	ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucSponsorPublicKey))
	if ret == 0:
		print('SDF_ExportSignPublicKey_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExportSignPublicKey_ECC fail, ret = ' + hex(ret))
	print(pucSponsorID.encode())
	ret = gm.SDF_GenerateAgreementDataWithECC(hSessionHandle, int(uiISKIndex), int(uiKeyBits), pucSponsorID.encode(), uiSponsorIDLength, byref(pucSponsorPublicKey), byref(pucSponsorTmpPublicKey), byref(phAgreementHandle))
	if ret == 0:
		print('SDF_GenerateAgreementDataWithECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenenrateAgreementDataWithECC fail ,ret = ' + hex(ret))


def SDF_GenerateKeyWithECC():
	phKeyHandle = c_void_p()
	ret = gm.SDF_GenerateKeyWithECC(hSessionHandle, pucResponseID.encode(), uiResponseIDLength, byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey), phAgreementHandle, byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenerateKeyWithECC fail, ret = ' + hex(ret))


def SDF_GenerateAgreementDataAndKeyWithECC():
	uiISKIndex = index = input('please input the index: ')
	uiKeyBits = input('please input the the keybits：')
	phKeyHandle = c_void_p()
	ret = gm.SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, int(uiISKIndex), int(uiKeyBits), pucResponseID.encode(), uiResponseIDLength, pucSponsorID.encode(), uiSponsorIDLength, byref(pucSponsorPublicKey), byref(pucSponsorTmpPublicKey), byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey), byref(phKeyHandle)) 
	if ret == 0:
		print('SDF_GenerateAgreementDataAndKeyWithECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenerateAgreementDataAndKeyWithECC fail, re = ' + hex(ret))


def SDF_ExchangeDigitEnvelopeBaseOnECC():
	KeyBits = input('please input the keybits of exchange: ')
	testPublicKey = ECCrefPublicKey()
	pucPublicKey = ECCrefPublicKey()
	pucEncDataIn = ECCCipher()
	pucEncDataOut = ECCCipher()
	phKeyHandle = c_void_p()
	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 2, byref(testPublicKey))
	if ret == 0:
		print('SDF_ExportSignPublicKey_ECC success index = 2, ret = ' + hex(ret))
	else:
		print('SDF_ExportSignPublicKey_ECC fail index = 2, ret = ' + hex(ret))
	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
	if ret == 0:
		print('SDF_ExportSignPublicKey_ECC success index = 1, ret = ' + hex(ret))
	else:
		print('SDF_ExportSignPublicKey_ECC fail index = 1, ret = ' + hex(ret))
	ret = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, int(KeyBits), SGD_SM2_3, byref(pucPublicKey), byref(pucEncDataIn), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithEPK_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenerateKeyWithEPK_ECC fail ret = ' + hex(ret))
	uiKeyIndex = 1
	uiAlgID = SGD_SM2_3
	ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, uiKeyIndex, uiAlgID, byref(testPublicKey), byref(pucEncDataIn), byref(pucEncDataOut))
	if ret ==  0:
		print('SDF_ExchangeDigitEnvelopeBaseOnECC sucess,  ret = ' + hex(ret))
	else:
		print('SDF_ExchangeDigitEnvelopeBaseOnECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithKEK():
	uiKEKIndex = input('please input the KEK index(1-100): ')
	uiKeyBits = input('please input the keybits(128): ')
	uiAlgID = SGD_SM4_ECB
	global pucKey
	pucKey = (c_ubyte * 1024)()
	puiKeyLength = c_uint()
	phKeyHandle = c_void_p()
	ret = gm.SDF_GenerateKeyWithKEK(hSessionHandle, int(uiKeyBits), uiAlgID, int(uiKEKIndex), pucKey, byref(puiKeyLength), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenenrateKeyWithKEK success, ret = ' + hex(ret))
		print('sessionKey ID: %s'%phKeyHandle.value)
	else:
		print('SDF_GenerateKeyWithKEK fail, ret = ' + hex(ret))

def SDF_ImportKeyWithKEK():	
	uiKEKIndex = input('please input the KEK index(0~9): ')
	puiKeyLength = input('please input the KeyLength(16,32,64): ')
	uiAlgID = SGD_SM4_ECB
	phKeyHandle = c_void_p()
	ret = gm.SDF_ImportKeyWithKEK(hSessionHandle, uiAlgID, int(uiKEKIndex), pucKey, int(puiKeyLength), byref(phKeyHandle))
	if ret == 0:
		print('SDF_ImportKeyWithKEK success, ret = ' + hex(ret))
		print('sessionKey ID: %s'%phKeyHandle.value)
	else:
		print('SDF_ImportKeyWithKEK fail, ret = ' + hex(ret))

def SDF_DestroyKey():
	ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
	if ret == 0:
		print('SDF_DestroyKey success, ret = ' + hex(ret))
	else:
		print('SDF_DestroyKey fail, ret = ' + hex(ret))

def SDF_ImportKey():
        pucKey = arr512()
        uiKeyLength = input('please input session key length(1~64): ')
       	phKeyHandle = c_void_p()
        ret = gm.SDF_GenerateRandom(hSessionHandle, int(uiKeyLength), pucKey)
        if ret != 0:
                print('SDF_GenerateRandom fail, ret  = ' + hex(ret))
	
       	ret = gm.SDF_ImportKey(hSessionHandle, pucKey, int(uiKeyLength), byref(phKeyHandle))
        if ret == 0:
                print('SDF_ImportKey success, ret = ' + hex(ret))
        else:
                print('SDF_ImportKey fail, ret = ' + hex(ret))


def SDF_InternalSign_ECC():
	uiIndex = input('please input the index: ')
	memset(Hash, 0x11, sizeof(Hash))
	HashLength = 32
	ret = gm.SDF_InternalSign_ECC(hSessionHandle, int(uiIndex), Hash, HashLength, byref(sign))
	if ret == 0:
		print('SDF_InternalSign_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_InternalSign_ECC fail, ret = ' + hex(ret))

def SDF_InternalVerify_ECC():
	uiIndex = input('please input the index: ')
	HashLength = 32
	memset(Hash, 0x11, sizeof(Hash))
	ret = gm.SDF_InternalVerify_ECC(hSessionHandle,int(uiIndex), Hash, HashLength, byref(sign))
	if ret == 0:
		print('SDF_InternalVerify_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_InternalVerify_ECC fail, ret = ' + hex(ret))


def SDF_ExternalVerify_ECC():
	uiIndex = input('please input the index: ')
	memset(Hash, 0x11, sizeof(Hash))
	HashLength = 32
	pbBlob = ECCrefPublicKey()
	ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiIndex), byref(pbBlob))
	if ret == 0:
		print('SDF_ExportSignPublicKey_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExportSignPublicKey_ECC fail , ret = ' + hex(ret))
	ret = gm.SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, byref(pbBlob), Hash, HashLength, byref(sign))
	if ret ==0:
		print('SDF_ExternalVerify_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExternalVerify_ECC fail, ret = ' + hex(ret))


def SDF_ExternalEncrypt_ECC():
	uiIndex = input('please input the index: ')
	HashLength = input('please input the SM2 data leng: ')
	pucPublickey = ECCrefPublicKey()
	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiIndex), byref(pucPublickey))
	if ret == 0:
		print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExportEncPublicKey_ECC fail , ret = ' + hex(ret))
	uiAlgID = SGD_SM2_3
	memset(Hash, 0x11, sizeof(Hash))
	pucEncData = ECCCipher()
	ret = gm.SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, byref(pucPublickey), Hash, int(HashLength), byref(pucEncData))
	if ret ==0:
		print('SDF_ExternalEncrypt_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExternalEncrypt_ECC fail, ret = ' + hex(ret))


def SDF_HashInit():
        uiKeyIndex = input('please input the index:')
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
        if ret == 0:
            print("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            print("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        AlgID = SGD_SM3
        pucID = "12345678"
        uiIDLength = 32
        ret = gm.SDF_HashInit(hSessionHandle, AlgID, byref(pucPublicKey), pucID, uiIDLength)
        if ret == 0:
            print("SDF_HashInit success, ret = 0x%x" % ret)
        else:
            print("SDF_HashInit fail, ret = 0x%08x" % ret)	


def SDF_HashUpdate():
	inData = input('please input your data: ')
	uiDataLength = len(inData)
	ret = gm.SDF_HashUpdate(hSessionHandle, pucData, uiDataLength)
	if ret ==0:
		print('SDF_HashUpdate success, ret = ' + hex(ret))
	else:
		print('SDF_HashUpdate fail, ret = ' + hex(ret))


def SDF_HashFinal():
	pucHash = arr32()
	uiHashLength = c_uint()
	ret = gm.SDF_HashFinal(hSessionHandle, pucHash, byref(uiHashLength))
	if ret ==0:
		print('SDF_HashFinal success, ret = ' + hex(ret))
		print('Hash Value: %s'%pucHash[:])
	else:
		print('SDF_HashFinal fail, ret ' + hex(ret))

def SDF_Encrypt():
	uiDataLength = int(input('please input your data length(< 1024): '))
	for i in range(uiDataLength):
		pucData[i] = int(i % 256)
	print('加密原文：%s'%pucData[0:uiDataLength])
	uiAlgID = SGD_SM4_ECB
	memset(pucIV, 0x00, sizeof(pucIV))
	ret = gm.SDF_Encrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, byref(puiEncDataLength))
	if ret == 0:
		print('SDF_Encrypt sucess, ret = ' + hex(ret))
	else:
		print('SDF_Encrypt fail, ret = ' + hex(ret))

def SDF_Decrypt():
	uiAlgID = SGD_SM4_ECB
	plain = arr1024()
	plainLength = c_uint()
	ret = gm.SDF_Decrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucEncData, puiEncDataLength, plain, byref(plainLength))
	if ret == 0:
		print('SDF_Decrypt success, ret = ' + hex(ret))
		print('解密原文：%s'%plain[0:plainLength.value])
	else:
		print('SDF_Decrypt fail, ret = ' + hex(ret))

def SDF_CalculateMAC():

	uiAlgID = SGD_SM4_MAC
	memset(pucIV, 0x00, sizeof(pucIV))
	uiInDataLength = int(input('please input your data length(1~1024):'))
	pucInData = arr1024()
	for i in range(uiInDataLength):
		pucInData[i] = int(i % 256)
	print('MAC原文：%s'%pucInData[0:uiInDataLength])
	pucMAC = arr4()
	uiMACLength = c_uint()
	ret = gm.SDF_CalculateMAC(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucInData, uiInDataLength, pucMAC, byref(uiMACLength))
	if ret == 0:
		print('SDF_CalcaluteMAC success, ret = ' + hex(ret))
		print('MAC Value: %s'%pucMAC[:])
	else:
		print('SDF_CalcaluteMAC fail, ret = ' + hex(ret))


def SDF_CreateFile():
	pucFileName = input('please input the file name(length < 32 Bytes): ')
	uiNameLen = len(pucFileName)
	uiFileSize  = input('please input the file size(length < 32K Bytes): ')
	print('pucFileName = %s, uiNameLen = %d , uiFileSize = %d'%(pucFileName, uiNameLen, int(uiFileSize)))
	ret = gm.SDF_CreateFile(hSessionHandle, pucFileName.encode(), uiNameLen, int(uiFileSize))
	if ret == 0:
		print('SDF_CreateFile success, ret = ' + hex(ret))
	else:
		print('SDF_CreateFile fail, ret = ' + hex(ret))


def SDF_ReadFile():
	pucFileName = input('please input the file name(length < 32 Bytes): ')
	uiNameLen = len(pucFileName)
	uiOffset  = int(input('please input the data offset address:'))
	puiFileLength = int(input('please input the read data len:'))
	pucBuffer = (c_ubyte * puiFileLength)()
	ret = gm.SDF_ReadFile(hSessionHandle, pucFileName.encode(), uiNameLen, uiOffset, byref(c_uint(puiFileLength)), pucBuffer)
	if ret == 0:
		print('SDF_ReadFile success, ret = ' + hex(ret))
		print(pucBuffer[:])
	else:
		print('SDF_ReadFile fail, ret = ' + hex(ret))


def SDF_WriteFile():
	pucFileName = input('please input the file name(length < 32 Bytes): ')
	uiNameLen = len(pucFileName)
	uiOffset  = int(input('please input the data offset address:'))
	puiFileLength = int(input('please input the write data:'))
	pucBuffer = (c_ubyte * puiFileLength)()
	for i in range(puiFileLength):
                pucBuffer[i] = int(i % 256)
	ret = gm.SDF_WriteFile(hSessionHandle, pucFileName.encode(), uiNameLen, uiOffset, puiFileLength, pucBuffer)
	if ret == 0:
		print('SDF_WriteFile success, ret = ' + hex(ret))
	else:
                print('SDF_WriteFile fail, ret = ' + hex(ret))


def SDF_DeleteFile():
	pucFileName = input('please input the file name:')
	nameLen  = len(pucFileName)
	ret = gm.SDF_DeleteFile(hSessionHandle, pucFileName.encode(), nameLen)
	if ret == 0:
		print('SDF_DeleteFile success, ret = ' + hex(ret))
	else:
		print('SDF_DeleteFile fail, ret  = ' + hex(ret))

def SDF_EnumFiles():
	nameList = (c_byte * 1024)()
	nameLen = c_uint()
	ret = gm.SDF_EnumFiles(hSessionHandle, nameList, byref(nameLen))
	if ret == 0:
		print('SDF_EnumFiles success, ret = ' + hex(ret))
		seq = []
		for i in range(nameLen.value):
			seq.append(chr(nameList[i]))
		print(seq)	
	else:
		print('SDF_EnumFiles fail, ret = ' + hex(ret))


def dmsPCI_PCICardInit():
	pin = input("please input pin: ")
	pinLen = len(pin)
	pciCardType = input("please input the pciCard Type(1:KMC  2:IMC): ")
	ret = gm.dmsPCI_PCICardInit(hSessionHandle, int(pciCardType), int(pinLen), pin.encode())
	if ret == 0:
		print('dmsPCI_PCICardInit success, ret = ' + hex(ret))
	else:
		print('dmsPCI_PCICardInit fail, ret  = ' + hex(ret))


def dmsPCI_PCICardGenerateMatrix():
	ret = gm.dmsPCI_PCICardGenerateMatrix(hSessionHandle)
	if ret == 0:
		print("dmsPCI_PCICardGenerateMatrix success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_PCICardGenerateMatrix fail, ret = 0x%08x" % ret)


def dmsPCI_TestSelf():
	ret = gm.SDF_dmsPCI_TestSelf(hSessionHandle)
	if ret == 0:
		print("dmsPCI_TestSelf success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_TestSelf fail, ret = 0x%08x" % ret)


def dmsPCI_ImportPubMatrix():
	#pucPubMatrix[4] = 10
	print("待导入公钥矩阵数据：\n%s" % pucPubMatrix[:])
	ret = gm.dmsPCI_ImportPubMatrix(hSessionHandle, pucPubMatrix, puiMatLen.value)
	if ret == 0:
		print("dmsPCI_ImportPubMatrix success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_ImportPubMatrix fail, ret = 0x%08x" % ret)


def dmsPCI_ExportPubMatrix():
	ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, pucPubMatrix, byref(puiMatLen))
	if ret == 0:
		print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
		print("公钥矩阵数据: \n%s" % pucPubMatrix[:])
		print("公钥矩阵长度：\n%s" % puiMatLen.value)
	else:
		print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)


def dmsPCI_SVSGetKeyPoolState():
	pKeyPoolStInfo = KeyPoolStateInfo()
	ret = gm.dmsPCI_SVSGetKeyPoolState(hSessionHandle, byref(pKeyPoolStInfo))
	if ret == 0:
		print("dmsPCI_SVSGetKeyPoolState success, ret = 0x%x" % ret)
		print("密钥池状态：\n%s" % pKeyPoolStInfo.ucKeyPoolStates[:])
	else:
		print("dmsPCI_SVSGetKeyPoolState fail, ret = 0x%08x" % ret)

def dmsPCI_SVSSetKeyIndex():
	uiKeyIndex = input('please input the KeyIndex(0~49): ')
	ret = gm.dmsPCI_SVSSetKeyIndex(hSessionHandle, int(uiKeyIndex))
	if ret == 0:
		print("dmsPCI_SVSSetKeyIndex success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_SVSSetKeyIndex fail, ret = 0x%08x" % ret) 


pucPublicKey = (ECCrefPublicKey * 2)()
def dmsPCI_GenECCKeyPair():
        KeyLen = input('please input the KeyLen: ')
        ret = gm.dmsPCI_GenECCKeyPair(hSessionHandle, int(KeyLen), pucPublicKey)
        if ret == 0:
                print("dmsPCI_GenECCKeyPair success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_GenECCKeyPair fail, ret = 0x%08x" % ret)



def dmsPCI_CalculatePersonKey():
        uiRegion = int(input('please input the Region(0~255): '))
        pucIdentify = input('please input the Identify(max=128): ')
        uiIdentifyLen = len(pucIdentify)
        pucLicenceIssuingAuthority = input('please input the LicenceIssuingAuthority(max=128): ')
        uiLicenceIssuingAuthorityLen = len(pucLicenceIssuingAuthority)
        pucTakeEffectDate = input('please input the TakeEffectDate(1~63): ')
        uiTakeEffectDateLen = len(pucTakeEffectDate)
        pucLoseEffectDate = input('please input the LoseEffectDate(1~63): ')
        uiLoseEffectDateLen = len(pucLoseEffectDate)
        pucPublicKeyLen = 264
        pke = (c_ubyte * 132)()
        pkeLen = c_uint()
        pks = (c_ubyte * 132)()
        pksLen = c_uint()
        global ske 
        ske = (c_ubyte * 384)()
        skeLen = c_uint()
        print("######################上传公钥######################")
        print("SignPubKey x分量：\n%s" % pucPublicKey[0].x[:])
        print("SignPubKey y分量：\n%s" % pucPublicKey[0].y[:])
        print("ProtectPubKey x分量：\n%s" % pucPublicKey[1].x[:])
        print("ProtectPubKey y分量：\n%s" % pucPublicKey[1].y[:])
        print("Region：%s" % uiRegion)
        print("Id: %s, IdLen: %d" % (pucIdentify, uiIdentifyLen))
        print("LIA: %s, LIALen: %d" % (pucLicenceIssuingAuthority, uiLicenceIssuingAuthorityLen))
        print("takeDate: %s, takeDateLen: %d" % (pucTakeEffectDate, uiTakeEffectDateLen))
        print("loseDate: %s, loseDateLen: %d" % (pucLoseEffectDate, uiLoseEffectDateLen))
        ret = gm.dmsPCI_CalculatePersonKey(hSessionHandle, uiRegion,
                                           pucIdentify, uiIdentifyLen,
                                           pucLicenceIssuingAuthority, uiLicenceIssuingAuthorityLen,
                                           pucTakeEffectDate, uiTakeEffectDateLen,
                                           pucLoseEffectDate, uiLoseEffectDateLen,
                                           pucPublicKey, pucPublicKeyLen,
                                           pke, byref(pkeLen),
                                           pks, byref(pksLen),
                                           ske, byref(skeLen))
        if ret == 0:
                print("dmsPCI_CalculatePersonKey success, ret = 0x%x" % ret)
                print("######################输出密钥######################")
                print('pksLen = %d pkeLen = %d skeLen = %d'%(pksLen.value, pkeLen.value, skeLen.value))
                print("签名公钥Pks：\n%s" % pks[:])
                print("加密公钥pke：\n%s" % pke[:])
                print("加密私钥ske：\n%s" % ske[:])
        else:
                print("dmsPCI_CalculatePersonKey fail, ret = 0x%08x" % ret)


def dmsPCI_ImportKeyWithECCKeyPair():
        ret = gm.dmsPCI_ImportKeyWithECCKeyPair(hSessionHandle, SGD_SM2_3, ske)
        if ret == 0:
                print("dmsPCI_ImportKeyWithECCKeyPair success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_ImportKeyWithECCKeyPair fail, ret = 0x%08x" % ret)
	

def dmsPCI_SVSGenECCKeyPair():
	uiKeyIndex = input('please input the KeyIndex: ')
	KeyLen = input('please input the KeyLen: ')
	ret = gm.dmsPCI_SVSGenECCKeyPair(hSessionHandle, int(uiKeyIndex), int(KeyLen), pucPublicKey)
	if ret == 0:
		print("dmsPCI_SVSGenECCKeyPair success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_SVSGenECCKeyPair fail, ret = 0x%08x" % ret)


def dmsPCI_SVSImportKeyWithECCKeyPair():
        uiKeyIndex = input('please input the KeyIndex: ')
        ret = gm.dmsPCI_SVSImportKeyWithECCKeyPair(hSessionHandle, int(uiKeyIndex), 0, ske)
        if ret == 0:
                print("dmsPCI_SVSImportKeyWithECCKeyPair success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_SVSImportKeyWithECCKeyPair fail, ret = 0x%08x" % ret)


def dmsPCI_SVSClearContainer():
	uiKeyIndex = input('please input the KeyIndex: ')
	ret = gm.SDF_dmsPCI_SVSClearContainer(hSessionHandle, int(uiKeyIndex))
	if ret == 0:
		print("dmsPCI_SVSClearContainer success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_SVSClearContainer fail, ret = 0x%08x" % ret)


def dmsPCI_ChangeCardPIN():
	pcOldManagePin = input('please input the old device password: ')
	pcNewManagePin = input('please input the new device password: ')
	ret = gm.dmsPCI_ChangeCardPIN(hSessionHandle, pcOldManagePin.encode(), pcNewManagePin.encode())
	if ret == 0:
		print("dmsPCI_ChangeCardPIN success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_ChangeCardPIN fail, ret = 0x%08x" % ret)


def dmsPCI_ChangeKeyPIN():
	uiKeyIndex = input('please input the index: ')
	pcOldKeyPin = input('please input the old key password: ')
	pcNewKeyPin = input('please input the new key password: ')
	ret = gm.dmsPCI_ChangeKeyPIN(hSessionHandle, int(uiKeyIndex), pcOldKeyPin.encode(), pcNewKeyPin.encode())
	if ret == 0:
		print("dmsPCI_ChangeKeyPIN success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_ChangeKeyPIN fail, ret = 0x%08x" % ret)


def dmsPCI_GenerateKEK():
	puiKEKindex = c_uint()
	uiKEKBitLen = input('please input the KEK length(128)：')
	ret = gm.dmsPCI_GenerateKEK(hSessionHandle, int(uiKEKBitLen), byref(puiKEKindex))
	if ret == 0:
		print("dmsPCI_GenerateKEK success, ret = 0x%x" % ret)
		print("puiKEKindex:%s" % puiKEKindex.value)
	else:
		print("dmsPCI_GenerateKEK fail, ret = 0x%08x" % ret)


def dmsPCI_DeleteKEK():
	uiKEKindex = input('please input the KEK index(1~100): ')
	ret = gm.dmsPCI_DeleteKEK(hSessionHandle, int(uiKEKindex))
	if ret == 0:
		print("dmsPCI_DeleteKEK success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_DeleteKEK fail, ret = 0x%08x" % ret)


def dmsPCI_CalculatePubKey():
	uiRegion = int(input('please input the Region(0~0xff): '))
	pucIdentity = input('please input the Identity: ')
	uiIdentityLen = len(pucIdentity)
	pECCPubkey = ECCrefPublicKey()
	ret = gm.dmsPCI_CalculatePubKey(hSessionHandle, uiRegion,
						byref(pECCPubkey),
						pucIdentity, uiIdentityLen)
	if ret == 0:
		print("dmsPCI_CalculatePubKey success, ret = 0x%x" % ret)
		print('pECCPubkey.x =')
		for i in range(64):
			print(hex(pECCPubkey.x[i]), end = ' ')
		print('\npECCPubkey.y =')
		for j in range(64):
			print(hex(pECCPubkey.y[j]), end = ' ')
	else:
		print("dmsPCI_CalculatePubKey fail, ret = 0x%08x" % ret)


def dmsPCI_CalculatePubKey_Optimize():
        uiRegion = int(input('please input the Region(0~0xff): '))
        pucIdentity = input('please input the Identity: ')
        uiIdentityLen = len(pucIdentity)
        pECCPubkey = ECCrefPublicKey()
        ret = gm.dmsPCI_CalculatePubKey(hSessionHandle, uiRegion,
                                                byref(pECCPubkey),
                                                pucIdentity, uiIdentityLen)
        if ret == 0:
                print("dmsPCI_CalculatePubKey success, ret = 0x%x" % ret) 
                print('pECCPubkey.x =')
                for i in range(64):
                        print(hex(pECCPubkey.x[i]), end = ' ') 
                print('\npECCPubkey.y =')
                for j in range(64):
                        print(hex(pECCPubkey.y[j]), end = ' ') 
        else:
                print("dmsPCI_CalculatePubKey fail, ret = 0x%08x" % ret)


def dmsPCI_IdentifyECCSignForEnvelope():
	uiRegion = int(input('please input the Region(0~0xff): '))
	pucIdentity = input('please input the Identity(max=128): ')
	uiIdentityLen = len(pucIdentity)
	pucSignID = input('please input the SignID(max=128): ')
	uiSignIDLen = len(pucSignID)
	pucData = '12345678'
	uiDataLen = len(pucData)
	pEccSign = ECCSignature()
	SignLen = c_int()
	puiSignAlgorithm = c_uint()
	puiHashAlgorithm = c_uint()
	ret = gm.dmsPCI_IdentifyECCSignForEnvelope(hSessionHandle, uiRegion,
							pucIdentity, uiIdentityLen,
							pucSignID, uiSignIDLen,
							pucData, uiDataLen,
							byref(pEccSign), byref(SignLen),
							byref(puiSignAlgorithm), byref(puiHashAlgorithm))
	if ret == 0:
		print("dmsPCI_IdentifyECCSignForEnvelope success, ret = 0x%x" % ret)
		print("puiSignAlgorithm = 0x%08x, puiHashAlgorithm = 0x%08x" % (puiSignAlgorithm.value, puiHashAlgorithm.value))
	else:
		print("dmsPCI_IdentifyECCSignForEnvelope fail, ret = 0x%08x" % ret)


def dmsPCI_IdentifyECCSignForEnvelope_Optimize():
        uiRegion = int(input('please input the Region(0~0xff): '))
        pucIdentity = input('please input the Identity(max=128): ')
        uiIdentityLen = len(pucIdentity)
        pucSignID = input('please input the SignID(max=128): ')
        uiSignIDLen = len(pucSignID)
        pucData = '12345678'
        uiDataLen = len(pucData)
        pEccSign = ECCSignature()
        SignLen = c_int()
        puiSignAlgorithm = c_uint()
        puiHashAlgorithm = c_uint()
        ret = gm.dmsPCI_IdentifyECCSignForEnvelope(hSessionHandle, uiRegion,
                                                        pucIdentity, uiIdentityLen,
                                                        pucSignID, uiSignIDLen,
                                                        pucData, uiDataLen,
                                                        byref(pEccSign), byref(SignLen),
                                                        byref(puiSignAlgorithm), byref(puiHashAlgorithm))
        if ret == 0:
                print("dmsPCI_IdentifyECCSignForEnvelope success, ret = 0x%x" % ret)
                print("puiSignAlgorithm = 0x%08x, puiHashAlgorithm = 0x%08x" % (puiSignAlgorithm.value, puiHashAlgorithm.value))
        else:
                print("dmsPCI_IdentifyECCSignForEnvelope fail, ret = 0x%08x" % ret)


def dmsPCI_GetKEKPoolStatus():
        pucKEKStatus = (c_ubyte * 100)()	
        puiMaxSize = c_uint(100)
        ret = gm.dmsPCI_GetKEKPoolStatus(hSessionHandle, byref(puiMaxSize), pucKEKStatus)
        if ret == 0:
                print("dmsPCI_GetKEKPoolStatus success, ret = 0x%x" % ret)
                print("KEKPoolStatus: %s"%pucKEKStatus[:])
        else:
                print("dmsPCI_GetKEKPoolStatus fail, ret = 0x%08x" % ret)


def dmsPCI_Generate_PKIKeyPair():
        uiKeyIndex = input('please input the KeyIndex(0~49): ')
        KeyFlag = input('please input the KeyFlag(enc:1, sign:2, encAndsign:3): ')
        pucPublicKey = (c_ubyte * 132)()
        pucPrivateKey = (c_ubyte * 68)()
        ret = gm.dmsPCI_Generate_PKIKeyPair(hSessionHandle, int(uiKeyIndex), int(KeyFlag), pucPublicKey, pucPrivateKey)
        if ret == 0:
                print("dmsPCI_Generate_PKIKeyPair success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_Generate_PKIKeyPair fail, ret = 0x%08x" % ret)	


def dmsPCI_ImportPKIEncryKeyPair():
        uiKeyIndex1 = input('please input the decryptIndex(0~49): ')
        uiKeyIndex2 = input('please input the saveIndex(0~49): ')
        pucPublicKey = (c_ubyte * 264)()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex1), byref(pucPublicKey))
        if ret == 0:
                print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
        else:
                print('SDF_ExportEncPublicKey_ECC fail, ret = ' + hex(ret))
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex1), byref(pucPublicKey, 132))
        if ret == 0:
                print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
        else:
                print('SDF_ExportEncPublicKey_ECC fail, ret = ' + hex(ret))
        uiRegion = 1
        pucIdentify = "ahdms12345"
        uiIdentifyLen = len(pucIdentify)
        pucLicenceIssuingAuthority = "ahdms12345"
        uiLicenceIssuingAuthorityLen = len(pucLicenceIssuingAuthority)
        pucTakeEffectDate = "2020-12-08"
        uiTakeEffectDateLen = len(pucTakeEffectDate)
        pucLoseEffectDate = "2022-12-08"
        uiLoseEffectDateLen = len(pucLoseEffectDate)
        pucPublicKeyLen = 264
        pke = (c_ubyte * 132)()
        pkeLen = c_uint()
        pks = (c_ubyte * 132)()
        pksLen = c_uint()
        ske = (c_ubyte * 384)()
        skeLen = c_uint()
        ret = gm.dmsPCI_CalculatePersonKey(hSessionHandle, uiRegion,
                                           pucIdentify, uiIdentifyLen,
                                           pucLicenceIssuingAuthority, uiLicenceIssuingAuthorityLen,
                                           pucTakeEffectDate, uiTakeEffectDateLen,
                                           pucLoseEffectDate, uiLoseEffectDateLen,
                                           pucPublicKey, pucPublicKeyLen,
                                           pke, byref(pkeLen),
                                           pks, byref(pksLen),
                                           ske, byref(skeLen))
        if ret == 0:
                print("dmsPCI_CalculatePersonKey success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_CalculatePersonKey fail, ret = 0x%08x" % ret)
        pucPassword = "dms123456"
        uiPwdLength = len(pucPassword)
        ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, int(uiKeyIndex1), pucPassword.encode(), uiPwdLength)
        if ret == 0:
                print('SDF_GetPrivateKeyAccessRight success, ret = ' + hex(ret))
        else:
                print('SDf_GetPrivateKeyAccessRight fail, ret =' + hex(ret))

        ret = gm.dmsPCI_ImportPKIEncryKeyPair(hSessionHandle, int(uiKeyIndex1), int(uiKeyIndex2), ske)
        if ret == 0:
                print("dmsPCI_ImportPKIEncryKeyPair success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_ImportPKIEncryKeyPair fail, ret = 0x%08x" % ret)


def dmsPCI_SymKeyEncrypt():
        uiDataLength = int(input('please input the dataLen: '))
        ret = gm.SDF_GenerateRandom(hSessionHandle, uiDataLength, pucData)
        if ret == 0:
                print('SDF_GenerateRandom success, ret  = ' + hex(ret))
                for i in range(uiDataLength):
                        print(hex(pucData[i]), end=' ')
        else:
                print('SDF_GenerateRandom fail ret = ' + hex(ret))
        print("")
        index = input('please input the summKey index: ')	
        uiAlgID = SGD_SM4_ECB
        ret = gm.dmsPCI_SymKeyEncrypt(hSessionHandle, int(index), uiAlgID, pucIV, pucData, uiDataLength, pucEncData, byref(puiEncDataLength))
        if ret == 0:
                print("dmsPCI_SymKeyEncrypt success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_SymKeyEncrypt fail, ret = 0x%08x" % ret)


def dmsPCI_SymKeyDecrypt():
        index = input('please input the summKey index: ')
        uiAlgID = SGD_SM4_ECB
        ret = gm.dmsPCI_SymKeyDecrypt(hSessionHandle, int(index), uiAlgID, pucIV, pucEncData, puiEncDataLength, pucDecData, byref(puiDecDataLength))
        if ret == 0:
                print("dmsPCI_SymKeyDecrypt success, ret = 0x%x" % ret)
                for i in range(puiDecDataLength.value):
                        print(hex(pucDecData[i]), end=' ')
        else:
                print("dmsPCI_SymKeyDecrypt fail, ret = 0x%08x" % ret)


def dmsPCI_GetSymmKeyHandle():
        index = input('please input the summKey index: ')
        ret = gm.dmsPCI_GetSymmKeyHandle(hSessionHandle, int(index), byref(phKeyHandle))
        if ret == 0:
                print("dmsPCI_GetSymmKeyHandle success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_GetSymmKeyHandle fail, ret = 0x%08x" % ret)


def dmsPCI_generate_symmkey_by_index():
        index = input('please input the index: ')
        bitLen = input('please input the bitLen: ')
        ret = gm.dmsPCI_generate_symmkey_by_index(hSessionHandle, int(index), int(bitLen))
        if ret == 0:
                print("dmsPCI_generate_symmkey_by_index success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_generate_symmkey_by_index fail, ret = 0x%08x" % ret)
                
                
def dmsPCI_GeneratePartSignPri_NoCert():
        #模拟ukey端提取保护公钥
        pucPublicKey = (c_ubyte * 132)(0x0, 0x1, 0x0, 0x0,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
0xa6, 0x5c, 0x78, 0xc1, 0x80, 0xfd, 0x19, 0xa5, 0xc7, 0x01, 0x01, 0x8b, 0xd4, 0x35, 0x27, 0x59, 0x96, 0x0a, 0xdf, 0xef, 0x0, 0x15, 0x6a, 0x68, 0xc4, 0x41, 0x69, 0x0a, 0x0c, 0xfb, 0x36, 0xbc,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
0x89, 0x2a, 0xa8, 0x77, 0xa6, 0xba, 0xb0, 0xde, 0xe6, 0x3c, 0x21, 0x67, 0x25, 0x36, 0xa6, 0x32, 0x78, 0x1d, 0xf9, 0xf1, 0xd4, 0x5e, 0xec, 0x30, 0x4b, 0x27, 0x6b, 0xa0, 0xfb, 0x48, 0x3c, 0xda)
        #uiKeyIndex = input('please enter the index of PKx and pubH(0~49): ')
        #pucPublicKey = ECCrefPublicKey()
        #ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
        #if ret == 0:
        #    print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
        #else:
        #    print('SDF_ExportEncPublicKey_ECC fail, ret = ' + hex(ret))
        #基于无证书生成部分签名私钥
        identify = input('\nplease input the Identify(max=128): ')
        identifyBitLen = len(identify)
        PKx = pubH = pucPublicKey
        cbEncryptedPriKey = arr1024()
        cbEncryptedPriKeyLen = c_uint()
        SM2Cipher = ECCCIPHERBLOB()
        global PA
       	PA = ECCrefPublicKey()
        ret = gm.dmsPCI_GeneratePartSignPri_NoCert(hSessionHandle, identify, (identifyBitLen * 8), PKx, pubH, cbEncryptedPriKey, byref(cbEncryptedPriKeyLen), byref(SM2Cipher), byref(PA))
        if ret == 0:
                print("dmsPCI_GeneratePartSignPri_NoCert success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_GeneratePartSignPri_NoCert fail, ret = 0x%08x" % ret)
                

def dmsPCI_SignValueVerify_NoCert():
        #导出公钥矩阵
        PubmatrixLen = c_uint(32788)
        Pubmatrix = (c_ubyte * 32788)()
        ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, Pubmatrix, byref(PubmatrixLen))
        if ret == 0:
            print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret) 
        else:
            print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret) 
            
        #IKI无证书模拟ukey端签名
        identify = "011410343631363437FFFF1720"
        identifyBitLen = 26 * 8                                                             
        inData = "abcd1234"
        inDataLen = 8
        PA = (c_ubyte * 132)(0x00, 0x01, 0x00, 0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xd3,0x7a,0x00,0x60,0x20,0xa9,0x2d,0xf2,0xac,0x00,0x19,0x4e,0x03,0x7f,0x15,0x23,0xb2,0x50,0x52,0xcc,0x88,0x44,0xf3,0x9e,0xbd,0xfa,0xfe,0x06,0x1a,0x3a,0x76,0x0b,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x17,0x37,0xce,0xde,0xcf,0x94,0xfc,0xb1,0x00,0xce,0x8f,0xa8,0x47,0x10,0x82,0x96,0x0e,0x84,0xac,0xd8,0x7f,0xc3,0x1c,0xc9,0xce,0x39,0x37,0x3a,0x6d,0x62,0x79,0xee)
        signature = (c_ubyte * 128)(
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xea,0x4e,0xdd,0x29,0x8c,0xa8,0x93,0x04,0x46,0x3f,0xbb,0x80,0x1c,0x92,0xe3,0x18,0xb5,0xb3,0x26,0x83,0x5c,0xca,0xc4,0x1f,0xd5,0x03,0xe7,0x7a,0x19,0x83,0x84,0x47, 
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xf7,0x59,0x40,0xbc,0xdc,0x5d,0x23,0xa0,0xfe,0x57,0x7e,0x78,0x0e,0xc4,0x7f,0x7c,0x96,0x6a,0xa5,0x4e,0xff,0x12,0xa0,0x05,0x3a,0xde,0x4b,0x88,0xf5,0x44,0xb8,0xa7)


        #IKI无证书验证签名(服务端)
        ret = gm.dmsPCI_SignValueVerify_NoCert(hSessionHandle, identify.encode(), identifyBitLen, Pubmatrix, PubmatrixLen.value, inData.encode(), inDataLen, PA, signature)
        if ret == 0:
                print("dmsPCI_SignValueVerify_NoCert success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_SignValueVerify_NoCert fail, ret = 0x%08x" % ret)
                
                
def dmsPCI_Calculate_and_Export_PKS_NoCert():
        #导出公钥矩阵
        PubmatrixLen = c_uint(32788)
        Pubmatrix = (c_ubyte * 32788)()
        ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, Pubmatrix, byref(PubmatrixLen))
        if ret == 0:
            print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
        else:
            print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)
            
        #IKI无证书计算并导出签名公钥
        identify = input('please input the Identify(max=128): ')
        identifyBitLen = len(identify)
        PKS = ECCrefPublicKey()
        ret = gm.dmsPCI_Calculate_and_Export_PKS_NoCert(hSessionHandle, identify, (identifyBitLen * 8), Pubmatrix, PubmatrixLen.value, byref(PA), byref(PKS))
        if ret == 0:
                print("dmsPCI_Calculate_and_Export_PKS_NoCert success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_Calculate_and_Export_PKS_NoCert fail, ret = 0x%08x" % ret)
                
                
                
def dmsPCI_Calculate_e_NoCert():
        #导出公钥矩阵
        PubmatrixLen = c_uint(32788)
        Pubmatrix = (c_ubyte * 32790)()
        ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, Pubmatrix, byref(PubmatrixLen))
        if ret == 0:
            print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
        else:
            print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)
            
        #IKI无证书验证签名(服务端)
        identify = input('please input the Identify(max=128): ')
        identifyBitLen = len(identify)
        inData = input('please input the inData: ')
        inDataLen = len(inData)
        global e
        e = arr32()
        ret = gm.dmsPCI_Calculate_e_NoCert(hSessionHandle, identify, (identifyBitLen * 8), Pubmatrix, PubmatrixLen.value, inData, inDataLen, byref(PA), e)
        if ret == 0:
                print("dmsPCI_Calculate_e_NoCert success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_Calculate_e_NoCert fail, ret = 0x%08x" % ret)
                

def dmsPCI_Export_PKM_Hash_Value():
	global pucHash, uiHashLength
	pucHash = arr32()
	uiHashLength = c_uint()
	ret = gm.dmsPCI_Export_PKM_Hash_Value(hSessionHandle, pucHash, byref(uiHashLength))
	if ret ==0:
		print('dmsPCI_Export_PKM_Hash_Value success, ret = ' + hex(ret))
		print('Hash Value: %s'%pucHash[:])
	else:
		print('dmsPCI_Export_PKM_Hash_Value fail, ret ' + hex(ret))
        
        
def dmsPCI_SignValueVerify_NoCert_by_hiki_passed_in():
        #导出公钥矩阵
        PubmatrixLen = c_uint(32788)
        Pubmatrix = (c_ubyte * 32788)()
        ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, Pubmatrix, byref(PubmatrixLen))
        if ret == 0:
            print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
        else:
            print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)
        #导出公钥矩阵的Hash值
        pucHash = arr32()
        uiHashLength = c_uint()
        ret = gm.dmsPCI_Export_PKM_Hash_Value(hSessionHandle, pucHash, byref(uiHashLength))
        if ret ==0:
            print('dmsPCI_Export_PKM_Hash_Value success, ret = ' + hex(ret))
            print('Hash Value: %s'%pucHash[:])
        else:
            print('dmsPCI_Export_PKM_Hash_Value fail, ret ' + hex(ret))
            
        #IKI无证书模拟ukey端签名
        identify = "011410343631363437FFFF1720"
        identifyBitLen = 26 * 8                                                             
        inData = "abcd1234"
        inDataLen = 8
        PA = (c_ubyte * 132)(0x00, 0x01, 0x00, 0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xd3,0x7a,0x00,0x60,0x20,0xa9,0x2d,0xf2,0xac,0x00,0x19,0x4e,0x03,0x7f,0x15,0x23,0xb2,0x50,0x52,0xcc,0x88,0x44,0xf3,0x9e,0xbd,0xfa,0xfe,0x06,0x1a,0x3a,0x76,0x0b,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x17,0x37,0xce,0xde,0xcf,0x94,0xfc,0xb1,0x00,0xce,0x8f,0xa8,0x47,0x10,0x82,0x96,0x0e,0x84,0xac,0xd8,0x7f,0xc3,0x1c,0xc9,0xce,0x39,0x37,0x3a,0x6d,0x62,0x79,0xee)
        signature = (c_ubyte * 128)(
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xea,0x4e,0xdd,0x29,0x8c,0xa8,0x93,0x04,0x46,0x3f,0xbb,0x80,0x1c,0x92,0xe3,0x18,0xb5,0xb3,0x26,0x83,0x5c,0xca,0xc4,0x1f,0xd5,0x03,0xe7,0x7a,0x19,0x83,0x84,0x47, 
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xf7,0x59,0x40,0xbc,0xdc,0x5d,0x23,0xa0,0xfe,0x57,0x7e,0x78,0x0e,0xc4,0x7f,0x7c,0x96,0x6a,0xa5,0x4e,0xff,0x12,0xa0,0x05,0x3a,0xde,0x4b,0x88,0xf5,0x44,0xb8,0xa7)
        #IKI无证书验证签名(服务端)
        ret = gm.dmsPCI_SignValueVerify_NoCert_by_hiki_passed_in(hSessionHandle, identify.encode(), identifyBitLen, Pubmatrix, PubmatrixLen.value, pucHash, uiHashLength.value, inData.encode(), inDataLen, PA, signature)
        if ret == 0:
                print("dmsPCI_SignValueVerify_NoCert_by_hiki_passed_in success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_SignValueVerify_NoCert_by_hiki_passed_in fail, ret = 0x%08x" % ret)
                
                
def dmsPCI_Calculate_and_Export_PKS_NoCert_by_hiki_passed_in():
        #导出公钥矩阵
        PubmatrixLen = c_uint(32788)
        Pubmatrix = (c_ubyte * 32788)()
        ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, Pubmatrix, byref(PubmatrixLen))
        if ret == 0:
            print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
        else:
            print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)
            
        #IKI无证书计算并导出签名公钥
        identify = input('please input the Identify(max=128): ')
        identifyBitLen = len(identify)
        PKS = ECCrefPublicKey()
        ret = gm.dmsPCI_Calculate_and_Export_PKS_NoCert_by_hiki_passed_in(hSessionHandle, identify, (identifyBitLen * 8), Pubmatrix, PubmatrixLen.value, pucHash, uiHashLength.value, byref(PA), byref(PKS))
        if ret == 0:
                print("dmsPCI_Calculate_and_Export_PKS_NoCert_by_hiki_passed_in success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_Calculate_and_Export_PKS_NoCert_by_hiki_passed_in fail, ret = 0x%08x" % ret)
                
                
                
def dmsPCI_Calculate_e_NoCert_by_hiki_passed_in():
        #导出公钥矩阵
        PubmatrixLen = c_uint(32788)
        Pubmatrix = (c_ubyte * 32788)()
        ret = gm.dmsPCI_ExportPubMatrix(hSessionHandle, Pubmatrix, byref(PubmatrixLen))
        if ret == 0:
            print("dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
        else:
            print("dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)
            
        #IKI无证书验证签名(服务端)
        identify = input('please input the Identify(max=128): ')
        identifyBitLen = len(identify)
        inData = input('please input the inData: ')
        inDataLen = len(inData)
        global e
        e = arr32()
        ret = gm.dmsPCI_Calculate_e_NoCert_by_hiki_passed_in(hSessionHandle, identify, (identifyBitLen * 8), pucHash, uiHashLength.value, inData, inDataLen, byref(PA), e)
        if ret == 0:
                print("dmsPCI_Calculate_e_NoCert_by_hiki_passed_in success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_Calculate_e_NoCert_by_hiki_passed_in fail, ret = 0x%08x" % ret)



def dmsPCI_SegMentKey():
	global sgmNum, index, flag
	sgmNum = input('please input the sgmNum(2<=sgmNum<=9): ')
	pin = input('please input the device pin: ')
	pinLen = len(pin)
	flag = input('please input the flag(fullKeySeg: 1, singleKeySeg: 0): ')
	index = input('please input the index: ') 
	ret = gm.dmsPCI_SegMentKey(hSessionHandle, int(sgmNum), pinLen, pin.encode(), int(flag), int(index))
	if ret == 0:
		print("dmsPCI_SegMentKey success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_SegMentKey fail, ret = 0x%08x" % ret)


def dmsPCI_GetSegMentKey():
	pin = input('please input the protect pin: ')
	pinLen = len(pin)
	global pucSegKey, puiSegKeyLen
	pucSegKey = (c_ubyte * 52128)()
	puiSegKeyLen = c_uint()
	pucSegKeyTemp = (c_ubyte * 26064)()
	puiSegKeyLenTemp = c_uint()
	for i in range(int(sgmNum)):
		ret = gm.dmsPCI_GetSegMentKey(hSessionHandle, pin.encode(), pinLen, pucSegKeyTemp, byref(puiSegKeyLenTemp), int(flag))
		if ret == 0:
			print("dmsPCI_GetSegMentKey success, ret = 0x%x" % ret)
			print(puiSegKeyLenTemp.value)
			memmove(byref(pucSegKey, 26064 * i), pucSegKeyTemp, 26064)
		else:
			print("dmsPCI_GetSegMentKey fail, ret = 0x%08x" % ret)
			return 0


def dmsPCI_KeyRecoveryInit():
	ret = gm.dmsPCI_KeyRecoveryInit(hSessionHandle)
	if ret == 0:
		print("dmsPCI_KeyRecoveryInit success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_KeyRecoveryInit fail, ret = 0x%08x" % ret)


def dmsPCI_ImportSegmentKey():
	pin = input('please input the protect pin: ')
	pinLen = len(pin)
	pucSegKeyTemp = (c_ubyte * 26064)()
	puiSegKeyLenTemp = 26064
	for i in range(int(sgmNum)):
		memmove(pucSegKeyTemp, byref(pucSegKey, 26064 * i), 26064)
		ret = gm.dmsPCI_ImportSegmentKey(hSessionHandle, pin.encode(), pinLen, pucSegKeyTemp, puiSegKeyLenTemp, int(flag))
		if ret == 0:
			print("dmsPCI_ImportSegmentKey success, ret = 0x%x" % ret)
		else:
			print("dmsPCI_ImportSegmentKey fail, ret = 0x%08x" % ret)
			return 0


def dmsPCI_KeyRecovery():
	
	ret = gm.dmsPCI_KeyRecovery(hSessionHandle, int(sgmNum), int(flag), int(index))
	if ret == 0:
		print("dmsPCI_KeyRecovery success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_KeyRecovery fail, ret = 0x%08x" % ret)


def dmsPCI_SegMentKeyThreshold():
	pin = input('please input the device pin: ')
	pinLen = len(pin)
	isFullKey = input('only FullKey：1：')
	index = 0
	global sgmNum, recoverNum
	sgmNum = int(input('please input the sgmNum: '))
	recoverNum = int(input('please input the recoverNum: '))
	global pucPciData, puiPciDataLen
	pucPciData = (c_ubyte * 32788)()
	puiPciDataLen = c_uint()
	ret = gm.dmsPCI_SegMentKeyThreshold(hSessionHandle, 
					sgmNum, recoverNum, 
					pinLen, pin.encode(),
					int(isFullKey), index,
					pucPciData, byref(puiPciDataLen))
	if ret == 0:
		print("dmsPCI_SegMentKeyThreshold success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_SegMentKeyThreshold fail, ret = 0x%08x" % ret)


def dmsPCI_GetSegMentKeyThreshold():
        uiKeyIndex = input('please input the publicKey index of protect segKey：')
        # 导出公钥
        pPubKey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pPubKey))
        if ret == 0:
                print("ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
                print("ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)

        # 导出分割对称密钥的密文结构
        global pCipherKey, pCipherKeyLen
        pCipherKey = (c_ubyte * 980)()
        pCipherKeyLen = c_uint()
        for i in range(recoverNum):
                ret = gm.dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), byref(pCipherKey, i * 196), byref(pCipherKeyLen))
                if ret == 0:
                       print("第 %d 次：dmsPCI_GetSegMentKeyThreshold success, ret = 0x%x" % (i + 1, ret))
                       print('pCipherKey1Len = %d'%pCipherKeyLen.value)
                else:
                       print("dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)


#def dmsPCI_GetSegMentKeyThreshold():
#	uiKeyIndex = input('请输入保护分割密钥的公钥索引值：')
#	# 导出公钥
#	pPubKey = ECCrefPublicKey()
#	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pPubKey))
#	if ret == 0:
#		print("ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
#	else:
#		print("ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)
#
#	# 导出分割对称密钥的密文结构
#	global pCipherKey1, pCipherKey2, pCipherKey3, pCipherKey4, pCipherKey5
#	global pCipherKey1Len, pCipherKey2Len, pCipherKey3Len, pCipherKey4Len, pCipherKey5Len
#	# 第一次
#	pCipherKey1 = (c_ubyte * 196)()
#	pCipherKey1Len = c_uint()
#	ret = gm.dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), byref(pCipherKey1), byref(pCipherKey1Len))
#	if ret == 0:
#		print("第一次：dmsPCI_GetSegMentKeyThreshold success, ret = 0x%x" % ret)
#		print('pCipherKey1Len = %d'%pCipherKey1Len.value)
#	else:
#		print("dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)
#	# 第二次
#	pCipherKey2 = (c_ubyte * 196)()
#	pCipherKey2Len = c_uint()
#	ret = gm.dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), byref(pCipherKey2), byref(pCipherKey2Len))
#	if ret == 0:
#		print("第二次：dmsPCI_GetSegMentKeyThreshold success, ret = 0x%x" % ret)
#		print('pCipherKey1Len = %d'%pCipherKey2Len.value)
#	else:
#		print("dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)
#	# 第三次
#	pCipherKey3 = (c_ubyte * 196)()
#	pCipherKey3Len = c_uint()
#	ret = gm.dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), byref(pCipherKey3), byref(pCipherKey3Len))
#	if ret == 0:
#		print("第三次：dmsPCI_GetSegMentKeyThreshold success, ret = 0x%x" % ret)
#		print('pCipherKey1Len = %d'%pCipherKey3Len.value)
#	else:
#		print("dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)
#	# 第四次
#	pCipherKey4 = (c_ubyte * 196)()
#	pCipherKey4Len = c_uint()
#	ret = gm.dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), byref(pCipherKey4), byref(pCipherKey4Len))
#	if ret == 0:
#		print("第四次：dmsPCI_GetSegMentKeyThreshold success, ret = 0x%x" % ret)
#		print('pCipherKey1Len = %d'%pCipherKey4Len.value)
#	else:
#		print("dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)
#	# 第五次
#	pCipherKey5 = (c_ubyte * 196)()
#	pCipherKey5Len = c_uint()
#	ret = gm.dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), byref(pCipherKey5), byref(pCipherKey5Len))
#	if ret == 0:
#		print("第五次：dmsPCI_GetSegMentKeyThreshold success, ret = 0x%x" % ret)
#		print('pCipherKey1Len = %d'%pCipherKey5Len.value)
#	else:
#		print("dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)




def dmsPCI_KeyRecoveryInitThreshold():
        pPubKey = (c_ubyte * 132)()
        ret = gm.dmsPCI_KeyRecoveryInitThreshold(hSessionHandle, pPubKey)
        if ret == 0:
                print("dmsPCI_KeyRecoveryInitThreshold success, ret = 0x%x" % ret)
        else:
                print("dmsPCI_KeyRecoveryInitThreshold fail, ret = 0x%08x" % ret)
        # 数字信封交换
        uiAlgID = SGD_SM2_3
        uiKeyIndex = input("please input the publicKey index of protect segKey：")
        global pCipherKeyEx
        pCipherKeyEx = (c_ubyte * 980)()
        for i in range(recoverNum):
                ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiKeyIndex), uiAlgID, pPubKey, byref(pCipherKey, i * 196),  byref(pCipherKeyEx, i* 196))
                if ret == 0:
                       print("第 %d 次: ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % (i + 1,ret))
                else:
                       print("ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)




#def dmsPCI_KeyRecoveryInitThreshold():
#	pPubKey = (c_ubyte * 132)()
#	ret = gm.dmsPCI_KeyRecoveryInitThreshold(hSessionHandle, pPubKey)
#	if ret == 0:
#		print("dmsPCI_KeyRecoveryInitThreshold success, ret = 0x%x" % ret)
#	else:
#		print("dmsPCI_KeyRecoveryInitThreshold fail, ret = 0x%08x" % ret)
#	# 数字信封交换
#	uiAlgID = SGD_SM2_3
#	uiKeyIndex = input("请输入保护秘钥分割数据的公钥的索引值Index（0~49）：") 
#	global pCipherKeyEx1, pCipherKeyEx2, pCipherKeyEx3, pCipherKeyEx4, pCipherKeyEx5
#	# 第一次交换
#	pCipherKeyEx1 = (c_ubyte * 196)()
#	ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiKeyIndex), uiAlgID, pPubKey,
#												pCipherKey1, pCipherKeyEx1)
#	if ret == 0:
#		print("第一次ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % ret)
#	else:
#		print("ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)
#	# 第二次交换
#	pCipherKeyEx2 = (c_ubyte * 196)()
#	ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiKeyIndex), uiAlgID, pPubKey,
#												pCipherKey2, pCipherKeyEx2)
#	if ret == 0:
#		print("第二次ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % ret)
#	else:
#		print("ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)
#	# 第三次交换
#	pCipherKeyEx3 = (c_ubyte * 196)()
#	ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiKeyIndex), uiAlgID, pPubKey,
#												pCipherKey3, pCipherKeyEx3)
#	if ret == 0:
#		print("第三次ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % ret)
#	else:
#		print("ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)



def dmsPCI_ImportSegmentKeyThreshold():
	for i in range(recoverNum):
	        ret = gm.dmsPCI_ImportSegmentKeyThreshold(hSessionHandle, byref(pCipherKeyEx, i * 196), pCipherKeyLen.value)
	        if ret == 0:
                       print("第 %d 次: 导入dmsPCI_ImportSegmentKeyThreshold success, ret = 0x%x" % (i + 1, ret))
	        else:
                       print("dmsPCI_ImportSegmentKeyThreshold fail, ret = 0x%08x" % ret)
	

def dmsPCI_KeyRecoveryThreshold():
	isFullKey = 1
	index = 0
	ret = gm.dmsPCI_KeyRecoveryThreshold(hSessionHandle, recoverNum, isFullKey, index, pucPciData, puiPciDataLen)
	if ret == 0:
		print("dmsPCI_KeyRecoveryThreshold success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_KeyRecoveryThreshold fail, ret = 0x%08x" % ret)

def exit():
	sys.exit()


switch = {
	"1" : SDF_OpenDevice,
	"2" : SDF_CloseDevice,
	"3" : SDF_OpenSession,
	"4" : SDF_CloseSession,
	"5" : SDF_GetDeviceInfo,
	"6" : SDF_GenerateRandom,
	"7" : SDF_GetPrivateKeyAccessRight,
	"8" : SDF_ReleasePrivateKeyAccessRight,
	"9" : SDF_ExportSignPublicKey_ECC,
	"10" : SDF_ExportEncPublicKey_ECC,
	"11" : SDF_GenerateKeyPair_ECC,
	"12" : SDF_GenerateKeyWithIPK_ECC,
	"13" : SDF_GenerateKeyWithEPK_ECC,
	"14" : SDF_ImportKeyWithISK_ECC,
	"15" : SDF_GenerateAgreementDataWithECC,
	"16" : SDF_GenerateKeyWithECC,
	"17" : SDF_GenerateAgreementDataAndKeyWithECC,
	"18" : SDF_ExchangeDigitEnvelopeBaseOnECC,
	"19" : SDF_GenerateKeyWithKEK,
	"20" : SDF_ImportKeyWithKEK,
	"21" : SDF_DestroyKey,
	"22" : SDF_InternalSign_ECC,
	"23" : SDF_InternalVerify_ECC,
	"24" : SDF_ExternalVerify_ECC,
	"25" : SDF_ExternalEncrypt_ECC,
	"26" : SDF_HashInit,
	"27" : SDF_HashUpdate,
	"28" : SDF_HashFinal,
	"29" : SDF_Encrypt,
	"30" : SDF_Decrypt,
	"31" : SDF_CalculateMAC,
	"32" : SDF_CreateFile,
	"33" : SDF_ReadFile,
	"34" : SDF_WriteFile,
	"35" : SDF_DeleteFile,
	"36" : SDF_EnumFiles,
	"37" : dmsPCI_SegMentKey,
        "38" : dmsPCI_GetSegMentKey,
        "39" : dmsPCI_KeyRecoveryInit,
        "40" : dmsPCI_ImportSegmentKey,
        "41" : dmsPCI_KeyRecovery,
        "42" : dmsPCI_SegMentKeyThreshold,
        "43" : dmsPCI_GetSegMentKeyThreshold,
        "44" : dmsPCI_KeyRecoveryInitThreshold,
        "45" : dmsPCI_ImportSegmentKeyThreshold,
        "46" : dmsPCI_KeyRecoveryThreshold,
	"47" : dmsPCI_PCICardInit,
    	"48" : dmsPCI_PCICardGenerateMatrix,
	"49" : dmsPCI_TestSelf,
    	"50" : dmsPCI_ImportPubMatrix,
    	"51" : dmsPCI_ExportPubMatrix,
    	"52" : dmsPCI_SVSGetKeyPoolState,
    	"53" : dmsPCI_SVSSetKeyIndex,
    	"54" : dmsPCI_GenECCKeyPair,
    	"55" : dmsPCI_SVSGenECCKeyPair,
    	"56" : dmsPCI_CalculatePersonKey,
   	"57" : dmsPCI_SVSImportKeyWithECCKeyPair,
   	"58" : dmsPCI_SVSClearContainer,
    	"59" : dmsPCI_ChangeCardPIN,
    	"60" : dmsPCI_ChangeKeyPIN,
    	"61" : dmsPCI_GenerateKEK,
    	"62" : dmsPCI_DeleteKEK,
    	"63" : dmsPCI_CalculatePubKey,
    	"64" : dmsPCI_IdentifyECCSignForEnvelope,
    	"65" : dmsPCI_ImportKeyWithECCKeyPair,
	"66" : dmsPCI_GetKEKPoolStatus,
	"67" : dmsPCI_Generate_PKIKeyPair,
	"68" : dmsPCI_ImportPKIEncryKeyPair,
	"69" : dmsPCI_SymKeyEncrypt,
	"70" : dmsPCI_SymKeyDecrypt,
	"71" : dmsPCI_GetSymmKeyHandle,
	"72" : dmsPCI_generate_symmkey_by_index,
	"73" : dmsPCI_CalculatePubKey_Optimize,
	"74" : dmsPCI_IdentifyECCSignForEnvelope_Optimize,
	"75" : dmsPCI_GeneratePartSignPri_NoCert,
	"76" : dmsPCI_SignValueVerify_NoCert,
	"77" : dmsPCI_Calculate_and_Export_PKS_NoCert,
	"78" : dmsPCI_Calculate_e_NoCert,
   	"79" : dmsPCI_Export_PKM_Hash_Value,
    	"80" : dmsPCI_SignValueVerify_NoCert_by_hiki_passed_in,
    	"81" : dmsPCI_Calculate_and_Export_PKS_NoCert_by_hiki_passed_in,
    	"82" : dmsPCI_Calculate_e_NoCert_by_hiki_passed_in,
	"99" : SDF_ImportKey,
    	"0" : exit 
	}


while True:
	print('\n\033[1;35m *****************************设备管理类函数***************************************** \033[0m')
	print('\033[1;33m 1.SDF_OpenDevice                              2.SDF_CloseDevice \033[0m')
	print('\033[1;33m 3.SDF_OpenSession                             4.SDF_CloseSession\033[0m')
	print('\033[1;33m 5.SDF_GetDeviceInfo                           6.SDF_GenerateRandom \033[0m')
	print('\033[1;33m 7.SDF_GetPrivateKeyAccessRight                8.SDF_ReleasePrivateKeyAccessRight \033[0m')
	print('\033[1;35m *****************************密钥管理类函数***************************************** \033[0m')
	print('\033[1;33m 9.SDF_ExportSignPublicKey_ECC                 10.SDF_ExportEncPublicKey_ECC \033[0m')
	print('\033[1;33m 11.SDF_GenerateKeyPair_ECC                    12.SDF_GenerateKeyWithIPK_ECC \033[0m')
	print('\033[1;33m 13.SDF_GenerateKeyWithEPK_ECC                 14.SDF_ImportKeyWithISK_ECC \033[0m')
	print('\033[1;33m 15.SDF_GenerateAgreementDataWithECC           16.SDF_GenerateKeyWithECC \033[0m')
	print('\033[1;33m 17.SDF_GenerateAgreementDataAndKeyWithECC     18.SDF_ExchangeDigitEnvelopeBaseOnECC \033[0m')
	print('\033[1;33m 19.SDF_GenerateKeyWithKEK                     20.SDF_ImportKeyWithKEK \033[0m')
	print('\033[1;33m 21.SDF_DestroyKey                             99.SDF_ImportKey(明文形式导入)\033[0m')
	print('\033[1;35m *****************************SM2/SM3/SM4算法类函数********************************** \033[0m')
	print('\033[1;33m 22.SDF_InternalSign_ECC                       23.SDF_InternalVerify_ECC \033[0m')
	print('\033[1;33m 24.SDF_ExternalVerify_ECC                     25.SDF_ExternalEncrypt_ECC \033[0m')
	print('\033[1;33m 26.SDF_HashInit                               27.SDF_HashUpdate \033[0m')
	print('\033[1;33m 28.SDF_HashFinal                              29.SDF_Encrypt \033[0m')
	print('\033[1;33m 30.SDF_Decrypt                                31.SDF_CalculateMAC \033[0m')
	print('\033[1;35m *****************************文件操作类函数***************************************** \033[0m')
	print('\033[1;33m 32.SDF_CreateFile                             33.SDF_ReadFile \033[0m')
	print('\033[1;33m 34.SDF_WriteFile                              35.SDF_DeleteFile \033[0m')
	print('\033[1;33m 36.SDF_EnumFiles \033[0m')
	print('\033[1;35m *****************************密钥备份/恢复类函数************************************ \033[0m')
	print('\033[1;33m 37.dmsPCI_SegMentKey                          38.dmsPCI_GetSegMentKey \033[0m')
	print('\033[1;33m 39.dmsPCI_KeyRecoveryInit                     40.dmsPCI_ImportSegmentKey \033[0m')
	print('\033[1;33m 41.dmsPCI_KeyRecovery \033[0m')
	print('\033[1;33m 42.dmsPCI_SegMentKeyThreshold                 43.dmsPCI_GetSegMentKeyThreshold \033[0m')
	print('\033[1;33m 44.dmsPCI_KeyRecoveryInitThreshold            45.dmsPCI_ImportSegmentKeyThreshold \033[0m')
	print('\033[1;33m 46.dmsPCI_KeyRecoveryThreshold \033[0m')
	print('\033[1;35m *****************************密钥生产操作类函数************************************* \033[0m')
	print('\033[1;33m 47.dmsPCI_PCICardInit                         48.dmsPCI_PCICardGenerateMatrix \033[0m')
	print('\033[1;33m 49.dmsPCI_TestSelf                            50.dmsPCI_ImportPubMatrix \033[0m')
	print('\033[1;33m 51.dmsPCI_ExportPubMatrix                     52.dmsPCI_SVSGetKeyPoolState \033[0m')
	print('\033[1;33m 53.dmsPCI_SVSSetKeyIndex                      54.dmsPCI_GenECCKeyPair \033[0m')
	print('\033[1;33m 55.dmsPCI_SVSGenECCKeyPair                    56.dmsPCI_CalculatePersonKey \033[0m')
	print('\033[1;33m 57.dmsPCI_SVSImportKeyWithECCKeyPair          58.dmsPCI_SVSClearContainer \033[0m')
	print('\033[1;33m 59.dmsPCI_ChangeCardPIN                       60.dmsPCI_ChangeKeyPIN \033[0m')
	print('\033[1;33m 61.dmsPCI_GenerateKEK                         62.dmsPCI_DeleteKEK \033[0m')
	print('\033[1;33m 63.dmsPCI_CalculatePubKey                     64.dmsPCI_IdentifyECCSignForEnvelope \033[0m')
	print('\033[1;33m 65.dmsPCI_ImportKeyWithECCKeyPair             66.dmsPCI_GetKEKPoolStatus\033[0m')   
	print('\033[1;33m 67.dmsPCI_Generate_PKIKeyPair                 68.dmsPCI_ImportPKIEncryKeyPair \033[0m')   
	print('\033[1;33m 69.dmsPCI_SymKeyEncrypt                       70.dmsPCI_SymKeyDecrypt \033[0m')   
	print('\033[1;33m 71.dmsPCI_GetSymmKeyHandle                    72.dmsPCI_generate_symmkey_by_index \033[0m')   
	print('\033[1;33m 73.dmsPCI_CalculatePubKey_Optimize            74.dmsPCI_IdentifyECCSignForEnvelope_Optimize \033[0m')   
	print('\033[1;33m 75.dmsPCI_GeneratePartSignPri_NoCert          76.dmsPCI_SignValueVerify_NoCert \033[0m')   
	print('\033[1;33m 77.dmsPCI_Calculate_and_Export_PKS_NoCert     78.dmsPCI_Calculate_e_NoCert \033[0m') 
	print('\033[1;33m 79.dmsPCI_Export_PKM_Hash_Value               80.dmsPCI_SignValueVerify_NoCert_by_hiki_passed_in \033[0m') 
	print('\033[1;33m 81.dmsPCI_Calculate_and_Export_PKS_NoCert_by_hiki_passed_in \033[0m') 
	print('\033[1;33m 82.dmsPCI_Calculate_e_NoCert_by_hiki_passed_in \033[0m') 
	print('\033[1;31m 0.exit\033[0m ')    
	print('\033[1;35m ************************************END********************************************* \033[0m')

	value = input("\033[1;31m请输入接口对应数字进行测试:\033[0m")
	try:
		switch[value]()
	except KeyError as e:
		print('命令输入错误，请重新输入!')
