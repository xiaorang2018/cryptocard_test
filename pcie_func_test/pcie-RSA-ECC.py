#!/usr/bin/python3

from ctypes import *
import os
import sys
gm = cdll.LoadLibrary('./libpcisdf.so')
#gm = cdll.LoadLibrary('./libPciGUOMI.so')

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

RSAref_MAX_BITS = 2048
RSAref_MAX_LEN = int((RSAref_MAX_BITS + 7) / 8)
RSAref_MAX_PBITS = int((RSAref_MAX_BITS + 1) / 2)
RSAref_MAX_PLEN = int((RSAref_MAX_BITS + 7) / 8)

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
SGD_SM4_CTR = 0x00000412  # SM4运算crt模式
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
#*******************信封标识*******************************
CKI_ENVELOPE_ID_SIZE = 128
CKI_ENVELOPE_DATA_SIZE = 64
CKI_ENVELOPE_PUBLICKEY_SIZE = 132
CKI_ENVELOPE_SIGN_SIZE = 128
CKI_ENVELOPE_EID_SIZE = (CKI_ENVELOPE_ID_SIZE + CKI_ENVELOPE_DATA_SIZE + CKI_ENVELOPE_DATA_SIZE)



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
        ('BufferSize', c_uint)]

# 设备信息自定义
class DMS_DEVICEINFO(Structure):
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
        ('UserFileMaxNum', c_uint),
        ('ProcessMaxNum', c_uint),
        ('SessionMaxNum', c_uint),
        ('SessionTimeout_Sec', c_uint),
        ('SessionKeyMaxNum', c_uint),
        ('AsymKeyContainerMaxNum', c_uint),
        ('SymKeyMaxNum', c_uint),
        ('State', c_uint),
        ('Type', c_uint)]


#RSA公钥数据结构
class RSArefPublicKey(Structure):
    _fields_ = [
        ('bits', c_uint),
        ('m', c_ubyte * RSAref_MAX_LEN),
        ('e', c_ubyte * RSAref_MAX_LEN)]


#RSA私钥数据结构
class RSArefPrivateKey(Structure):
    _fields_ = [
        ('bits', c_uint), 
        ('m', c_ubyte * RSAref_MAX_LEN),
        ('e', c_ubyte * RSAref_MAX_LEN),
        ('d', c_ubyte * RSAref_MAX_LEN),
        ('prime', c_ubyte * RSAref_MAX_PLEN * 2),
        ('pexp', c_ubyte * RSAref_MAX_PLEN * 2),
        ('coef', c_ubyte * RSAref_MAX_PLEN)]


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
        ('C', c_ubyte * 16)]


# ECC签名数据结构
class ECCSignature(Structure):
    _fields_ = [
        ('r', c_ubyte * ECCref_MAX_LEN),
        ('s', c_ubyte * ECCref_MAX_LEN)]


# ECC公钥交换数据块，该结构体定义在GM/T 0016
class ECCCipehrBlob(Structure):
    _fields_ = [('XCoordinate', ArrX),
                ('YCoordinate', ArrY),
                ('HASH', c_ubyte * 32),
                ('CipherLen', c_uint),
                ('Cipher', c_ubyte * 16)]

# ECC加密密钥对保护结构
class EnvelopedKeyBlob(Structure):
    _fields_ = [
	('ulAsymmAlgID', c_uint),
	('ulSymmAlgID', c_uint),
	('PubKey', ECCrefPrivateKey),
	('cbEncryptedPriKey', c_ubyte * 64),
	('ECCCipehrBlob', ECCCipher)]

# 密钥池结构
class KeyPoolStateInfo(Structure):
    _fields_ = [
        ('uiKeyPoolSize', c_uint),
        ('ucKeyPoolStates', c_ubyte * KEY_POOL_SIZE_MAX)]
        
# 信封内容结构
class CkiEnvelopeContent(Structure):
    _fields_ = [('id', c_ubyte * CKI_ENVELOPE_ID_SIZE),
                ('licenceIssuingauthority', c_ubyte * CKI_ENVELOPE_ID_SIZE),
                ('pke', c_ubyte * CKI_ENVELOPE_PUBLICKEY_SIZE),
                ('pks', c_ubyte * CKI_ENVELOPE_PUBLICKEY_SIZE),
                ('takeEffectDate', c_ubyte * CKI_ENVELOPE_DATA_SIZE),
                ('loseEffectDate', c_ubyte * CKI_ENVELOPE_DATA_SIZE)]

#信封
class CkiEnvelope(Structure):
    _fields_ = [('signAlgorithm',c_uint),
                ('sign', c_ubyte * CKI_ENVELOPE_SIGN_SIZE),
                ('enve', CkiEnvelopeContent)]
                
                

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

pucPublicKey = ECCrefPublicKey()
pucPrivateKey = ECCrefPrivateKey()
pucSignature = ECCSignature()
pucEncData = ECCCipher()
pTmpSignPublicKey = ECCrefPublicKey()
pTmpEncPublicKey = ECCrefPublicKey()
pEnv = CkiEnvelope()
pSke = EnvelopedKeyBlob()

pucData = arr32()
uiDataLength = c_int(32)
Hash = arr32()
HashLength = 32
memset(Hash, 0x11, sizeof(Hash))
	
pucIV = arr16()
pucEncData = (c_ubyte * 16384)()
puiEncDataLength = c_uint()
pucDecData = (c_ubyte * 16384)()
puiDecDataLength = c_uint()

puiMatLen = c_uint(32788)
pucPubMatrix = (c_ubyte * 32790)()

pECCPubkeyPa = ECCrefPublicKey()

pucPublicKeyRSA = RSArefPublicKey()
pucPrivateKeyRSA = RSArefPrivateKey()
pucKeyRSA = (c_ubyte * 1024)()
puiKeyRSALength = c_uint()


#**********************函数定义开始*************************
def PrintData(itemName, sourceData, dataLength, rowCount):
    if (sourceData ==None) and (rowCount == 0) and (dataLength == 0):
        return -1 
    if itemName != None:
        print("\n%s[%d]:"%(itemName, dataLength), end = '')
    for i in range(dataLength//rowCount):
        print("\n%d" % (i*rowCount))
        for j in range(rowCount):
            print("%02x" % sourceData[i*rowCount + j], end = ' ')
    if dataLength % rowCount ==0:
        return 0
    print("\n%d"%((dataLength//rowCount)*rowCount))
    for j in range(dataLength%rowCount):
        print("%02x" % sourceData[dataLength//rowCount*rowCount + j], end = ' ')
    return 0
                
def SDF_OpenDevice():
	ret = gm.SDF_OpenDevice(byref(hDeviceHandle))
	if ret == 0:
		print("SDF_Opendevice success，ret = " + hex(ret))
		print("hDeviceHandle ID =" + hex(hDeviceHandle.value))
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
		print("hDeviceHandle ID =" + hex(hDeviceHandle.value))
	else:
		print("SDF_CloseDevice fail，ret = " + hex(ret))

def SDF_OpenSession():
	ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
	if ret == 0:
		print("SDF_OpenSession success, ret = " + hex(ret))
		print("hSessionHandle ID = " + hex(hSessionHandle.value))
	else:
		print("SDF_OpenSession fail, ret = " + hex(ret)) 


def SDF_CloseSession():
	ret = gm.SDF_CloseSession(hSessionHandle)
	if ret == 0:
		print("SDF_CloseSession success, ret = " + hex(ret))
		print("hSessionHandle ID = " + hex(hSessionHandle.value))
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
	else:
		print('SDF_GetDeviceInfo fail, ret = ' + hex(ret))

def SDF_GenerateRandom():
	uiLength = int(input('please enter random length（1~16K=16384）：'))
	pucRandom = (c_ubyte * 65536)()
	ret = gm.SDF_GenerateRandom(hSessionHandle, uiLength, pucRandom)
	if ret == 0:
		print('SDF_GenerateRandom success, ret  = ' + hex(ret))
		PrintData("random", pucRandom, uiLength, 32)
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
	uiKeyIndex = input('please enter the index(0~49999): ')
	ret = gm.SDF_ReleasePrivateKeyAccessRight(hSessionHandle, int(uiKeyIndex))
	if ret == 0:
		print('SDF_ReleasePrivateKeyAccessRight success, ret = ' + hex(ret))
	else:
		print('SDF_ReleasePrivateKeyAccessRight fail, ret = ' + hex(ret))

def SDF_ExportSignPublicKey_ECC():
	uiKeyIndex = input('please enter the index(0~49999): ')
	ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
	if ret == 0:
		print('SDF_ExportSignPublicKey_ECC success, ret = ' + hex(ret))
		PrintData("publicKey.x", pucPublicKey.x, 64, 32)
		PrintData("publicKey.y", pucPublicKey.y, 64, 32)
	else:
		print('SDF_ExportSignPublicKey_ECC fail, ret = ' + hex(ret))

def SDF_ExportEncPublicKey_ECC():
	uiKeyIndex = input('please enter the index(0~49999): ')
	pucPublicKey = ECCrefPublicKey()
	ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
	if ret == 0:
		print('SDF_ExportEncPublicKey_ECC success, ret = ' + hex(ret))
		PrintData("publicKey.x", pucPublicKey.x, 64, 32)
		PrintData("publicKey.y", pucPublicKey.y, 64, 32)
	else:
		print('SDF_ExportEncPublicKey_ECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyPair_ECC():
	uiKeyBits = input('please input the KeyBits: ')
	uiAlgID = SGD_SM2
	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, int(uiKeyBits), byref(pucPublicKey), byref(pucPrivateKey))
	if ret == 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))
		PrintData("publicKey.x", pucPublicKey.x, 64, 32)
		PrintData("publicKey.y", pucPublicKey.y, 64, 32)
		PrintData("privateKey.K", pucPrivateKey.K, 64, 32)
	else:
		print('SDF_GenerateKeyPair_ECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithIPK_ECC():
	uiIPKIndex = input('please input the index：')
	uiKeyBits = input('please input the keybits：')
	ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, int(uiIPKIndex), int(uiKeyBits), byref(pucKey), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithIPK_ECC success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
		print('sessionKey ID: '+hex(phKeyHandle.value))
	else:
		print('SDF_GenerateKeyWithIPK_ECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithEPK_ECC():
	uiKeyBits = input('please input the keybits：')
	uiAlgID = SGD_SM2_3
	ret  = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, int(uiKeyBits), uiAlgID, byref(pucPublicKey), byref(pucKey), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithEPK_ECC success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
	else:
		print('SDF_GenerateKeyWithEPK_ECC fail ret = ' + hex(ret))

def SDF_ImportKeyWithISK_ECC():
	uiISKIndex = input('please input the index:')
	ret = gm.SDF_ImportKeyWithISK_ECC(hSessionHandle, int(uiISKIndex), byref(pucKey), byref(phKeyHandle))
	if ret == 0:
		print('SDF_ImportKeyWithISK_ECC success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
	else:
		print('SDF_ImportKeyWithISK_ECC fail, ret = ' + hex(ret))

def SDF_GenerateAgreementDataWithECC():
	uiISKIndex = uiKeyIndex = input('please input the index: ')
	uiKeyBits = input('please input the keybits：')
    
	ret = gm.SDF_GenerateAgreementDataWithECC(hSessionHandle, int(uiISKIndex), int(uiKeyBits), pucSponsorID.encode(), uiSponsorIDLength, byref(pucSponsorPublicKey), byref(pucSponsorTmpPublicKey), byref(phAgreementHandle))
	if ret == 0:
		print('SDF_GenerateAgreementDataWithECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenenrateAgreementDataWithECC fail ,ret = ' + hex(ret))


def SDF_GenerateKeyWithECC():
	ret = gm.SDF_GenerateKeyWithECC(hSessionHandle, pucResponseID.encode(), uiResponseIDLength, byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey), phAgreementHandle, byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithECC success, ret = ' + hex(ret))
		print('发起方phKeyHandle ID = ' + hex(phKeyHandle.value))
	else:
		print('SDF_GenerateKeyWithECC fail, ret = ' + hex(ret))


def SDF_GenerateAgreementDataAndKeyWithECC():
	uiISKIndex = index = input('please input the index: ')
	uiKeyBits = input('please input the the keybits：')
	ret = gm.SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, int(uiISKIndex), int(uiKeyBits), pucResponseID.encode(), uiResponseIDLength, pucSponsorID.encode(), uiSponsorIDLength, byref(pucSponsorPublicKey), byref(pucSponsorTmpPublicKey), byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey), byref(phKeyHandle)) 
	if ret == 0:
		print('SDF_GenerateAgreementDataAndKeyWithECC success, ret = ' + hex(ret))
		print('响应方phKeyHandle ID = ' + hex(phKeyHandle.value))
	else:
		print('SDF_GenerateAgreementDataAndKeyWithECC fail, re = ' + hex(ret))
    

def SDF_ExchangeDigitEnvelopeBaseOnECC():
	uiIPKIndex = input('please input the index：')
	uiKeyBits = input('please input the keybits of exchange:：')
	pucEncDataIn = ECCCipher()
	pucEncDataOut = ECCCipher()
	uiAlgID = SGD_SM2_3
	ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, int(uiIPKIndex), int(uiKeyBits), byref(pucEncDataIn), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithIPK_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenerateKeyWithIPK_ECC fail, ret = ' + hex(ret))

	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, 256, byref(pucPublicKey), byref(pucPrivateKey))
	if ret == 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_GenerateKeyPair_ECC fail, ret = ' + hex(ret))
	uiAlgID = SGD_SM2_2
	ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiIPKIndex), uiAlgID, byref(pucPublicKey), byref(pucEncDataIn), byref(pucEncDataOut))
	if ret ==  0:
		print('SDF_ExchangeDigitEnvelopeBaseOnECC sucess,  ret = ' + hex(ret))
	else:
		print('SDF_ExchangeDigitEnvelopeBaseOnECC fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithKEK():
	uiKEKIndex = input('please input the KEK index(1-300): ')
	uiKeyBits = input('please input the keybits(128): ')
	uiAlgID = SGD_SM4_ECB
	global pucKey
	pucKey = (c_ubyte * 1024)()
	puiKeyLength = c_uint()
	ret = gm.SDF_GenerateKeyWithKEK(hSessionHandle, int(uiKeyBits), uiAlgID, int(uiKEKIndex), pucKey, byref(puiKeyLength), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenenrateKeyWithKEK success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
	else:
		print('SDF_GenerateKeyWithKEK fail, ret = ' + hex(ret))

def SDF_ImportKeyWithKEK():	
	uiKEKIndex = input('please input the KEK index(1~300): ')
	puiKeyLength = input('please input the KeyLength(16): ')
	uiAlgID = SGD_SM4_ECB
	ret = gm.SDF_ImportKeyWithKEK(hSessionHandle, uiAlgID, int(uiKEKIndex), pucKey, int(puiKeyLength), byref(phKeyHandle))
	if ret == 0:
		print('SDF_ImportKeyWithKEK success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
	else:
		print('SDF_ImportKeyWithKEK fail, ret = ' + hex(ret))
        

def SDF_ImportKey():
        pucKey = arr512()
        uiKeyLength = input('please input session key length(1~64): ')
        ret = gm.SDF_GenerateRandom(hSessionHandle, int(uiKeyLength), pucKey)
        if ret != 0:
                print('SDF_GenerateRandom fail, ret  = ' + hex(ret))
	
       	ret = gm.SDF_ImportKey(hSessionHandle, pucKey, int(uiKeyLength), byref(phKeyHandle))
        if ret == 0:
                print('SDF_ImportKey success, ret = ' + hex(ret))
                print('ImportKey SessionKey ID: 0x%x'%(phKeyHandle.value))
        else:
                print('SDF_ImportKey fail, ret = ' + hex(ret))


def SDF_DestroyKey():
    #phAgreementHandle,phKeyHandle
	ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
	if ret == 0:
		print('SDF_DestroyKey success, ret = ' + hex(ret))
		print('phKeyHandle ID = %x' %hex(phKeyHandle.value))
	else:
		print('SDF_DestroyKey fail, ret = ' + hex(ret))



def SDF_InternalSign_ECC():
	uiIndex = input('please input the index: ')
	ret = gm.SDF_InternalSign_ECC(hSessionHandle, int(uiIndex), Hash, HashLength, byref(pucSignature))
	if ret == 0:
		print('SDF_InternalSign_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_InternalSign_ECC fail, ret = ' + hex(ret))

def SDF_InternalVerify_ECC():
	uiIndex = input('please input the index: ')
	ret = gm.SDF_InternalVerify_ECC(hSessionHandle,int(uiIndex), Hash, HashLength, byref(pucSignature))
	if ret == 0:
		print('SDF_InternalVerify_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_InternalVerify_ECC fail, ret = ' + hex(ret))


def SDF_ExternalSign_ECC():
	uiAlgID = SGD_SM2_1
	ret = gm.SDF_ExternalSign_ECC(hSessionHandle, uiAlgID, byref(pucPrivateKey), Hash, HashLength, byref(pucSignature))
	if ret == 0:
		print('SDF_ExternalSign_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExternalSign_ECC fail, ret = ' + hex(ret))

def SDF_ExternalVerify_ECC():
	uiAlgID = SGD_SM2_1
	ret = gm.SDF_ExternalVerify_ECC(hSessionHandle, uiAlgID, byref(pucPublicKey), Hash, 32, byref(pucSignature))
	if ret ==0:
		print('SDF_ExternalVerify_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExternalVerify_ECC fail, ret = ' + hex(ret))


def SDF_ExternalEncrypt_ECC():
	uiAlgID = SGD_SM2_3
	uiDataLength = int(input('please input your data length(1~16K=16384): '))
	pucData = (c_ubyte * 65536)()
	ret = gm.SDF_GenerateRandom(hSessionHandle, uiDataLength, pucData)
	if ret == 0:
		PrintData("encrypt plaintext", pucData, uiDataLength, 32)
	else:
		print("generate encrypt plaintext fail")
	ret = gm.SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, byref(pucPublicKey), pucData, uiDataLength, byref(pucEncData))
	if ret ==0:
		print('\nSDF_ExternalEncrypt_ECC success, ret = ' + hex(ret))
	else:
		print('SDF_ExternalEncrypt_ECC fail, ret = ' + hex(ret))
        
 
def SDF_ExternalDecrypt_ECC():
	uiAlgID = SGD_SM2_3
	ret = gm.SDF_ExternalDecrypt_ECC(hSessionHandle, uiAlgID, byref(pucPrivateKey), byref(pucEncData), pucData, byref(uiDataLength))
	if ret ==0:
		print('SDF_ExternalDecrypt_ECC success, ret = ' + hex(ret))
		PrintData("decrypt plaintext", pucData, uiDataLength.value, 32)
	else:
		print('SDF_ExternalDecrypt_ECC fail, ret = ' + hex(ret))


def SDF_HashInit():
	pucSignID = input('please input the SignID(max=128): ')
	uiSignIDLen = len(pucSignID)
	AlgID = SGD_SM3
	PrintData("Hash publicKey.x", pucPublicKey.x, 64, 32)
	PrintData("Hash publicKey.y", pucPublicKey.y, 64, 32)
	ret = gm.SDF_HashInit(hSessionHandle, AlgID, byref(pucPublicKey), pucSignID.encode(), uiSignIDLen)
	if ret == 0:
		print("\nSDF_HashInit success, ret = 0x%x" % ret)
	else:
		print("\nSDF_HashInit fail, ret = 0x%08x" % ret)	


def SDF_HashUpdate():
	pucData = input('please input the Data(max=128): ')
	uiDataLenigth = len(pucData)
	ret = gm.SDF_HashUpdate(hSessionHandle, pucData.encode(), uiDataLength)
	if ret ==0:
		print('SDF_HashUpdate success, ret = ' + hex(ret))
	else:
		print('SDF_HashUpdate fail, ret = ' + hex(ret))


def SDF_HashFinal():
	uiHashLength = c_uint()
	ret = gm.SDF_HashFinal(hSessionHandle, Hash, byref(uiHashLength))
	if ret ==0:
		print('SDF_HashFinal success, ret = ' + hex(ret))
		PrintData("HashValue", Hash, 32, 32)
	else:
		print('SDF_HashFinal fail, ret ' + hex(ret))

def SDF_Encrypt():
	uiDataLength = int(input('please input your data length(1~16K=16384): '))
	pucData = (c_ubyte * 65536)()
	ret = gm.SDF_GenerateRandom(hSessionHandle, uiDataLength, pucData)
	if ret == 0:
		PrintData("plaintext", pucData, uiDataLength, 32)
	else:
		print("generate encrypt plaintext fail")
	uiAlgID = SGD_SM4_ECB
	memset(pucIV, 0x00, sizeof(pucIV))
	print('\nsessionKey ID: 0x%x'%phKeyHandle.value)
	ret = gm.SDF_Encrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData, byref(puiEncDataLength))
	if ret == 0:
		print('SDF_Encrypt sucess, ret = ' + hex(ret))
	else:
		print('SDF_Encrypt fail, ret = ' + hex(ret))

def SDF_Decrypt():
	uiAlgID = SGD_SM4_ECB
	plain = arr1024()
	plainLength = c_uint()
	memset(pucIV, 0x00, sizeof(pucIV))
	print('sessionKey ID: 0x%x'%phKeyHandle.value)
	ret = gm.SDF_Decrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucEncData, puiEncDataLength, plain, byref(plainLength))
	if ret == 0:
		print('SDF_Decrypt success, ret = ' + hex(ret))
		PrintData("decrypt plaintext", plain, plainLength.value, 32)
	else:
		print('SDF_Decrypt fail, ret = ' + hex(ret))

def SDF_CalculateMAC():

	uiAlgID = SGD_SM4_MAC
	memset(pucIV, 0x00, sizeof(pucIV))
	uiInDataLength = int(input('please input your data length(1~16K=16384): '))
	pucInData = (c_ubyte * 65536)()
	ret = gm.SDF_GenerateRandom(hSessionHandle, uiInDataLength, pucInData)
	if ret == 0:
		PrintData("MAC plaintext", pucInData, uiInDataLength, 32)
	else:
		print("generate MAC plaintext fail")
	pucMAC = arr4()
	uiMACLength = c_uint()
	ret = gm.SDF_CalculateMAC(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucInData, uiInDataLength, pucMAC, byref(uiMACLength))
	if ret == 0:
		print('\nSDF_CalcaluteMAC success, ret = ' + hex(ret))
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
        
        
def SDF_dmsPCI_SegMentKeyInit():
	global sgmNum
	sgmNum = input('please input the sgmNum(2<=sgmNum<=9): ')
	pin = input('please input the device pin: ')
	pinLen = len(pin)
	ret = gm.SDF_dmsPCI_SegMentKeyInit(hSessionHandle, int(sgmNum), pin.encode(), pinLen)
	if ret == 0:
		print("SDF_dmsPCI_SegMentKeyInit success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_SegMentKeyInit fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_GetSegMentKey():
	pin = input('please input the protect pin: ')
	pinLen = len(pin)
	global pucSegKey, puiSegKeyLen
	pucSegKey = (c_ubyte * 30 * 1024 *1024 * int(sgmNum))()
	puiSegKeyLen = c_uint()
	for i in range(int(sgmNum)):
		ret = gm.SDF_dmsPCI_GetSegMentKey(hSessionHandle, pin.encode(), pinLen, byref(puiSegKeyLen), byref(pucSegKey, i * 30 * 1024 *1024))
		if ret == 0:
			print("SDF_dmsPCI_GetSegMentKey success, ret = 0x%x" % ret)
		else:
			print("SDF_dmsPCI_GetSegMentKey fail, ret = 0x%08x" % ret)
			return 0


def SDF_dmsPCI_SegMentKeyFinal():
	ret = gm.SDF_dmsPCI_SegMentKeyFinal(hSessionHandle)
	if ret == 0:
		print("SDF_dmsPCI_SegMentKeyFinal success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_SegMentKeyFinal fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_KeyRecoveryInit():
	ret = gm.SDF_dmsPCI_KeyRecoveryInit(hSessionHandle)
	if ret == 0:
		print("SDF_dmsPCI_KeyRecoveryInit success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_KeyRecoveryInit fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_ImportSegmentKey():
	pin = input('please input the protect pin: ')
	pinLen = len(pin)
	for i in range(int(sgmNum)):
		ret = gm.SDF_dmsPCI_ImportSegmentKey(hSessionHandle, pin.encode(), pinLen, byref(pucSegKey, i * 30 * 1024 *1024), puiSegKeyLen)
		if ret == 0:
			print("SDF_dmsPCI_ImportSegmentKey success, ret = 0x%x" % ret)
		else:
			print("SDF_dmsPCI_ImportSegmentKey fail, ret = 0x%08x" % ret)
			return 0


def SDF_dmsPCI_KeyRecovery():
	sgmNum = input('please input the sgmNum: ')
	ret = gm.SDF_dmsPCI_KeyRecovery(hSessionHandle, int(sgmNum))
	if ret == 0:
		print("SDF_dmsPCI_KeyRecovery success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_KeyRecovery fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_Backup_Threshold():
	pin = input('please input the device pin: ')
	pinLen = len(pin)
	global sgmNum, recoverNum
	sgmNum = int(input('please input the sgmNum: '))
	recoverNum = int(input('please input the recoverNum: '))
	global pucPciData, puiPciDataLen
	puiPciDataLen = c_uint()
	ret = gm.SDF_dmsPCI_Backup_Threshold(hSessionHandle, 0, 0, 0, None, None, byref(puiPciDataLen))
	if ret != 0:
		print("SDF_dmsPCI_Backup_Threshold fail, ret = 0x%08x" % ret)
		
	pucPciData = (c_ubyte * (puiPciDataLen.value))()
	ret = gm.SDF_dmsPCI_Backup_Threshold(hSessionHandle, 
					sgmNum, recoverNum, 
					pinLen, pin.encode(),
					pucPciData, byref(puiPciDataLen))
	if ret == 0:
		print("SDF_dmsPCI_Backup_Threshold success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_Backup_Threshold fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_ExportSegmentKey_Threshold():
        uiKeyIndex = input('please input the publicKey index of protect segKey：')
        # 导出公钥
        pPubKey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pPubKey))
        if ret == 0:
                print("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
                print("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)

        # 导出分割对称密钥的密文结构
        global pCipherKey, pCipherKeyLen
        pCipherKey = (c_ubyte * 980)()
        pCipherKeyLen = c_uint()
        for i in range(recoverNum):
                ret = gm.SDF_dmsPCI_ExportSegmentKey_Threshold(hSessionHandle, byref(pPubKey), byref(pCipherKey, i * 196), byref(pCipherKeyLen))
                if ret == 0:
                       print("第 %d 次：SDF_dmsPCI_ExportSegmentKey_Threshold success, ret = 0x%x" % (i + 1, ret))
                       print('pCipherKey1Len = %d'%pCipherKeyLen.value)
                else:
                       print("SDF_dmsPCI_ExportSegmentKey_Threshold fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_GetEncPubKey_Threshold():
        pPubKey = (c_ubyte * 132)()
        ret = gm.SDF_dmsPCI_GetEncPubKey_Threshold(hSessionHandle, pPubKey)
        if ret == 0:
                print("SDF_dmsPCI_GetEncPubKey_Threshold success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsPCI_GetEncPubKey_Threshold fail, ret = 0x%08x" % ret)
        # 数字信封交换
        uiAlgID = SGD_SM2_3
        uiKeyIndex = input("please input the publicKey index of protect segKey：")
        global pCipherKeyEx
        pCipherKeyEx = (c_ubyte * 980)()
        #模拟ukey端，用卡导出的公钥替换ukey端对称密钥分割密钥的加密公钥。
        for i in range(recoverNum):
                ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiKeyIndex), uiAlgID, pPubKey, byref(pCipherKey, i * 196),  byref(pCipherKeyEx, i* 196))
                if ret == 0:
                       print("第 %d 次: ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % (i + 1,ret))
                else:
                       print("ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)



def SDF_dmsPCI_ImportSegmentKey_Threshold():
	for i in range(recoverNum):
	        ret = gm.SDF_dmsPCI_ImportSegmentKey_Threshold(hSessionHandle, byref(pCipherKeyEx, i * 196), pCipherKeyLen.value)
	        if ret == 0:
                       print("第 %d 次: 导入SDF_dmsPCI_ImportSegmentKey_Threshold success, ret = 0x%x" % (i + 1, ret))
	        else:
                       print("SDF_dmsPCI_ImportSegmentKey_Threshold fail, ret = 0x%08x" % ret)
	

def SDF_dmsPCI_Restore_Threshold():
	ret = gm.SDF_dmsPCI_Restore_Threshold(hSessionHandle, recoverNum, pucPciData, puiPciDataLen.value)
	if ret == 0:
		print("SDF_dmsPCI_Restore_Threshold success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_Restore_Threshold fail, ret = 0x%08x" % ret)
        
def SDF_dmsPCI_TestSelf():
	ret = gm.SDF_dmsPCI_TestSelf(hSessionHandle)
	if ret == 0:
		print("dmsPCI_TestSelf success, ret = 0x%x" % ret)
	else:
		print("dmsPCI_TestSelf fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_PCICardInit():
	pin = input("please input pin: ")
	pinLen = len(pin)
	pciCardType = input("please input the pciCard Type(1:KMC  2:IMC): ")
	ret = gm.SDF_dmsPCICardInit(hSessionHandle, int(pciCardType), pin.encode(), int(pinLen))
	if ret == 0:
		print('dmsPCI_PCICardInit success, ret = ' + hex(ret))
	else:
		print('dmsPCI_PCICardInit fail, ret  = ' + hex(ret))


def SDF_dmsPCI_GetKeyPoolState():
	pKeyPoolStInfo = KeyPoolStateInfo()
	ret = gm.SDF_dmsPCI_GetKeyPoolState(hSessionHandle, byref(pKeyPoolStInfo))
	if ret == 0:
		print("SDF_dmsPCI_GetKeyPoolState success, ret = 0x%x" % ret)
		print("密钥池状态：\n%s" % pKeyPoolStInfo.ucKeyPoolStates[:])
	else:
		print("SDF_dmsPCI_GetKeyPoolState fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_PCICardGenerateMatrix():
	ret = gm.SDF_dmsPCI_PCICardGenerateMatrix(hSessionHandle)
	if ret == 0:
		print("SDF_dmsPCI_PCICardGenerateMatrix success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_PCICardGenerateMatrix fail, ret = 0x%08x" % ret)



def SDF_dmsPCI_ImportPubMatrix():
	#pucPubMatrix[4] = 10
	print("待导入公钥矩阵数据：\n%s" % pucPubMatrix[:])
	ret = gm.SDF_dmsPCI_ImportPubMatrix(hSessionHandle, pucPubMatrix, puiMatLen.value)
	if ret == 0:
		print("SDF_dmsPCI_ImportPubMatrix success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_ImportPubMatrix fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_ExportPubMatrix():
	ret = gm.SDF_dmsPCI_ExportPubMatrix(hSessionHandle, pucPubMatrix, byref(puiMatLen))
	if ret == 0:
		print("SDF_dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
		print("公钥矩阵数据: \n%s" % pucPubMatrix[:])
		print("公钥矩阵长度：\n%x" % puiMatLen.value)
	else:
		print("SDF_dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_GenECCKeyPair():
        uiKeyIndex = input('please input the KeyIndex: ')
        ret = gm.SDF_dmsPCI_GenECCKeyPair(hSessionHandle, int(uiKeyIndex), byref(pTmpSignPublicKey), byref(pTmpEncPublicKey))
        if ret == 0:
               	print("SDF_dmsPCI_GenECCKeyPair success, ret = 0x%x" % ret)
                
        else:
                print("SDF_dmsPCI_GenECCKeyPair fail, ret = 0x%08x" % ret)



def SDF_dmsPCI_CalculatePersonKey():
        uiRegion = int(input('please input the Region(0~255): '))
        pucIdentify = input('please input the Identify(max=128): ')
        pucLicenceIssuingAuthority = input('please input the LicenceIssuingAuthority(max=128): ')
        pucTakeEffectDate = input('please input the TakeEffectDate(1~63): ')
        pucLoseEffectDate = input('please input the LoseEffectDate(1~63): ')
        print("######################上传临时公钥######################")
        print("TmpSignPublicKey x分量：\n%s" % pTmpSignPublicKey.x[:])
        print("TmpSignPublicKey y分量：\n%s" % pTmpSignPublicKey.y[:])
        print("TmpEncPublicKey x分量：\n%s" % pTmpEncPublicKey.x[:])
        print("TmpEncPublicKey y分量：\n%s" % pTmpEncPublicKey.y[:])
        print("Region：%s" % uiRegion)
        print("Id: %s, IdLen: %d" % (pucIdentify, len(pucIdentify)))
        print("LIA: %s, LIALen: %d" % (pucLicenceIssuingAuthority, len(pucLicenceIssuingAuthority)))
        print("takeDate: %s, takeDateLen: %d" % (pucTakeEffectDate, len(pucTakeEffectDate)))
        print("loseDate: %s, loseDateLen: %d" % (pucLoseEffectDate, len(pucLoseEffectDate)))
        ret = gm.SDF_dmsPCI_CalculatePersonKey(hSessionHandle, uiRegion,
                                           pucIdentify.encode(), pucLicenceIssuingAuthority.encode(),
                                           pucTakeEffectDate.encode(), pucLoseEffectDate.encode(), 
                                           byref(pTmpSignPublicKey), byref(pTmpEncPublicKey),
                                           byref(pEnv), byref(pSke))
        if ret == 0:
                print("SDF_dmsPCI_CalculatePersonKey success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsPCI_CalculatePersonKey fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_ImportKeyWithECCKeyPair():
        uiKeyIndex = int(input('please input the KeyIndex: '))
        ret = gm.SDF_dmsPCI_ImportKeyWithECCKeyPair(hSessionHandle, uiKeyIndex, byref(pSke))
        if ret == 0:
                print("SDF_dmsPCI_ImportKeyWithECCKeyPair success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsPCI_ImportKeyWithECCKeyPair fail, ret = 0x%08x" % ret)
	


def SDF_dmsPCI_SVSClearContainer():
	uiKeyIndex = input('please input the KeyIndex: ')
	ret = gm.SDF_dmsPCI_SVSClearContainer(hSessionHandle, int(uiKeyIndex))
	if ret == 0:
		print("SDF_dmsPCI_SVSClearContainer success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_SVSClearContainer fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_ChangeCardPIN():
	pcOldManagePin = input('please input the old device password: ')
	pcNewManagePin = input('please input the new device password: ')
	ret = gm.SDF_dmsPCI_ChangeCardPIN(hSessionHandle, pcOldManagePin.encode(), pcNewManagePin.encode())
	if ret == 0:
		print("SDF_dmsPCI_ChangeCardPIN success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_ChangeCardPIN fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_ChangeKeyPIN():
	uiKeyIndex = input('please input the index: ')
	pcOldKeyPin = input('please input the old key password: ')
	pcNewKeyPin = input('please input the new key password: ')
	ret = gm.SDF_dmsPCI_ChangeKeyPIN(hSessionHandle, int(uiKeyIndex), pcOldKeyPin.encode(), pcNewKeyPin.encode())
	if ret == 0:
		print("SDF_dmsPCI_ChangeKeyPIN success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_ChangeKeyPIN fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_GenerateKEK():
	puiKEKindex = c_uint()
	uiKEKBitLen = input('please input the KEK length(128)：')
	ret = gm.SDF_dmsPCI_GenerateKEK(hSessionHandle, int(uiKEKBitLen), byref(puiKEKindex))
	if ret == 0:
		print("SDF_dmsPCI_GenerateKEK success, ret = 0x%x" % ret)
		print("puiKEKindex:%x" % puiKEKindex.value)
	else:
		print("SDF_dmsPCI_GenerateKEK fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_DeleteKEK():
	uiKEKindex = input('please input the KEK index(1~100): ')
	ret = gm.SDF_dmsPCI_DeleteKEK(hSessionHandle, int(uiKEKindex))
	if ret == 0:
		print("SDF_dmsPCI_DeleteKEK success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_DeleteKEK fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_GetKEKPoolState():
        pucKEKStatus = (c_ubyte * 300)()	
        puiMaxSize = c_uint(300)
        ret = gm.SDF_dmsPCI_GetKEKPoolState(hSessionHandle, pucKEKStatus, byref(puiMaxSize))
        if ret == 0:
                print("SDF_dmsPCI_GetKEKPoolState success, ret = 0x%x" % ret)
                print("KEKPoolStatus: %s"%pucKEKStatus[:])
        else:
                print("SDF_dmsPCI_GetKEKPoolState fail, ret = 0x%08x" % ret)


def SDF_dmsGenerate_PKIKeyPair():
        uiKeyIndex = input('please input the KeyIndex(0~49): ')
        KeyFlag = input('please input the KeyFlag(enc:1, sign:2, encAndsign:3): ')
        pucPublicKey = (c_ubyte * 132)()
        pucPrivateKey = (c_ubyte * 68)()
        ret = gm.SDF_dmsGenerate_PKIKeyPair(hSessionHandle, int(uiKeyIndex), int(KeyFlag), pucPublicKey, pucPrivateKey)
        if ret == 0:
                print("SDF_dmsGenerate_PKIKeyPair success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsGenerate_PKIKeyPair fail, ret = 0x%08x" % ret)	


def SDF_dmsPCI_GenerateKEKByIndex():
        index = input('please input the index: ')
        bitLen = input('please input the bitLen: ')
        ret = gm.SDF_dmsPCI_GenerateKEKByIndex(hSessionHandle, int(index), int(bitLen))
        if ret == 0:
                print("SDF_dmsPCI_GenerateKEKByIndex success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsPCI_GenerateKEKByIndex fail, ret = 0x%08x" % ret)                             


def SDF_dmsPCI_CalculatePubKey():
	uiRegion = 0
	pucIdentity = input('please input the Identity: ')
	uiIdentityLen = len(pucIdentity)
	ret = gm.SDF_dmsPCI_CalculatePubKey(hSessionHandle, uiRegion,
						pucIdentity, uiIdentityLen, byref(pucPublicKey))
	if ret == 0:
                print("SDF_dmsPCI_CalculatePubKey success, ret = 0x%x" % ret)
                PrintData("publicKey.x", pucPublicKey.x, 64, 32)
                PrintData("publicKey.y", pucPublicKey.y, 64, 32)
	else:
		print("SDF_dmsPCI_CalculatePubKey fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_CalculatePubKey_Optimize():
        uiRegion = 0
        pucIdentity = input('please input the Identity: ')
        uiIdentityLen = len(pucIdentity)
        ret = gm.SDF_dmsPCI_CalculatePubKey_Optimize(hSessionHandle, uiRegion,
                                                pucIdentity.encode(), uiIdentityLen, byref(pucPublicKey))
        if ret == 0:
                print("SDF_dmsPCI_CalculatePubKey_Optimize success, ret = 0x%x" % ret)
                PrintData("publicKey.x", pucPublicKey.x, 64, 32)
                PrintData("publicKey.y", pucPublicKey.y, 64, 32) 
        else:
                print("SDF_dmsPCI_CalculatePubKey_Optimize fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_IdentifyECCSignForEnvelope():
	uiRegion = 0
	pucIdentity = input('please input the Identity(max=128): ')
	uiIdentityLen = len(pucIdentity)
	pucSignID = input('please input the SignID(max=128): ')
	uiSignIDLen = len(pucSignID)
	pucData = input('please input the Data: ')
	uiDataLen = len(pucData)
	ret = gm.SDF_dmsPCI_IdentifyECCSignForEnvelope(hSessionHandle, uiRegion,
							pucIdentity.encode(), uiIdentityLen,
							pucSignID.encode(), uiSignIDLen,
							pucData.encode(), uiDataLen,
							byref(pucSignature))
	if ret == 0:
		print("SDF_dmsPCI_IdentifyECCSignForEnvelope success, ret = 0x%x" % ret)
		print('pucSignature.r =')
		for i in range(64):
                       	print(hex(pucSignature.r[i]), end = ' ') 
		print('\npucSignature.s =')
		for j in range(64):
                        print(hex(pucSignature.s[j]), end = ' ') 
	else:
		print("SDF_dmsPCI_IdentifyECCSignForEnvelope fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize():
        uiRegion = 0
        pucIdentity = input('please input the Identity(max=128): ')
        uiIdentityLen = len(pucIdentity)
        pucSignID = input('please input the SignID(max=128): ')
        uiSignIDLen = len(pucSignID)
        pucData = input('please input the Data: ')
        uiDataLen = len(pucData)
        ret = gm.SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize(hSessionHandle, uiRegion,
                                                        pucIdentity.encode(), uiIdentityLen,
                                                        pucSignID.encode(), uiSignIDLen,
                                                        pucData, uiDataLen,
                                                        byref(pucSignature))
        if ret == 0:
                print("SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize fail, ret = 0x%08x" % ret)


def SDF_dmsPCI_GetDeviceInfo():
	pstDeviceInfo = DMS_DEVICEINFO()
	ret = gm.SDF_dmsPCI_GetDeviceInfo(hSessionHandle, byref(pstDeviceInfo))
	if ret == 0:
		print('SDF_dmsPCI_GetDeviceInfo success, ret = ' + hex(ret))
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
		print("BufferSize = %d" % pstDeviceInfo.BufferSize)
		print("UserFileMaxNum = %d" % pstDeviceInfo.UserFileMaxNum)
		print("ProcessMaxNum = %d" % pstDeviceInfo.ProcessMaxNum)
		print("SessionMaxNum = %d" % pstDeviceInfo.SessionMaxNum)
		print("SessionTimeout_Sec = %d" % pstDeviceInfo.SessionTimeout_Sec)
		print("SessionKeyMaxNum = 0x%08x" % pstDeviceInfo.SessionKeyMaxNum)
		print("AsymKeyContainerMaxNum = %d" % pstDeviceInfo.AsymKeyContainerMaxNum)
		print("SymKeyMaxNum = %d" % pstDeviceInfo.SymKeyMaxNum)
		print("State = %d" % pstDeviceInfo.State)
		print("Type = %d" % pstDeviceInfo.Type)
	else:
		print('SDF_dmsPCI_GetDeviceInfo fail, ret = ' + hex(ret))


def SDF_dmsPCI_GetPriMatrixAccessRight():
        pucPassword = input('please enter the private key access password: ')
        uiPwdLength = len(pucPassword)
        ret = gm.SDF_dmsPCI_GetPriMatrixAccessRight(hSessionHandle, pucPassword.encode(), uiPwdLength)
        if ret == 0:
                print('SDF_dmsPCI_GetPriMatrixAccessRight success, ret = ' + hex(ret))
        else:
                print('SDF_dmsPCI_GetPriMatrixAccessRight fail, ret =' + hex(ret))


def SDF_dmsPCI_ReleasePriMatrixAccessRight():
        ret = gm.SDF_dmsPCI_ReleasePriMatrixAccessRight(hSessionHandle)
        if ret == 0:
                print('SDF_dmsPCI_ReleasePriMatrixAccessRight success, ret = ' + hex(ret))
        else:
                print('SDF_dmsPCI_ReleasePriMatrixAccessRight fail, ret =' + hex(ret))


def SDF_dmsPCI_ChangePriMatrixPIN():
        pcOldKeyPin = input('please input the old key password: ')
        pcNewKeyPin = input('please input the new key password: ')
        ret = gm.SDF_dmsPCI_ChangePriMatrixPIN(hSessionHandle, pcOldKeyPin.encode(), pcNewKeyPin.encode())
        if ret == 0:
                print("SDF_dmsPCI_ChangePriMatrixPIN success, ret = 0x%x" % ret)
        else:
                print("SDF_dmsPCI_ChangePriMatrixPIN fail, ret = 0x%08x" % ret)

def SDF_dmsPCI_GenPartSignPri_NoCert():
	#生成部分签名公钥和保护公钥
	uiAlgID = SGD_SM2
	pTmpSignPublicKey = ECCrefPublicKey()
	pTmpEncPublicKey = ECCrefPublicKey()
	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, 256, byref(pTmpSignPublicKey), byref(pucPrivateKey))
	if ret != 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))
	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, 256, byref(pTmpEncPublicKey), byref(pucPrivateKey))
	if ret != 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))

	pcIdentity = input('please input the pcIdentity: ')
	pcbEncryptedPriKey = arr1024()
	pcbEncryptedPriKeyLen = c_uint()
	pCipherKey = ECCCipher()
	ret = gm.SDF_dmsPCI_GenPartSignPri_NoCert(hSessionHandle, pcIdentity.encode(), byref(pTmpSignPublicKey), byref(pTmpEncPublicKey), 
						pcbEncryptedPriKey, byref(pcbEncryptedPriKeyLen), byref(pCipherKey), byref(pECCPubkeyPa))
	if ret == 0:
		print("SDF_dmsPCI_GenPartSignPri_NoCert success, ret = 0x%x" % ret)
	else:
		print("SDF_dmsPCI_GenPartSignPri_NoCert fail, ret = 0x%x" % ret)

def SDF_dmsPCI_VerifySignedData_NoCert():
	pcIdentity = "testdmsid"
	pECCPubkeyPa = (c_ubyte * 132)(0x00, 0x01, 0x00, 0x00,
                                       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				       0x1e,0x71,0x2d,0xc9,0x35,0x10,0x46,0x44,0x3f,0xb9,0xa9,0xf1,0x0f,0xa5,0x0b,0x87,0xa7,0xf2,0x34,0x76,0x45,0xcf,0xd9,0xeb,0xc3,0x32,0x87,0xaf,0xcb,0xdd,0xea,0x53,
				       0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				       0xa0,0x87,0x49,0xa9,0xd9,0x2e,0x88,0xf7,0xf5,0x6e,0x11,0x9a,0x89,0x1c,0x94,0xe3,0x48,0xe2,0x5f,0x32,0x5c,0xc6,0xb6,0x00,0x31,0x22,0x37,0x25,0xf1,0x8b,0xf8,0x36)
	signature = (c_ubyte * 128)(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				    0xfa,0xba,0xb7,0xee,0xa0,0x60,0x09,0x84,0x3f,0xab,0x04,0x6d,0x82,0x9d,0x5b,0x9a,0x68,0xc4,0x32,0x3c,0x4b,0x56,0x9b,0x4d,0x17,0x72,0x22,0x5e,0x08,0x7f,0x6f,0x04,
				    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				    0xe4,0xfa,0xc5,0x0f,0xc4,0xe5,0x47,0xb0,0xd5,0x0f,0xac,0x33,0x11,0x87,0x51,0xd8,0x5c,0x26,0x82,0xa5,0xa9,0xc1,0xe4,0x8d,0x09,0xf2,0x9a,0x81,0xb4,0xd9,0x98,0xd1)
	pucIndata = (c_ubyte * 32)(0x58,0xf0,0x3b,0x12,0x46,0xb6,0x9f,0xd6,0x29,0xd4,0x18,0x6a,0xd9,0xb6,0x89,0xd2,0x5d,0xb9,0x18,0xbc,0xac,0x3b,0x2b,0xe6,0x8d,0xe4,0x38,0xa2,0xbd,0xe7,0xda,0xb9)
	uiInDataLen = 32
	ret =  gm.SDF_dmsPCI_VerifySignedData_NoCert(hSessionHandle, pcIdentity.encode(), pucIndata, uiInDataLen, pECCPubkeyPa, signature)
	if ret == 0:
		print("SDF_dmsPCI_VerifySignedData_NoCert success, ret = 0x%x" % ret) 
	else:
		print("SDF_dmsPCI_VerifySignedData_NoCert fail, ret = 0x%x" % ret) 


#**************************************MK平台相关接口***********************************
pkx = ECCrefPublicKey()
pEncY_By_Pks = EnvelopedKeyBlob()
pkxy = ECCrefPublicKey()

def SDF_dmsPCI_Generate_pky():
	pks = ECCrefPublicKey()
	uiAlgID = SGD_SM2
	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, 256, byref(pks), byref(pucPrivateKey))
	if ret != 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))
	ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, 256, byref(pkx), byref(pucPrivateKey))
	if ret != 0:
		print('SDF_GenerateKeyPair_ECC success, ret = ' + hex(ret))
	ret = gm.SDF_dmsPCI_Generate_pky(hSessionHandle, byref(pks), byref(pkx), byref(pEncY_By_Pks), byref(pkxy))
	if ret == 0:
		print("SDF_dmsPCI_Generate_pky success, ret = 0x%x" % ret)
		PrintData("pkxy.x", pkxy.x, 64, 32)
		PrintData("pkxy.y", pkxy.x, 64, 32)
	else:
		print("SDF_dmsPCI_Generate_pky fail, ret = 0x%x" % ret)


def SDF_dmsPCI_CalculateCooperateKey():
	region = 1
	pcIdentity = input('please input the pcIdentity: ')
	pcLicenceIssuingAuthority = input('please input the pcLicenceIssuingAuthority: ')
	pcTakeEffectDate = input('please input the pcTakeEffectDate: ')
	pcLoseEffectDate = input('please input the pcLoseEffectDate: ')
	#pky = pEncY_By_Pks.PubKey
	pEnv = CkiEnvelope()
	pOutEncD1ByPkx = EnvelopedKeyBlob()
	pOutEncD2ByPky = EnvelopedKeyBlob()
	pOutd3G = ECCrefPublicKey()
	PrintData("pky.x", pkxy.x, 64, 32)
	PrintData("pky.y", pkxy.x, 64, 32)
	ret = gm.SDF_dmsPCI_CalculateCooperateKey(hSessionHandle, region, pcIdentity, pcLicenceIssuingAuthority,
						pcTakeEffectDate, pcLoseEffectDate,
						byref(pkx), byref(pkxy), byref(pEncY_By_Pks.PubKey), byref(pEnv),
						byref(pOutEncD1ByPkx), byref(pOutEncD2ByPky), byref(pOutd3G))
	if ret == 0:
		print("SDF_dmsPCI_CalculateCooperateKey success, ret = 0x%x"%ret)
	else:
		print("SDF_dmsPCI_CalculateCooperateKey fail, ret = 0x%x"%ret)

 
def SDF_ExportSignPublicKey_RSA():
	uiKeyIndex = input('please enter the index(0~49999): ')
	ret = gm.SDF_ExportSignPublicKey_RSA(hSessionHandle, int(uiKeyIndex), byref(pucPublicKeyRSA))
	if ret == 0:
		print('SDF_ExportSignPublicKey_RSA success, ret = ' + hex(ret))
		PrintData("publicKeyRSA.m", pucPublicKeyRSA.m, 256, 32)
		PrintData("publicKeyRSA.e", pucPublicKeyRSA.e, 256, 32)
	else:
		print('SDF_ExportSignPublicKey_RSA fail, ret = ' + hex(ret))


def SDF_ExportEncPublicKey_RSA():
	uiKeyIndex = input('please enter the index(0~49999): ')
	ret = gm.SDF_ExportEncPublicKey_RSA(hSessionHandle, int(uiKeyIndex), byref(pucPublicKeyRSA))
	if ret == 0:
		print('SDF_ExportEncPublicKey_RSA success, ret = ' + hex(ret))
		PrintData("publicKeyRSA.m", pucPublicKeyRSA.m, 256, 32)
		PrintData("publicKeyRSA.e", pucPublicKeyRSA.e, 256, 32)
	else:
		print('SDF_ExportEncPublicKey_RSA fail, ret = ' + hex(ret))

def SDF_GenerateKeyPair_RSA():
	uiKeyBits = input('please input the KeyBits: ')
	ret = gm.SDF_GenerateKeyPair_RSA(hSessionHandle, int(uiKeyBits), byref(pucPublicKeyRSA), byref(pucPrivateKeyRSA))
	if ret == 0:
		print('SDF_GenerateKeyPair_RSA success, ret = ' + hex(ret))
		PrintData("publicKeyRSA.m", pucPublicKeyRSA.m, 256, 32)
		PrintData("publicKeyRSA.e", pucPublicKeyRSA.e, 256, 32)
		PrintData("privateKeyRSA.d", pucPrivateKeyRSA.d, 256, 32)
	else:
		print('SDF_GenerateKeyPair_RSA fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithIPK_RSA():
	uiIPKIndex = input('please input the index：')
	uiKeyBits = input('please input the keybits：')
	ret = gm.SDF_GenerateKeyWithIPK_RSA(hSessionHandle, int(uiIPKIndex), int(uiKeyBits), pucKeyRSA, byref(puiKeyRSALength), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithIPK_RSA success, ret = ' + hex(ret))
		print('sessionKey ID: '+hex(phKeyHandle.value))
	else:
		print('SDF_GenerateKeyWithIPK_RSA fail, ret = ' + hex(ret))

def SDF_GenerateKeyWithEPK_RSA():
	uiKeyBits = input('please input the keybits：')
	ret  = gm.SDF_GenerateKeyWithEPK_RSA(hSessionHandle, int(uiKeyBits), byref(pucPublicKeyRSA), pucKeyRSA, byref(puiKeyRSALength), byref(phKeyHandle))
	if ret == 0:
		print('SDF_GenerateKeyWithEPK_RSA success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
	else:
		print('SDF_GenerateKeyWithEPK_RSA fail ret = ' + hex(ret))

def SDF_ImportKeyWithISK_RSA():
	uiISKIndex = input('please input the index:')
	ret = gm.SDF_ImportKeyWithISK_RSA(hSessionHandle, int(uiISKIndex), pucKeyRSA, puiKeyRSALength.value, byref(phKeyHandle))
	if ret == 0:
		print('SDF_ImportKeyWithISK_RSA success, ret = ' + hex(ret))
		print('sessionKey ID: %x'%phKeyHandle.value)
	else:
		print('SDF_ImportKeyWithISK_RSA fail, ret = ' + hex(ret))


def SDF_ExchangeDigitEnvelopeBaseOnRSA():
	uiIPKIndex = input('please input the index：')
	pucDEOutput = (c_ubyte * 1024)()
	puiDELength = c_uint()
	ret = gm.SDF_ExchangeDigitEnvelopeBaseOnRSA(hSessionHandle, int(uiIPKIndex), byref(pucPublicKeyRSA), pucKeyRSA, puiKeyRSALength.value, pucDEOutput, byref(puiDELength))
	if ret ==  0:
		print('SDF_ExchangeDigitEnvelopeBaseOnRSA sucess,  ret = ' + hex(ret))
	else:
		print('SDF_ExchangeDigitEnvelopeBaseOnRSA fail, ret = ' + hex(ret))


def SDF_ExternalPublicKeyOperation_RSA():
	global pucDataInput, puiInputLength, pucDataOutput, puiOutputLength
	pucDataInput = (c_ubyte * 2048)()
	puiInputLength = c_uint()
	pucDataOutput = (c_ubyte * 2048)()
	puiOutputLength = c_uint()
	ret = gm.SDF_ExternalPublicKeyOperation_RSA(hSessionHandle,  byref(pucPublicKeyRSA), pucDataInput, puiInputLength, pucDataOutput, byref(puiOutputLength))
	if ret ==  0:
		print('SDF_ExternalPublicKeyOperation_RSA sucess,  ret = ' + hex(ret))
	else:
		print('SDF_ExternalPublicKeyOperation_RSA fail, ret = ' + hex(ret))


def SDF_InternalPublicKeyOperation_RSA():
	uiIPKIndex = input('please input the index：')
	ret = gm.SDF_InternalPublicKeyOperation_RSA(hSessionHandle, int(uiIPKIndex), pucDataInput, puiInputLength, pucDataOutput, byref(puiOutputLength))
	if ret ==  0:
		print('SDF_InternalPublicKeyOperation_RSA sucess,  ret = ' + hex(ret))
	else:
		print('SDF_InternalPublicKeyOperation_RSA fail, ret = ' + hex(ret))
	

def SDF_InternalPrivateKeyOperation_RSA():
	uiIPKIndex = input('please input the index：')
	ret = gm.SDF_InternalPrivateKeyOperation_RSA(hSessionHandle, int(uiIPKIndex), pucDataInput, puiInputLength, pucDataOutput, byref(puiOutputLength))
	if ret ==  0:
		print('SDF_InternalPrivateKeyOperation_RSA sucess,  ret = ' + hex(ret))
	else:
		print('SDF_InternalPrivateKeyOperation_RSA fail, ret = ' + hex(ret))

 
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
	"21" : SDF_ImportKey,
	"22" : SDF_DestroyKey,
	"23" : SDF_InternalSign_ECC,
	"24" : SDF_InternalVerify_ECC,
	"25" : SDF_ExternalSign_ECC,
	"26" : SDF_ExternalVerify_ECC,
	"27" : SDF_ExternalEncrypt_ECC,
	"28" : SDF_ExternalDecrypt_ECC,
	"29" : SDF_HashInit,
	"30" : SDF_HashUpdate,
	"31" : SDF_HashFinal,
	"32" : SDF_Encrypt,
	"33" : SDF_Decrypt,
	"34" : SDF_CalculateMAC,
	"35" : SDF_CreateFile,
	"36" : SDF_ReadFile,
	"37" : SDF_WriteFile,
        "38" : SDF_DeleteFile,
        "39" : SDF_EnumFiles,
        "40" : SDF_dmsPCI_SegMentKeyInit,
        "41" : SDF_dmsPCI_GetSegMentKey,
        "42" : SDF_dmsPCI_SegMentKeyFinal,
        "43" : SDF_dmsPCI_KeyRecoveryInit,
        "44" : SDF_dmsPCI_ImportSegmentKey,
        "45" : SDF_dmsPCI_KeyRecovery,
        "46" : SDF_dmsPCI_Backup_Threshold,
        "47" : SDF_dmsPCI_ExportSegmentKey_Threshold,
	"48" : SDF_dmsPCI_GetEncPubKey_Threshold,
    	"49" : SDF_dmsPCI_ImportSegmentKey_Threshold,
	"50" : SDF_dmsPCI_Restore_Threshold,
    	"51" : SDF_dmsPCI_TestSelf,
    	"52" : SDF_dmsPCI_PCICardInit,
    	"53" : SDF_dmsPCI_GetKeyPoolState,
    	"54" : SDF_dmsPCI_PCICardGenerateMatrix,
    	"55" : SDF_dmsPCI_ImportPubMatrix,
    	"56" : SDF_dmsPCI_ExportPubMatrix,
    	"57" : SDF_dmsPCI_GenECCKeyPair,
   	"58" : SDF_dmsPCI_CalculatePersonKey,
   	"59" : SDF_dmsPCI_ImportKeyWithECCKeyPair,
    	"60" : SDF_dmsPCI_SVSClearContainer,
    	"61" : SDF_dmsPCI_ChangeCardPIN,
    	"62" : SDF_dmsPCI_ChangeKeyPIN,
    	"63" : SDF_dmsPCI_GenerateKEK,
    	"64" : SDF_dmsPCI_DeleteKEK,
    	"65" : SDF_dmsPCI_GetKEKPoolState,
    	"66" : SDF_dmsGenerate_PKIKeyPair,
	"67" : SDF_dmsPCI_GenerateKEKByIndex,
	"68" : SDF_dmsPCI_CalculatePubKey,
	"69" : SDF_dmsPCI_CalculatePubKey_Optimize,
	"70" : SDF_dmsPCI_IdentifyECCSignForEnvelope,
	"71" : SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize,
    	"72" : SDF_dmsPCI_GetDeviceInfo,
    	"73" : SDF_dmsPCI_GetPriMatrixAccessRight,
    	"74" : SDF_dmsPCI_ReleasePriMatrixAccessRight,
    	"75" : SDF_dmsPCI_ChangePriMatrixPIN,
	"76" : SDF_dmsPCI_GenPartSignPri_NoCert,
	"77" : SDF_dmsPCI_VerifySignedData_NoCert,
	"78" : SDF_dmsPCI_Generate_pky,
	"79" : SDF_dmsPCI_CalculateCooperateKey,
	"84" : SDF_ExportSignPublicKey_RSA,
        "85" : SDF_ExportEncPublicKey_RSA,
        "86" : SDF_GenerateKeyPair_RSA,
	"87" : SDF_GenerateKeyWithIPK_RSA,
        "88" : SDF_GenerateKeyWithEPK_RSA,
        "89" : SDF_ImportKeyWithISK_RSA,
	"90" : SDF_ExchangeDigitEnvelopeBaseOnRSA,
	"91" : SDF_ExternalPublicKeyOperation_RSA,      
	"92" : SDF_InternalPublicKeyOperation_RSA,
	"93" : SDF_InternalPrivateKeyOperation_RSA,
    "0"  : exit,
	}


while True:
	print('\n\033[1;35m ********************************************设备管理类函数***************************************************************************** \033[0m')
	print('\033[1;33m 1.SDF_OpenDevice                            2.SDF_CloseDevice                          3.SDF_OpenSession \033[0m')
	print('\033[1;33m 4.SDF_CloseSession                          5.SDF_GetDeviceInfo                        6.SDF_GenerateRandom \033[0m')
	print('\033[1;33m 7.SDF_GetPrivateKeyAccessRight              8.SDF_ReleasePrivateKeyAccessRight \033[0m')
	print('\033[1;35m ********************************************密钥管理类函数(ECC)************************************************************************* \033[0m')
	print('\033[1;33m 9.SDF_ExportSignPublicKey_ECC               10.SDF_ExportEncPublicKey_ECC              11.SDF_GenerateKeyPair_ECC \033[0m')
	print('\033[1;33m 12.SDF_GenerateKeyWithIPK_ECC               13.SDF_GenerateKeyWithEPK_ECC              14.SDF_ImportKeyWithISK_ECC \033[0m')
	print('\033[1;33m 15.SDF_GenerateAgreementDataWithECC         16.SDF_GenerateKeyWithECC                  17.SDF_GenerateAgreementDataAndKeyWithECC \033[0m')
	print('\033[1;33m 18.SDF_ExchangeDigitEnvelopeBaseOnECC       19.SDF_GenerateKeyWithKEK                  20.SDF_ImportKeyWithKEK \033[0m')
	print('\033[1;33m 21.SDF_ImportKey                            22.SDF_DestroyKey \033[0m')
	print('\033[1;35m ********************************************SM2/SM3/SM4算法类函数*********************************************************************** \033[0m')
	print('\033[1;33m 23.SDF_InternalSign_ECC                     24.SDF_InternalVerify_ECC                  25.SDF_ExternalSign_ECC \033[0m')
	print('\033[1;33m 26.SDF_ExternalVerify_ECC                   27.SDF_ExternalEncrypt_ECC                 28.SDF_ExternalDecrypt_ECC \033[0m')
	print('\033[1;33m 29.SDF_HashInit                             30.SDF_HashUpdate                          31.SDF_HashFinal \033[0m')
	print('\033[1;33m 32.SDF_Encrypt                              33.SDF_Decrypt                             34.SDF_CalculateMAC \033[0m')
	print('\033[1;35m ********************************************文件操作类函数****************************************************************************** \033[0m')
	print('\033[1;33m 35.SDF_CreateFile                           36.SDF_ReadFile                            37.SDF_WriteFile  \033[0m')
	print('\033[1;33m 38.SDF_DeleteFile                           39.SDF_EnumFiles\033[0m')
	print('\033[1;35m ********************************************密钥备份/恢复类函数(DMS-Define)************************************************************* \033[0m')
	print('\033[1;33m 40.SDF_dmsPCI_SegMentKeyInit                41.SDF_dmsPCI_GetSegMentKey                42.SDF_dmsPCI_SegMentKeyFinal\033[0m')
	print('\033[1;33m 43.SDF_dmsPCI_KeyRecoveryInit               44.SDF_dmsPCI_ImportSegmentKey             45.SDF_dmsPCI_KeyRecovery\033[0m')        
	print('\033[1;33m 46.SDF_dmsPCI_SegMentKeyThreshold           47.SDF_dmsPCI_GetSegMentKeyThreshold       48.SDF_dmsPCI_GetEncPubKey_Threshold\033[0m')
	print('\033[1;33m 49.SDF_dmsPCI_ImportSegmentKey_Threshold    50.SDF_dmsPCI_Restore_Threshold\033[0m')
	print('\033[1;35m ********************************************密钥生产操作类函数(DMS-Define)************************************************************** \033[0m')
	print('\033[1;33m 51.SDF_dmsPCI_TestSelf                      52.SDF_dmsPCI_PCICardInit                  53.SDF_dmsPCI_GetKeyPoolState \033[0m')
	print('\033[1;33m 54.SDF_dmsPCI_PCICardGenerateMatrix         55.SDF_dmsPCI_ImportPubMatrix              56.SDF_dmsPCI_ExportPubMatrix \033[0m')
	print('\033[1;33m 57.SDF_dmsPCI_GenECCKeyPair                 58.SDF_dmsPCI_CalculatePersonKey           59.SDF_dmsPCI_ImportKeyWithECCKeyPair\033[0m')
	print('\033[1;33m 60.SDF_dmsPCI_SVSClearContainer             61.SDF_dmsPCI_ChangeCardPIN                62.SDF_dmsPCI_ChangeKeyPIN \033[0m')
	print('\033[1;33m 63.SDF_dmsPCI_GenerateKEK                   64.SDF_dmsPCI_DeleteKEK                    65.SDF_dmsPCI_GetKEKPoolState \033[0m')  
	print('\033[1;33m 66.SDF_dmsGenerate_PKIKeyPair               67.SDF_dmsPCI_GenerateKEKByIndex           68.SDF_dmsPCI_CalculatePubKey \033[0m')   
	print('\033[1;33m 69.SDF_dmsPCI_CalculatePubKey_Optimize      70.SDF_dmsPCI_IdentifyECCSignForEnvelope   71.SDF_dmsPCI_IdentifyECCSignForEnvelope_Optimize \033[0m')
	print('\033[1;33m 72.SDF_dmsPCI_GetDeviceInfo                 73.SDF_dmsPCI_GetPriMatrixAccessRight      74.SDF_dmsPCI_ReleasePriMatrixAccessRight \033[0m')      
	print('\033[1;33m 75.SDF_dmsPCI_ChangePriMatrixPIN            76.SDF_dmsPCI_GenPartSignPri_NoCert        77.SDF_dmsPCI_VerifySignedData_NoCert \033[0m')      
	print('\033[1;33m 78.SDF_dmsPCI_Generate_pky                  79.SDF_dmsPCI_CalculateCooperateKey        80.SDF_dmsPCI_CalculateD4 \033[0m')      
	print('\033[1;33m 81.SDF_dmsPCI_CopDecrypt                    82.SDF_dmsPCI_CopSign                      83.SDF_dmsPCI_ExchangeDigitEnvelopeKeyBlob \033[0m')      
	print('\033[1;35m ********************************************密钥生产操作类函数(RSA)********************************************************************* \033[0m')
	print('\033[1;33m 84.SDF_ExportSignPublicKey_RSA              85.SDF_ExportEncPublicKey_RSA              86.SDF_GenerateKeyPair_RSA \033[0m')
	print('\033[1;33m 87.SDF_GenerateKeyWithIPK_RSA               88.SDF_GenerateKeyWithEPK_RSA              89.SDF_ImportKeyWithISK_RSA \033[0m')
	print('\033[1;33m 90.SDF_ExchangeDigitEnvelopeBaseOnRSA       91.SDF_ExternalPublicKeyOperation_RSA      92.SDF_InternalPublicKeyOperation_RSA\033[0m')
	print('\033[1;33m 92.SDF_InternalPrivateKeyOperation_RSA       0.exit \033[0m')
	print('\033[1;35m ********************************************END***************************************************************************************** \033[0m')

	value = input("\033[1;31m请输入接口对应数字进行测试:\033[0m")
	try:
		switch[value]()
	except KeyError as e:
		print('命令输入错误，请重新输入!')
