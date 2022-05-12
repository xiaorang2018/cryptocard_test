#!/usr/bin/python3
import os
import configparser
import sys
import time
from ctypes import *
from PyQt5.QtWidgets import QWidget, QPushButton, QApplication, QMainWindow, QLabel, QLineEdit, QTextBrowser

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

arr1 = c_ubyte * 1
arr2 = c_ubyte * 2
arr4 = c_ubyte * 4
arr16 = c_ubyte * 16
arr32 = c_ubyte * 32
arr40 = c_ubyte * 40
arr50 = c_ubyte * 50
arr64 = c_ubyte * 64
arr1024 = c_ubyte * 1024

uiKeyBits = 256


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

KEY_POOL_SIZE_MAX = 50
class KeyPoolStateInfo(Structure):
    _fields_ = [
        ('uiKeyPoolSize', c_uint),
        ('ucKeyPoolStates', c_ubyte * KEY_POOL_SIZE_MAX)]


hDeviceHandle = c_void_p()
hSessionHandle = c_void_p()

pucKey1 = ECCCipher()
phKeyHandle = c_void_p()
phAgreementHandle = c_void_p()

pucSponsorID = '12345678'
uiSponsorIDLength = 8
pucResponseID = '12345678'
uiResponseIDLength = 8

pucSponsorPublicKey = ECCrefPublicKey()
pucSponsorTmpPublicKey = ECCrefPublicKey()

pucResponsePublicKey = ECCrefPublicKey()
pucResponseTmpPublicKey = ECCrefPublicKey()

sign = ECCSignature()
Hash = arr32()
HashLength = 32
pucData = (c_ubyte * 65536)()
uiDataLength = c_uint()
pucIV = arr16()
pucEncData = arr1024()
uiEncDataLength = c_uint()


class UiUkey(QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # 设备管理
        btn1 = QPushButton("打开设备", self)
        btn1.setGeometry(30, 110, 130, 30)
        btn2 = QPushButton("打开指定设备", self)
        btn2.setGeometry(30, 150, 130, 30)
        btn3 = QPushButton("关闭设备", self)
        btn3.setGeometry(30, 190, 130, 30)
        btn4 = QPushButton("创建会话", self)
        btn4.setGeometry(30, 230, 130, 30)
        btn5 = QPushButton("关闭会话", self)
        btn5.setGeometry(30, 270, 130, 30)
        btn6 = QPushButton("获取设备信息", self)
        btn6.setGeometry(30, 310, 130, 30)
        btn7 = QPushButton("产生随机数", self)
        btn7.setGeometry(30, 350, 130, 30)
        btn8 = QPushButton("获取私钥使用权限", self)
        btn8.setGeometry(30, 390, 130, 30)
        btn9 = QPushButton("释放私钥使用权限", self)
        btn9.setGeometry(30, 430, 130, 30)

        # 密钥管理类管理
        btn10 = QPushButton("导出ECC签名公钥", self)
        btn10.setGeometry(170, 110, 230, 30)
        btn11 = QPushButton("导出ECC加密公钥", self)
        btn11.setGeometry(170, 150, 230, 30)
        btn12 = QPushButton("产生ECC密钥对并输出", self)
        btn12.setGeometry(170, 190, 230, 30)
        btn13 = QPushButton("生成会话密钥并用内部ECC公钥加密输出", self)
        btn13.setGeometry(170, 230, 230, 30)
        btn14 = QPushButton("生成会话密钥并用外部ECC公钥加密输出", self)
        btn14.setGeometry(170, 270, 230, 30)
        btn15 = QPushButton("导入会话密钥并用内部ECC私钥解密", self)
        btn15.setGeometry(170, 310, 230, 30)
        btn16 = QPushButton("生成密钥协商参数并输出", self)
        btn16.setGeometry(170, 350, 230, 30)
        btn17 = QPushButton("计算会话密钥", self)
        btn17.setGeometry(170, 390, 230, 30)
        btn18 = QPushButton("产生协商数据并计算会话密钥", self)
        btn18.setGeometry(170, 430, 230, 30)
        btn19 = QPushButton("基于ECC算法的数字信封转换", self)
        btn19.setGeometry(410, 110, 230, 30)
        btn20 = QPushButton("生成会话密钥并密钥加密密钥加密输出", self)
        btn20.setGeometry(410, 150, 230, 30)
        btn21 = QPushButton("导入会话密钥并密钥加密密钥解密", self)
        btn21.setGeometry(410, 190, 230, 30)
        btn22 = QPushButton("销毁会话密钥", self)
        btn22.setGeometry(410, 230, 230, 30)

        # 非对称算法类函数
        btn23 = QPushButton("外部密钥ECC验证", self)
        btn23.setGeometry(650, 110, 150, 30)
        btn24 = QPushButton("内部密钥ECC签名", self)
        btn24.setGeometry(650, 150, 150, 30)
        btn25 = QPushButton("内部密钥ECC验证", self)
        btn25.setGeometry(650, 190, 150, 30)
        btn26 = QPushButton("外部密钥ECC公钥加密", self)
        btn26.setGeometry(650, 230, 150, 30)

        # 对称算法类函数
        btn27 = QPushButton("对称加密", self)
        btn27.move(810, 30)
        btn28 = QPushButton("对称解密", self)
        btn28.move(810, 70)
        btn29 = QPushButton("计算MAC", self)
        btn29.move(810, 110)

        # 杂凑运算类函数
        btn30 = QPushButton("杂凑运算初始化", self)
        btn30.move(920, 30)
        btn31 = QPushButton("多包杂凑运算", self)
        btn31.move(920, 70)
        btn32 = QPushButton("杂凑运算结束", self)
        btn32.move(920, 110)

        # 用户文件类操作函数
        btn33 = QPushButton("创建文件", self)
        btn33.move(1030, 30)
        btn34 = QPushButton("读取文件", self)
        btn34.move(1030, 70)
        btn35 = QPushButton("写文件", self)
        btn35.move(1030, 110)
        btn36 = QPushButton("删除文件", self)
        btn36.move(1030, 150)
        btn37 = QPushButton("枚举文件", self)
        btn37.move(1030, 190)

        # 清空输出日志
        btn38 = QPushButton("清空输出日志", self)
        btn38.move(780, 620)
        btn39 = QPushButton("全功能测试", self)
        btn39.move(780, 580)

        #密钥生产操作类函数
        btn40 = QPushButton("PCI初始化", self)
        btn40.setGeometry(410, 270, 230, 30)
        btn41 = QPushButton("生成公私钥矩阵", self)
        btn41.setGeometry(410, 310, 230, 30)
        btn42 = QPushButton("算法自检", self)
        btn42.setGeometry(410, 350, 230, 30)
        btn43 = QPushButton("导入公钥矩阵", self)
        btn43.setGeometry(410, 390, 230, 30)
        btn44 = QPushButton("导出公钥矩阵", self)
        btn44.setGeometry(410, 430, 230, 30)
        btn45 = QPushButton("获取密钥池状态", self)
        btn45.setGeometry(650, 270, 150, 30)
        btn46 = QPushButton("产生部分签名和保护公钥", self)
        btn46.setGeometry(650, 310, 150, 30)
        btn47 = QPushButton("导入密钥对", self)
        btn47.setGeometry(650, 350, 150, 30)
        btn48 = QPushButton("产生用户密钥", self)
        btn48.setGeometry(650, 390, 150, 30)
        btn49 = QPushButton("删除密钥对", self)
        btn49.setGeometry(650, 430, 150, 30)
        btn50 = QPushButton("修改设备管理PIN码", self)
        btn50.setGeometry(810, 270, 150, 30)
        btn51 = QPushButton("修改私钥权限标识码", self)
        btn51.setGeometry(810, 310, 150, 30)
        btn52 = QPushButton("生成密钥加密密钥", self)
        btn52.setGeometry(810, 350, 150, 30)
        btn53 = QPushButton("删除密钥加密密钥", self)
        btn53.setGeometry(810, 390, 150, 30)
        btn54 = QPushButton("通过矩阵计算标识公钥", self)
        btn54.setGeometry(810, 430, 150, 30)
        btn55 = QPushButton("标识签名", self)
        btn55.setGeometry(810, 470, 150, 30)


        #密钥备份和恢复类操作函数
        btn56 = QPushButton("密钥分割", self)
        btn56.setGeometry(970, 270, 200, 30)
        btn57 = QPushButton("导出密钥分割数据", self)
        btn57.setGeometry(970, 310, 200, 30)
        btn58 = QPushButton("密钥恢复初始化", self)
        btn58.setGeometry(970, 350, 200, 30)
        btn59 = QPushButton("导入密钥分割数据", self)
        btn59.setGeometry(970, 390, 200, 30)
        btn60 = QPushButton("密钥恢复", self)
        btn60.setGeometry(970, 430, 200, 30)
        btn61 = QPushButton("三五门限：密钥分割", self)
        btn61.setGeometry(970, 470, 200, 30)
        btn62 = QPushButton("三五门限：导出密钥分割数据", self)
        btn62.setGeometry(970, 510, 200, 30)
        btn63 = QPushButton("三五门限：密钥恢复初始化", self)
        btn63.setGeometry(970, 550, 200, 30)
        btn64 = QPushButton("三五门限：导入密钥分割数据", self)
        btn64.setGeometry(970, 590, 200, 30)
        btn65 = QPushButton("三五门限：密钥恢复", self)
        btn65.setGeometry(970, 630, 200, 30)
        #随机数检测
        btn66 = QPushButton("随机数单次检测", self)
        btn66.setGeometry(810, 150, 150, 30)
        btn67 = QPushButton("随机数上电检测", self)
        btn67.setGeometry(810, 190, 150, 30)
        btn68 = QPushButton("随机数循环检测", self)
        btn68.setGeometry(810, 230, 150, 30)
        btn69 = QPushButton("获取对称密钥池状态", self)
        btn69.setGeometry(810, 510, 150, 30)

        inLabe1 = QLabel(self)
        inLabe1.setText("KeyIndex:")
        inLabe1.move(30, 30)
        self.input1 = QLineEdit(self)
        self.input1.setGeometry(110, 30, 90, 30)

        inLabe2 = QLabel(self)
        inLabe2.setText("Password:")
        inLabe2.move(30, 70)
        self.input2 = QLineEdit(self)
        self.input2.setGeometry(110, 70, 90, 30)

        inLabe3 = QLabel(self)
        inLabe3.setText("FileName:")
        inLabe3.move(220, 30)
        self.input3 = QLineEdit(self)
        self.input3.setGeometry(280, 30, 110, 30)

        inLabe4 = QLabel(self)
        inLabe4.setText("FileSize:")
        inLabe4.move(220, 70)
        self.input4 = QLineEdit(self)
        self.input4.setGeometry(280, 70, 110, 30)

        inLabe5 = QLabel(self)
        inLabe5.setText("FileOffSet:")
        inLabe5.move(410, 30)
        self.input5 = QLineEdit(self)
        self.input5.setGeometry(480, 30, 110, 30)

        inLabe6 = QLabel(self)
        inLabe6.setText("RandomLeng:")
        inLabe6.move(410, 70)
        self.input6 = QLineEdit(self)
        self.input6.setGeometry(480, 70, 110, 30)

        inLabe7 = QLabel(self)
        inLabe7.setText("KeyBits:")
        inLabe7.move(610, 30)
        self.input7 = QLineEdit(self)
        self.input7.setGeometry(710, 30, 90, 30)

        inLabe8 = QLabel(self)
        inLabe8.setText("DLeng/NewPasswd:")
        inLabe8.move(610, 70)
        self.input8 = QLineEdit(self)
        self.input8.setGeometry(710, 70, 90, 30)

        outLabel = QLabel(self)
        outLabel.setText("输出:")
        outLabel.move(30, 460)
        self.output = QTextBrowser(self)
        self.output.setGeometry(30, 490, 740, 160)

        # 设备管理类函数
        btn1.clicked.connect(self.SDF_OpenDevice)
        btn2.clicked.connect(self.SDF_OpenDeviceWithCfg)
        btn3.clicked.connect(self.SDF_CloseDevice)
        btn4.clicked.connect(self.SDF_OpenSession)
        btn5.clicked.connect(self.SDF_CloseSession)
        btn6.clicked.connect(self.SDF_GetDeviceInfo)
        btn7.clicked.connect(self.SDF_GenerateRandom)
        btn8.clicked.connect(self.SDF_GetPrivateKeyAccessRight)
        btn9.clicked.connect(self.SDF_ReleasePrivateKeyAccessRight)
        # 密钥管理类函数
        btn10.clicked.connect(self.SDF_ExportSignPublicKey_ECC)
        btn11.clicked.connect(self.SDF_ExportEncPublicKey_ECC)
        btn12.clicked.connect(self.SDF_GenerateKeyPair_ECC)
        btn13.clicked.connect(self.SDF_GenerateKeyWithIPK_ECC)
        btn14.clicked.connect(self.SDF_GenerateKeyWithEPK_ECC)
        btn15.clicked.connect(self.SDF_ImportKeyWithISK_ECC)
        btn16.clicked.connect(self.SDF_GenerateAgreementDataWithECC)
        btn17.clicked.connect(self.SDF_GenerateKeyWithECC)
        btn18.clicked.connect(self.SDF_GenerateAgreementDataAndKeyWithECC)
        btn19.clicked.connect(self.SDF_ExchangeDigitEnvelopeBaseOnECC)
        btn20.clicked.connect(self.SDF_GenerateKeyWithKEK)
        btn21.clicked.connect(self.SDF_ImportKeyWithKEK)
        btn22.clicked.connect(self.SDF_DestroyKey)
        # 非对称算法类函数
        btn23.clicked.connect(self.SDF_ExternalVerify_ECC)
        btn24.clicked.connect(self.SDF_InternalSign_ECC)
        btn25.clicked.connect(self.SDF_InternalVerify_ECC)
        btn26.clicked.connect(self.SDF_ExternalEncrypt_ECC)
        # 对称算法类函数
        btn27.clicked.connect(self.SDF_Encrypt)
        btn28.clicked.connect(self.SDF_Decrypt)
        btn29.clicked.connect(self.SDF_CalculateMAC)
        # 杂凑运算类函数
        btn30.clicked.connect(self.SDF_HashInit)
        btn31.clicked.connect(self.SDF_HashUpdate)
        btn32.clicked.connect(self.SDF_HashFinal)
        # 用户文件操作类函数
        btn33.clicked.connect(self.SDF_CreateFile)
        btn34.clicked.connect(self.SDF_ReadFile)
        btn35.clicked.connect(self.SDF_WriteFile)
        btn36.clicked.connect(self.SDF_DeleteFile)
        btn37.clicked.connect(self.SDF_EnumFiles)
        btn38.clicked.connect(self.clearLog)
        btn39.clicked.connect(self.SDF_FullFunction)

        #密钥生产管理类函数
        btn40.clicked.connect(self.SDF_dmsPCI_PCICardInit)
        btn41.clicked.connect(self.SDF_dmsPCI_PCICardGenerateMatrix)
        btn42.clicked.connect(self.SDF_dmsPCI_AlgSelfInspection)
        btn43.clicked.connect(self.SDF_dmsPCI_ImportPubMatrix)
        btn44.clicked.connect(self.SDF_dmsPCI_ExportPubMatrix)
        btn45.clicked.connect(self.SDF_dmsPCI_GetKeyPoolState)
        btn46.clicked.connect(self.SDF_dmsPCI_GenECCKeyPair)
        btn47.clicked.connect(self.SDF_dmsPCI_ImportKeyWithECCKeyPair)
        btn48.clicked.connect(self.SDF_dmsPCI_CalculatePersonKey)
        btn49.clicked.connect(self.SDF_dmsPCI_ClearECCKeyPair)
        btn50.clicked.connect(self.SDF_dmsPCI_ChangeCardPIN)
        btn51.clicked.connect(self.SDF_dmsPCI_ChangeKeyPIN)
        btn52.clicked.connect(self.SDF_dmsPCI_GenerateKEK)
        btn53.clicked.connect(self.SDF_dmsPCI_DeleteKEK)
        btn69.clicked.connect(self.SDF_dmsPCI_GetKEKPoolState)
        btn54.clicked.connect(self.SDF_dmsPCI_CalculatePKid_ExtPKM)
        btn55.clicked.connect(self.SDF_dmsPCI_IdentifyECCSignForEnvelope)
        #密钥备份恢复类操作函数
        btn56.clicked.connect(self.SDF_dmsPCI_SegMentKey)
        btn57.clicked.connect(self.SDF_dmsPCI_GetSegMentKey)
        btn58.clicked.connect(self.SDF_dmsPCI_KeyRecoveryInit)
        btn59.clicked.connect(self.SDF_dmsPCI_ImportSegmentKey)
        btn60.clicked.connect(self.SDF_dmsPCI_KeyRecovery)
        btn61.clicked.connect(self.SDF_dmsPCI_SegMentKeyThreshold)
        btn62.clicked.connect(self.SDF_dmsPCI_GetSegMentKeyThreshold)
        btn63.clicked.connect(self.SDF_dmsPCI_KeyRecoveryInitThreshold)
        btn64.clicked.connect(self.SDF_dmsPCI_ImportSegmentKeyThreshold)
        btn65.clicked.connect(self.SDF_dmsPCI_KeyRecoveryThreshold)
        #随机数检测操作类函数
        btn66.clicked.connect(self.SDF_dmsCMRandomSingleDetection)
        btn67.clicked.connect(self.SDF_dmsCMRandomPowerOnSelfTest)
        btn68.clicked.connect(self.SDF_dmsCMRandomCycleDetection)


        self.setGeometry(310, 150, 1246, 678)
        self.setWindowTitle('MMJ Test')
        self.show()

    # *******************************设备管理类函数**************************************
    def SDF_OpenDevice(self):
        ret = gm.SDF_OpenDevice(byref(hDeviceHandle))
        if ret == 0:
            self.output.append("SDF_Opendevice success, ret = 0x%x" % ret)
            self.output.append(" hDeviceHandle ID = %s" % hDeviceHandle.value)
        else:
            self.output.append("SDF_Opendevice fail, ret = 0x%08x" % ret)

    def SDF_OpenDeviceWithCfg(self):
        pcCfgPath = "C:\\Users\\xiaorang\\PycharmProjects\\QT\\venv\\src\\"
        ret = gm.SDF_OpenDeviceWithCfg(pcCfgPath.encode(), byref(hDeviceHandle))
        if ret == 0:
            self.output.append("SDF_OpenDeviceWithCfg success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_OpenDeviceWithCfg fail, ret = 0x%08x" % ret)

    def SDF_CloseDevice(self):
        ret = gm.SDF_CloseDevice(hDeviceHandle)
        if ret == 0:
            self.output.append("SDF_CloseDevice success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CloseDevice fail, ret = 0x%08x" % ret)

    def SDF_OpenSession(self):
        ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
        if ret == 0:
            self.output.append("SDF_OpenSession success, ret = 0x%x" % ret)
            self.output.append("hSessionHandle ID = %s" % hSessionHandle.value)
        else:
            self.output.append("SDF_OpenSession fail, ret = 0x%08x" % ret)

    def SDF_CloseSession(self):
        ret = gm.SDF_CloseSession(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_CloseSession success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CloseSession fail, ret = 0x%08x" % ret)

    def SDF_GetDeviceInfo(self):
        pstDeviceInfo = DEVICEINFO()
        ret = gm.SDF_GetDeviceInfo(hSessionHandle, byref(pstDeviceInfo))
        if ret == 0:
            self.output.append("SDF_GetDeviceInfo success, ret = 0x%x" % ret)
            seq1 = []
            for i in range(40):
                seq1.append(chr(pstDeviceInfo.IssuerName[i]))
            self.output.append("IssuerName = %s" % (''.join(seq1)))
            seq2 = []
            for i in range(16):
                seq2.append(chr(pstDeviceInfo.DeviceName[i]))
            self.output.append("DeviceName = %s" % (''.join(seq2)))
            seq3 = []
            for i in range(16):
                seq3.append(chr(pstDeviceInfo.DeviceSerial[i]))
            self.output.append("DeviceSerial = %s" % (''.join(seq3)))
            self.output.append("DeviceVersion = %d" % pstDeviceInfo.DeviceVersion)
            self.output.append("StandardVersion = %d" % pstDeviceInfo.StandardVersion)
            self.output.append("AsymAlgAbility = %s, 最大模长 = %d" % (pstDeviceInfo.AsymAlgAbility[0], pstDeviceInfo.AsymAlgAbility[1]))
            self.output.append("SymAlgAbility = %s" % pstDeviceInfo.SymAlgAbility)
            self.output.append("HashAlgAbility = %s" % pstDeviceInfo.HashAlgAbility)
            self.output.append("BufferSize = %s" % pstDeviceInfo.BufferSize)
        else:
            self.output.append("SDF_GetDeviceInfo fail, ret = 0x%08x" % ret)

    def SDF_GenerateRandom(self):
        input6 = self.input6.text()
        if input6 == '':
            self.output.append("请输入生产随机数的长度：")
            return
        uiLength = int(input6)
        pucRandom = (c_ubyte * 16384)()
        ret = gm.SDF_GenerateRandom(hSessionHandle, uiLength, pucRandom)
        if ret == 0:
            self.output.append('SDF_GenerateRandom success, ret = 0x%x' % ret)
            seq = []
            for i in range(uiLength):
                seq.append(hex(pucRandom[i]))
            self.output.append("随机数：\n%s" % seq)
        else:
            self.output.append("SDF_GenerateRandom fail, ret = 0x%08x" % ret)

    def SDF_GetPrivateKeyAccessRight(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入获取指定私钥的Index：")
            return
        pucPassword = self.input2.text()
        if pucPassword == '':
            self.output.append("请输入正确的Password：")
            return
        uiPwdLength = len(pucPassword)
        ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, int(uiKeyIndex), pucPassword.encode(), uiPwdLength)
        if ret == 0:
            self.output.append("SDF_GetPrivateKeyAccessRight success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)

    def SDF_ReleasePrivateKeyAccessRight(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入释放私钥的Index：")
            return
        ret = gm.SDF_ReleasePrivateKeyAccessRight(hSessionHandle, int(uiKeyIndex))
        if ret == 0:
            self.output.append("SDF_ReleasePrivateKeyAccessRight success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ReleasePrivateKeyAccessRight fail, ret = 0x%08x" % ret)

    # *******************************密钥管理类函数**************************************
    def SDF_ExportSignPublicKey_ECC(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入导出签名公钥的索引值Index（1~49）：")
            return 0
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
            seq_x = []
            for i in range(ECCref_MAX_LEN):
                seq_x.append(hex((pucPublicKey.x)[i]))
            self.output.append("X分量：\n%s" % seq_x)
            seq_y = []
            for j in range(ECCref_MAX_LEN):
                seq_y.append(hex((pucPublicKey.y)[j]))
            self.output.append("y分量：\n%s" % seq_y)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)

    def SDF_ExportEncPublicKey_ECC(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入导出加密公钥的索引值Index（1~49）：")
            return 0
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
            seq_x = []
            for i in range(ECCref_MAX_LEN):
                seq_x.append(hex((pucPublicKey.x)[i]))
            self.output.append("X分量：\n%s" % seq_x)
            seq_y = []
            for j in range(ECCref_MAX_LEN):
                seq_y.append(hex((pucPublicKey.y)[j]))
            self.output.append("y分量：\n%s" % seq_y)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateKeyPair_ECC(self):
        uiAlgID = SGD_SM2
        uiKeyBits = 256
        pucPublicKey = ECCrefPublicKey()
        pucPrivateKey = ECCrefPrivateKey()
        ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits, byref(pucPublicKey), byref(pucPrivateKey))
        if ret == 0:
            self.output.append("SDF_GenerateKeyPair_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyPair_ECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateKeyWithIPK_ECC(self):
        uiIPKIndex = self.input1.text()
        if uiIPKIndex == '':
            self.output.append("请输入加密会话密钥内部公钥的索引值Index（1~49）：")
            return 0
        uiKeyBits = self.input7.text()
        if uiKeyBits == '':
            self.output.append("请输入生成会话密钥的长度：")
            return 0
        ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, int(uiIPKIndex), int(uiKeyBits), byref(pucKey1), byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithIPK_ECC success, ret = 0x%x" % ret)
            self.output.append("sessionKey ID: %s" % phKeyHandle.value)
        else:
            self.output.append("SDF_GenerateKeyWithIPK_ECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateKeyWithEPK_ECC(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入内部公钥转外部公钥的索引值Index（1~49）：")
            return 0
        uiKeyBits = self.input7.text()
        if uiKeyBits == '':
            self.output.append("请输入生成会话密钥的长度：")
            return 0
        uiAlgID = SGD_SM2_1
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)
        ret = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, int(uiKeyBits), uiAlgID, byref(pucPublicKey), byref(pucKey1),
                                            byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithEPK_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithEPK_ECC fail, ret = 0x%08x" % ret)

    def SDF_ImportKeyWithISK_ECC(self):
        uiISKIndex = self.input1.text()
        if uiISKIndex == '':
            self.output.append("请输入内部公钥的索引值Index（1~49）：")
            return 0
        ret = gm.SDF_ImportKeyWithISK_ECC(hSessionHandle, int(uiISKIndex), byref(pucKey1), byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_ImportKeyWithISK_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ImportKeyWithISK_ECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateAgreementDataWithECC(self):
        index = self.input1.text()
        if index == '':
            self.output.append("请输入进行密钥协商发起方的加密索引值：")
            return 0
        uiKeyBits = self.input7.text()
        if uiKeyBits == '':
            self.output.append("请输入生成会话密钥的长度：")
            return 0
        ret = gm.SDF_GenerateAgreementDataWithECC(hSessionHandle, int(index), int(uiKeyBits), pucSponsorID.encode(),
                                                  uiSponsorIDLength, byref(pucSponsorPublicKey),
                                                  byref(pucSponsorTmpPublicKey), byref(phAgreementHandle))
        if ret == 0:
            self.output.append("SDF_GenerateAgreementDataWithECC success, ret = 0x%x" % ret)
            self.output.append("out----phAgreementHandle = 0x%x" % phAgreementHandle.value)
        else:
            self.output.append("SDF_GenerateAgreementDataWithECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateKeyWithECC(self):
        self.output.append("in----phAgreementHandle = 0x%x" % phAgreementHandle.value)
        ret = gm.SDF_GenerateKeyWithECC(hSessionHandle, pucResponseID.encode(), uiResponseIDLength,
                                        byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey), phAgreementHandle,
                                        byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateAgreementDataAndKeyWithECC(self):
        index = self.input1.text()
        if index == '':
            self.output.append("请输入进行密钥协商响应方的加密索引值：")
            return 0
        uiKeyBits = self.input7.text()
        if uiKeyBits == '':
            self.output.append("请输入生成会话密钥的长度：")
            return 0
        ret = gm.SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, int(index), int(uiKeyBits), pucResponseID.encode(),
                                                        uiResponseIDLength, pucSponsorID.encode(), uiSponsorIDLength,
                                                        byref(pucSponsorPublicKey), byref(pucSponsorTmpPublicKey),
                                                        byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey),
                                                        byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateAgreementDataAndKeyWithECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateAgreementDataAndKeyWithECC fail, ret = 0x%08x" % ret)

    def SDF_ExchangeDigitEnvelopeBaseOnECC(self):
        testPublicKey = ECCrefPublicKey()
        pucPublicKey = ECCrefPublicKey()
        pucEncDataIn = ECCCipher()
        pucEncDataOut = ECCCipher()
        phKeyHandle = c_void_p()
        uiKeyBits = 128
        uiAlgID = SGD_SM2_3
        uiKeyIndex = 1
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 2, byref(testPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success index = 2, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail index = 2, ret = 0x%08x" % ret)
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success index = 1, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail index = 1, ret = 0x%08x" % ret)

        ret = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, uiKeyBits, uiAlgID, byref(pucPublicKey),
                                            byref(pucEncDataIn),
                                            byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithEPK_ECC success, index = 1 ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithEPK_ECC fail, index = 1 ret = 0x%08x" % ret)
        uiAlgID = SGD_SM2_1
        ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, uiKeyIndex, uiAlgID, byref(testPublicKey),
                                                    byref(pucEncDataIn), byref(pucEncDataOut))
        if ret == 0:
            self.output.append("SDF_ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % ret)
            seq_C = []
            print(pucEncDataOut.L)
            # for i in range(pucEncDataOut.L):
            #     seq_C.append(hex((pucEncDataOut.C)[i]))
            # self.output.append("C密文：\n%s" % seq_C)

        else:
            self.output.append("SDF_ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)

    def SDF_GenerateKeyWithKEK(self):
        uiKEKIndex = self.input1.text()
        if uiKEKIndex == '':
            self.output.append("请输入正确的密钥加密密钥索引值Index（1~10）：")
            return
        uiKeyBits = self.input7.text()
        if uiKeyBits == '':
            self.output.append("请输入生成会话密钥长度（128, 256, 512）：")
            return 0
        uiAlgID = SGD_SM4_ECB
        global pucKey, puiKeyLength
        puiKeyLength = c_uint()
        pucKey = (c_ubyte * 1024)()
        ret = gm.SDF_GenerateKeyWithKEK(hSessionHandle, int(uiKeyBits), uiAlgID, int(uiKEKIndex), pucKey,
                                        byref(puiKeyLength), byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithKEK success, ret = 0x%x" % ret)
            self.output.append("KeyLength: %s" % puiKeyLength.value)
            self.output.append("sessionKey ID: %s" % phKeyHandle.value)
        else:
            self.output.append("SDF_GenerateKeyWithKEK fail, ret = 0x%08x" % ret)

    def SDF_ImportKeyWithKEK(self):
        uiKEKIndex = self.input1.text()
        if uiKEKIndex == '':
            self.output.append("请输入正确的密钥加密密钥索引值Index（1~10）：")
            return
        uiAlgID = SGD_SM4_ECB
        ret = gm.SDF_ImportKeyWithKEK(hSessionHandle, uiAlgID, int(uiKEKIndex), byref(pucKey), puiKeyLength.value,
                                      byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_ImportKeyWithKEK success, ret = 0x%x" % ret)
            self.output.append("KeyLength: %s" % puiKeyLength.value)
            self.output.append("sessionKey ID: %s" % phKeyHandle.value)
        else:
            self.output.append("SDF_ImportKeyWithKEK fail, ret = 0x%08x" % ret)

    def SDF_DestroyKey(self):
        ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
        if ret == 0:
            self.output.append("SDF_DestroyKey success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DestroyKey fail, ret = 0x%08x" % ret)

    # *******************************非对称算法类函数**************************************
    def SDF_InternalSign_ECC(self):
        input1 = self.input1.text()
        if input1 == '':
            self.output.append("请输入私钥的索引值Index（1~49）：")
            return
        uiIndex = int(input1)
        input8 = self.input8.text()
        if input8 == '':
            self.output.append("请输入待签名的数据长度：")
            return
        uiDataLength = int(input8)
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        ret = gm.SDF_InternalSign_ECC(hSessionHandle, uiIndex, pucData, uiDataLength, byref(sign))
        if ret == 0:
            self.output.append("SDF_InternalSign_ECC success, ret = 0x%x" % ret)
            seq = []
            for i in range(uiDataLength):
                seq.append(hex(pucData[i]))
            self.output.append("SM2签名原文：\n%s" % seq)
        else:
            self.output.append("SDF_InternalSign_ECC fail, ret = 0x%08x" % ret)

    def SDF_InternalVerify_ECC(self):
        input1 = self.input1.text()
        if input1 == '':
            self.output.append("请输入私钥的索引值Index（1~49）：")
            return
        uiIndex = int(input1)
        input8 = self.input8.text()
        if input8 == '':
            self.output.append("请输入待签名的数据长度：")
            return
        uiDataLength = int(input8)
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        ret = gm.SDF_InternalVerify_ECC(hSessionHandle, uiIndex, pucData, uiDataLength, byref(sign))
        if ret == 0:
            self.output.append("SDF_InternalVerify_ECC success, ret = 0x%x" % ret)
            seq = []
            for i in range(uiDataLength):
                seq.append(hex(pucData[i]))
            self.output.append("SM2验签原文：\n%s" % seq)
        else:
            self.output.append("SDF_InternalVerify_ECC fail, ret = 0x%08x" % ret)

    def SDF_ExternalVerify_ECC(self):
        input1 = self.input1.text()
        if input1 == '':
            self.output.append("请输入私钥的索引值Index（1~49）：")
            return
        uiIndex = int(input1)
        input8 = self.input8.text()
        if input8 == '':
            self.output.append("请输入待签名的数据长度：")
            return
        uiDataLength = int(input8)
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        pbBlob = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, uiIndex, byref(pbBlob))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        ret = gm.SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, byref(pbBlob), pucData, uiDataLength, byref(sign))
        if ret == 0:
            self.output.append("SDF_ExternalVerify_ECC success, ret = 0x%x" % ret)
            seq = []
            for i in range(uiDataLength):
                seq.append(hex(pucData[i]))
            self.output.append("SM2验签原文：\n%s" % seq)
        else:
            self.output.append("SDF_ExternalVerify_ECC fail, ret = 0x%08x" % ret)

    def SDF_ExternalEncrypt_ECC(self):
        uiIndex = self.input1.text()
        if uiIndex == '':
            self.output.append("请输入内部公钥转外部公钥的索引值Index（1~49）：")
            return 0
        uiDataLength = self.input8.text()
        if uiDataLength == '':
            self.output.append("请输入加密数据的长度：")
            return 0
        for i in range(int(uiDataLength)):
            pucData[i] = int(i % 256)
        pucPublickey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiIndex), byref(pucPublickey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)
        uiAlgID = SGD_SM2_3
        pucEncData = ECCCipher()
        ret = gm.SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, byref(pucPublickey), pucData, int(uiDataLength),
                                         byref(pucEncData))
        if ret == 0:
            self.output.append("SDF_ExternalVerify_ECC success, ret = 0x%x" % ret)
            seq = []
            for i in range(int(uiDataLength)):
                seq.append(hex(pucData[i]))
            self.output.append("SM2加密明文：\n%s" % seq)
        else:
            self.output.append("SDF_ExternalVerify_ECC fail, ret = 0x%08x" % ret)

    # *******************************对称算法类函数**************************************
    def SDF_Encrypt(self):
        input8 = self.input8.text()
        if input8 == '':
            self.output.append("请输入加密数据的长度：")
            return 0
        uiDataLength = int(input8)
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        uiAlgID = SGD_SM4_ECB
        memset(pucIV, 0x00, sizeof(pucIV))
        uiEncDataLength = c_uint(uiDataLength)
        ret = gm.SDF_Encrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData,
                             byref(uiEncDataLength))
        if ret == 0:
            self.output.append("SDF_Encrypt success, ret = 0x%x" % ret)
            seq = []
            for i in range(uiDataLength):
                seq.append(hex(pucData[i]))
            self.output.append("加密明文：\n%s" % seq)
        else:
            self.output.append("SDF_Encrypt fail, ret = 0x%08x" % ret)

    def SDF_Decrypt(self):
        input8 = self.input8.text()
        if input8 == '':
            self.output.append("请输入解密数据的长度：")
            return 0
        uiDataLength = int(input8)
        uiAlgID = SGD_SM4_ECB
        plain = (c_ubyte * 65536)()
        uiEncDataLength = uiDataLength
        plainLength = c_uint(uiDataLength)
        memset(pucIV, 0x00, sizeof(pucIV))
        ret = gm.SDF_Decrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, plain,
                             byref(plainLength))
        if ret == 0:
            self.output.append("SDF_Decrypt success, ret = 0x%x" % ret)
            seq = []
            for i in range(uiDataLength):
                seq.append(hex(plain[i]))
            self.output.append("解密明文：\n%s" % seq)
        else:
            self.output.append("SDF_Decrypt fail, ret = 0x%08x" % ret)

    def SDF_CalculateMAC(self):
        input8 = self.input8.text()
        if input8 == '':
            self.output.append("请输入计算MAC数据的长度：")
            return 0
        uiInDataLength = int(input8)
        uiAlgID = SGD_SM4_ECB
        memset(pucIV, 0x00, sizeof(pucIV))
        pucInData = arr1024()
        for i in range(uiInDataLength):
            pucInData[i] = int(i % 256)
        self.output.append("计算mac的明文数据：\n%s" % pucInData[0:uiInDataLength])
        pucMAC = arr4()
        uiMACLength = c_uint(4)
        ret = gm.SDF_CalculateMAC(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucInData, uiInDataLength, pucMAC,
                                  byref(uiMACLength))
        if ret == 0:
            self.output.append("SDF_CalculateMAC success, ret = 0x%x" % ret)
            seq = []
            for i in range(4):
                seq.append(hex(pucMAC[i]))
            self.output.append("MAC值：\n%s" % seq)
        else:
            self.output.append("SDF_CalculateMAC fail, ret = 0x%08x" % ret)

    # *******************************杂凑算法类函数**************************************
    def SDF_HashInit(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入Hash初始化的公钥Index（1~49）：")
            return 0
        pucID = self.input8.text()
        if pucID == '':
            self.output.append("请输入signer ID：")
            return 0
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        AlgID = SGD_SM3
        uiIDLength = len(pucID)
        ret = gm.SDF_HashInit(hSessionHandle, AlgID, pucPublicKey, pucID, uiIDLength)
        if ret == 0:
            self.output.append("SDF_HashInit success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_HashInit fail, ret = 0x%08x" % ret)

    def SDF_HashUpdate(self):
        str8 = self.input8.text()
        if str8 == '':
            self.output.append("请输入待Hash的数据长度：")
            return 0
        uiDataLength = int(self.input8.text())
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        ret = gm.SDF_HashUpdate(hSessionHandle, pucData, uiDataLength)
        if ret == 0:
            self.output.append("SDF_HashUpdate success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_HashUpdate fail, ret = 0x%08x" % ret)

    def SDF_HashFinal(self):
        pucHash = arr32()
        uiHashLength = c_uint()
        ret = gm.SDF_HashFinal(hSessionHandle, pucHash, byref(uiHashLength))
        if ret == 0:
            self.output.append("SDF_HashFinal success, ret = 0x%x" % ret)
            seq = []
            for i in range(32):
                seq.append(hex(pucHash[i]))
            self.output.append("Hash值：\n%s" % seq)
        else:
            self.output.append("SDF_HashFinal fail, ret = 0x%08x" % ret)

    # *******************************文件操作类函数**************************************
    def SDF_CreateFile(self):
        pucFileName = self.input3.text()
        if pucFileName == '':
            self.output.append("文件名为空，请输入文件名：")
        uiNameLen = len(pucFileName)
        uiFileSize = self.input4.text()
        if uiFileSize == '':
            self.output.append("请输入创建文件的大小(32K)：")
            return 0
        ret = gm.SDF_CreateFile(hSessionHandle, pucFileName.encode(), uiNameLen, int(uiFileSize))
        if ret == 0:
            self.output.append("SDF_CreateFile success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CreateFile fail, ret = 0x%08x" % ret)

    def SDF_ReadFile(self):
        if self.input3.text() == '':
            self.output.append("请输入文件名：")
            return 0
        if self.input4.text() == '':
            self.output.append("请输入文件长度：")
            return 0
        if self.input5.text() == '':
            self.output.append("请输入偏移地址：")
            return 0
        pucFileName = self.input3.text()
        puiFileLength = int(self.input4.text())
        uiOffset = int(self.input5.text())
        uiNameLen = len(pucFileName)
        pucBuffer = (c_ubyte * puiFileLength)()
        ret = gm.SDF_ReadFile(hSessionHandle, pucFileName.encode(), uiNameLen, uiOffset, byref(c_uint(puiFileLength)),
                              pucBuffer)
        if ret == 0:
            self.output.append("SDF_ReadFile success, ret = 0x%x" % ret)
            seq = []
            for i in range(puiFileLength):
                seq.append(hex(pucBuffer[i]))
            self.output.append("read data：\n%s" % seq)
        else:
            self.output.append("SDF_ReadFile fail, ret = 0x%08x" % ret)

    def SDF_WriteFile(self):
        if self.input3.text() == '':
            self.output.append("请输入文件名：")
            return 0
        if self.input4.text() == '':
            self.output.append("请输入文件长度：")
            return 0
        if self.input5.text() == '':
            self.output.append("请输入偏移地址：")
            return 0
        pucFileName = self.input3.text()
        uiNameLen = len(pucFileName)
        puiFileLength = int(self.input4.text())
        uiOffset = int(self.input5.text())
        pucBuffer = (c_ubyte * 32678)()
        for i in range(puiFileLength):
            pucBuffer[i] = int(i % 256)
        ret = gm.SDF_WriteFile(hSessionHandle, pucFileName.encode(), uiNameLen, uiOffset, puiFileLength, pucBuffer)
        if ret == 0:
            self.output.append("SDF_WriteFile success, ret = 0x%x" % ret)
            seq = []
            for i in range(puiFileLength):
                seq.append(hex(i % 256))
            self.output.append("write data：\n%s" % seq)
        else:
            self.output.append("SDF_WriteFile fail, ret = 0x%08x" % ret)

    def SDF_DeleteFile(self):
        pucFileName = self.input3.text()
        if pucFileName == '':
            self.output.append("请输入文件名：")
            return 0
        nameLen = len(pucFileName)
        ret = gm.SDF_DeleteFile(hSessionHandle, pucFileName.encode(), nameLen)
        if ret == 0:
            self.output.append("SDF_DeleteFile success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DeleteFile fail, ret = 0x%08x" % ret)

    def SDF_EnumFiles(self):
        szFileList = (c_byte * 1024)()
        pulSize = c_uint(1024)
        ret = gm.SDF_EnumFiles(hSessionHandle, szFileList, byref(pulSize))
        if ret == 0:
            self.output.append("SDF_EnumFiles success, ret = 0x%x" % ret)
            seq = []
            for i in range(pulSize.value):
                seq.append(chr(szFileList[i]))
            self.output.append('fileName:%s'%seq)
        else:
            self.output.append("SDF_EnumFiles fail, ret = 0x%08x" % ret)

    def clearLog(self):
        self.output.document().clear()

    def SDF_dmsPCI_PCICardInit(self):
        pcPin = self.input2.text()
        if pcPin == '':
            self.output.append("请输入设备管理PIN码")
        ret = gm.SDF_dmsPCI_PCICardInit(hSessionHandle, pcPin.encode())
        if ret == 0:
            self.output.append("SDF_dmsPCI_PCICardInit success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_PCICardInit fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_PCICardGenerateMatrix(self):
        ret = gm.SDF_dmsPCI_PCICardGenerateMatrix(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_dmsPCI_PCICardGenerateMatrix success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_PCICardGenerateMatrix fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_AlgSelfInspection(self):
        ret = gm.SDF_dmsPCI_AlgSelfInspection(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_dmsPCI_AlgSelfInspection success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_AlgSelfInspection fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ImportPubMatrix(self):
        self.output.append("待导入公钥矩阵数据：\n%s" % pucPubMatrix[:])
        ret = gm.SDF_dmsPCI_ImportPubMatrix(hSessionHandle, pucPubMatrix, puiMatLen.value)
        if ret == 0:
            self.output.append("SDF_dmsPCI_ImportPubMatrix success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_ImportPubMatrix fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ExportPubMatrix(self):
        global pucPubMatrix, puiMatLen
        puiMatLen = c_uint(32788)
        pucPubMatrix = (c_ubyte * 32788)()
        ret = gm.SDF_dmsPCI_ExportPubMatrix(hSessionHandle, pucPubMatrix, byref(puiMatLen))
        if ret == 0:
            self.output.append("SDF_dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
            self.output.append("公钥矩阵：\n%s" % pucPubMatrix[:])
        else:
            self.output.append("SDF_dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_GetKeyPoolState(self):
        pKeyPoolStInfo = KeyPoolStateInfo()
        ret = gm.SDF_dmsPCI_GetKeyPoolState(hSessionHandle, byref(pKeyPoolStInfo))
        if ret == 0:
            self.output.append("SDF_dmsPCI_GetKeyPoolState success, ret = 0x%x" % ret)
            self.output.append("密钥池状态：\n%s" % pKeyPoolStInfo.ucKeyPoolStates[:])
        else:
            self.output.append("SDF_dmsPCI_GetKeyPoolState fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_GenECCKeyPair(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入产生签名公钥和加密公钥的索引值Index（1~49）：")
            return 0
        global pTmpSignPublicKey, pTmpEncPublicKey
        pTmpSignPublicKey = ECCrefPublicKey()
        pTmpEncPublicKey = ECCrefPublicKey()
        ret = gm.SDF_dmsPCI_GenECCKeyPair(hSessionHandle, int(uiKeyIndex), byref(pTmpSignPublicKey), byref(pTmpEncPublicKey))
        if ret == 0:
            self.output.append("SDF_dmsPCI_GenECCKeyPair success, ret = 0x%x" % ret)
            self.output.append("######################上传公钥######################")
            self.output.append("pucTmpSignPubKey x分量：\n%s" % pTmpSignPublicKey.x[:])
            self.output.append("pucTmpSignPubKey y分量：\n%s" % pTmpSignPublicKey.y[:])
            self.output.append("pucTmpEncPubKey x分量：\n%s" % pTmpEncPublicKey.x[:])
            self.output.append("pucTmpEncPubKey y分量：\n%s" % pTmpEncPublicKey.y[:])
        else:
            self.output.append("SDF_dmsPCI_GenECCKeyPair fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ImportKeyWithECCKeyPair(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入导入密钥对的索引值Index（1~49）：")
            return 0
        ret = gm.SDF_dmsPCI_ImportKeyWithECCKeyPair(hSessionHandle, int(uiKeyIndex), byref(pSke))
        if ret == 0:
            self.output.append("SDF_dmsPCI_ImportKeyWithECCKeyPair success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_ImportKeyWithECCKeyPair fail, ret = 0x%08x" % ret)


    def SDF_dmsPCI_CalculatePersonKey(self):
        pucIdentify = self.input8.text()
        if pucIdentify == '':
            self.output.append("请输入计算用户密钥的标识： ")
        uiRegion = 1
        identidfyLength = len(pucIdentify)
        pucLicenceIssuingAuthority = 'ahdms'
        pucTakeEffectDate = '2020-06-24'
        pucLoseEffectDate = '2022-06-24'
        pucTmpSignPubKey = pTmpSignPublicKey
        pucTmpEncPubKey = pTmpEncPublicKey
        pucPke = ECCrefPublicKey()
        pucPks = ECCrefPublicKey()
        global pSke
        pSke = EnvelopedKeyBlob()
        ret = gm.SDF_dmsPCI_CalculatePersonKey(hSessionHandle, uiRegion,
                                               pucIdentify.encode(),
                                               pucLicenceIssuingAuthority.encode(),
                                               pucTakeEffectDate.encode(),
                                               pucLoseEffectDate.encode(),
                                               byref(pucTmpSignPubKey), byref(pucTmpEncPubKey),
                                               byref(pucPke), byref(pucPks), byref(pSke))
        if ret == 0:
            self.output.append("SDF_dmsPCI_CalculatePersonKey success, ret = 0x%x" % ret)
            self.output.append("identidfyLength = %s" % identidfyLength)
            self.output.append("######################上传公钥######################")
            self.output.append("pucTmpSignPubKey x分量：\n%s" % pucTmpSignPubKey.x[:])
            self.output.append("pucTmpSignPubKey y分量：\n%s" % pucTmpSignPubKey.y[:])
            self.output.append("pucTmpEncPubKey x分量：\n%s" % pucTmpEncPubKey.x[:])
            self.output.append("pucTmpEncPubKey y分量：\n%s" % pucTmpEncPubKey.y[:])
            self.output.append("######################输出公钥######################")
            self.output.append("签名公钥Pks x分量：\n%s" % pucPks.x[:])
            self.output.append("签名公钥Pks y分量：\n%s" % pucPks.y[:])
            self.output.append("加密公钥pke x分量：\n%s" % pucPke.x[:])
            self.output.append("加密公钥pke y分量：\n%s" % pucPke.y[:])
        else:
            self.output.append("SDF_dmsPCI_CalculatePersonKey fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ClearECCKeyPair(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入删除密钥对的索引值Index（1~49）：")
            return 0
        pcManagePin = self.input2.text()
        if pcManagePin == '':
            self.output.append("请输入正确的Password：")
            return 0
        ret = gm.SDF_dmsPCI_ClearECCKeyPair(hSessionHandle, pcManagePin.encode(), int(uiKeyIndex))
        if ret == 0:
            self.output.append("SDF_dmsPCI_ClearECCKeyPair success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_ClearECCKeyPair fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ChangeCardPIN(self):
        pcOldManagePin = self.input2.text()
        if pcOldManagePin == '':
            self.output.append("请输入正确的Old PassWord：")
            return 0
        pcNewManagePin = self.input8.text()
        if pcNewManagePin == '':
            self.output.append("请输入正确的New PassWord：")
            return 0
        ret = gm.SDF_dmsPCI_ChangeCardPIN(hSessionHandle, pcOldManagePin.encode(), pcNewManagePin.encode())
        if ret == 0:
            self.output.append("SDF_dmsPCI_ChangeCardPIN success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_ChangeCardPIN fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ChangeKeyPIN(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入删除密钥对的索引值Index（1~49）：")
            return 0
        pcOldKeyPin = self.input2.text()
        if pcOldKeyPin == '':
            self.output.append("请输入正确的Old私钥权限码：")
            return 0
        pcNewKeyPin = self.input8.text()
        if pcNewKeyPin == '':
            self.output.append("请输入正确的New私钥权限码：")
            return 0
        ret = gm.SDF_dmsPCI_ChangeKeyPIN(hSessionHandle, int(uiKeyIndex), pcOldKeyPin.encode(), pcNewKeyPin.encode())
        if ret == 0:
            self.output.append("SDF_dmsPCI_ChangeKeyPIN success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_ChangeKeyPIN fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_GenerateKEK(self):
        puiKEKindex = c_uint()
        ret = gm.SDF_dmsPCI_GenerateKEK(hSessionHandle, byref(puiKEKindex))
        if ret == 0:
            self.output.append("SDF_dmsPCI_GenerateKEK success, ret = 0x%x" % ret)
            self.output.append("puiKEKindex:%s" % puiKEKindex.value)

        else:
            self.output.append("SDF_dmsPCI_GenerateKEK fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_DeleteKEK(self):
        uiKEKindex = self.input1.text()
        if uiKEKindex == '':
            self.output.append("请输入需删除的密钥加密密钥索引值Index（1~10）：")
            return 0
        ret = gm.SDF_dmsPCI_DeleteKEK(hSessionHandle, int(uiKEKindex))
        if ret == 0:
            self.output.append("SDF_dmsPCI_DeleteKEK success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_DeleteKEK fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_GetKEKPoolState(self):
        pucKEKState = (c_ubyte * 100)()
        puiKEKStateLen = c_uint(100)
        ret = gm.SDF_dmsPCI_GetKEKPoolState(hSessionHandle, pucKEKState, byref(puiKEKStateLen))
        if ret == 0:
            self.output.append("SDF_dmsPCI_GetKEKPoolState success, ret = 0x%x" % ret)
            self.output.append("对称密钥池状态：%s" % pucKEKState[:])
        else:
            self.output.append("SDF_dmsPCI_GetKEKPoolState fail, ret = 0x%08x" % ret)


    def SDF_dmsPCI_CalculatePKid_ExtPKM(self):
        pucIdentify = self.input8.text()
        if pucIdentify == '':
            self.output.append("请输入计算公钥的标识： ")
        pucPubMatrix = (c_ubyte * 32788)()
        uiPubmatrixLen = c_uint(32788)
        ret = gm.SDF_dmsPCI_ExportPubMatrix(hSessionHandle, pucPubMatrix, byref(uiPubmatrixLen))
        if ret == 0:
            self.output.append("SDF_dmsPCI_ExportPubMatrix success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_ExportPubMatrix fail, ret = 0x%08x" % ret)
        uiRegion = 0
        pECCPubkey = ECCrefPublicKey()
        ret = gm.SDF_dmsPCI_CalculatePKid_ExtPKM(hSessionHandle, uiRegion,
                                                 pucIdentify.encode(),
                                                 byref(pucPubMatrix), uiPubmatrixLen,
                                                 byref(pECCPubkey))
        if ret == 0:
            self.output.append("SDF_dmsPCI_CalculatePKid_ExtPKM success, ret = 0x%x" % ret)
            seq_x = []
            for i in range(ECCref_MAX_LEN):
                seq_x.append(hex((pECCPubkey.x)[i]))
            self.output.append("计算公钥的X分量：\n%s" % seq_x)
            seq_y = []
            for j in range(ECCref_MAX_LEN):
                seq_y.append(hex((pECCPubkey.y)[j]))
            self.output.append("计算公钥的y分量：\n%s" % seq_y)

        else:
            self.output.append("SDF_dmsPCI_CalculatePKid_ExtPKM fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_IdentifyECCSignForEnvelope(self):
        uiRegion = 0
        pucIdentity = '123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456789'
        pucSignID = '12345678'
        pucData = '12345678'
        uiDataLen = len(pucData)
        puiSignAlgorithm = c_uint()
        puiHashAlgorithm = c_uint()
        pEccSign = ECCSignature()
        ret = gm.SDF_dmsPCI_IdentifyECCSignForEnvelope(hSessionHandle, uiRegion,
                                                 pucIdentity.encode(),
                                                 pucSignID.encode(),
                                                 pucData, uiDataLen,
                                                 byref(puiSignAlgorithm), byref(puiHashAlgorithm),
                                                 byref(pEccSign))
        if ret == 0:
            self.output.append("SDF_dmsPCI_IdentifyECCSignForEnvelope success, ret = 0x%x" % ret)
            self.output.append("puiSignAlgorithm = 0x%08x, puiHashAlgorithm = 0x%08x" % (puiSignAlgorithm.value, puiHashAlgorithm.value))
        else:
            self.output.append("SDF_dmsPCI_IdentifyECCSignForEnvelope fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_SegMentKey(self):
        global uiGroup
        uiGroup = self.input8.text()
        if uiGroup == '':
            self.output.append("请密钥分割组数，2 <= nGroup <= 9：")
            return 0
        pcManagePin = self.input2.text()
        if pcManagePin == '':
            self.output.append("请输入正确的设备管理PIN码：")
            return 0
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入待分割的私钥索引值，为0xFFFFFFFF(4294967295)时表示对PCIe卡的私钥矩阵和所有密钥进行分割：")
            return 0
        # uiKeyIndex = c_ulong(4294967295)
        ret = gm.SDF_dmsPCI_SegMentKey(hSessionHandle, int(uiGroup), pcManagePin.encode(), int(uiKeyIndex))
        if ret == 0:
            self.output.append("SDF_dmsPCI_SegMentKey success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_SegMentKey fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_GetSegMentKey(self):
        pcPassword = self.input2.text()
        if pcPassword == '':
            self.output.append("请输入保护分割密钥的密码：")
            return 0
        global pucSegKey, puiSegKeyLen
        #全密钥2 4064，单密钥1 60
        pucSegKey = (c_ubyte * 24064 * 9)()
        puiSegKeyLen = c_ulong(24064 * 9)
        pucSegKeyTemp = (c_ubyte * 24064)()
        puiSegKeyLenTemp = c_uint(24064)
        for i in range(int(uiGroup)):
            ret = gm.SDF_dmsPCI_GetSegMentKey(hSessionHandle, pcPassword.encode(), pucSegKeyTemp, byref(puiSegKeyLenTemp))
            if ret == 0:
                self.output.append("SDF_dmsPCI_GetSegMentKey success, ret = 0x%x" % ret)
                memmove(byref(pucSegKey, 24064 * i), pucSegKeyTemp, 24064)
                print(puiSegKeyLenTemp.value)
            else:
                self.output.append("SDF_dmsPCI_GetSegMentKey fail, ret = 0x%08x" % ret)
                return 0

    def SDF_dmsPCI_KeyRecoveryInit(self):
        uiGroup = self.input8.text()
        if uiGroup == '':
            self.output.append("请设置密钥恢复组数，2 <= nGroup <= 9：")
            return 0
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入待分割的私钥索引值，uiKeyIndex为0xFFFFFFFF(4294967295)时表示对PCIe卡的私钥矩阵和所有密钥进行分割：")
            return 0
        ret = gm.SDF_dmsPCI_KeyRecoveryInit(hSessionHandle, int(uiGroup), int(uiKeyIndex))
        if ret == 0:
            self.output.append("SDF_dmsPCI_KeyRecoveryInit success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_KeyRecoveryInit fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ImportSegmentKey(self):
        pcPassword = self.input2.text()
        if pcPassword == '':
            self.output.append("请输入保护分割密钥的密码：")
            return 0
        uiGroup = self.input8.text()
        if uiGroup == '':
            self.output.append("请输入导入分割密钥的组数：")
            return 0
        pucSegKeyTemp = (c_ubyte * 24064)()
        puiSegKeyLenTemp = 24064
        for i in range(int(uiGroup)):
            memmove(pucSegKeyTemp, byref(pucSegKey, 24064 * i), 24064)
            ret = gm.SDF_dmsPCI_ImportSegmentKey(hSessionHandle, pcPassword.encode(), pucSegKeyTemp, puiSegKeyLenTemp)
            if ret == 0:
                self.output.append("SDF_dmsPCI_ImportSegmentKey success, ret = 0x%x" % ret)
            else:
                self.output.append("SDF_dmsPCI_ImportSegmentKey fail, ret = 0x%08x" % ret)
                return 0

    def SDF_dmsPCI_KeyRecovery(self):
        ret = gm.SDF_dmsPCI_KeyRecovery(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_dmsPCI_KeyRecovery success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_KeyRecovery fail, ret = 0x%08x" % ret)

    #三五门限恢复
    def SDF_dmsPCI_SegMentKeyThreshold(self):
        pcManagePin = self.input2.text()
        if pcManagePin == '':
            self.output.append("请输入正确的设备管理PIN码：")
            return 0
        global uiSgmNum, uiRecoverNum
        uiSgmNum = 5
        uiRecoverNum = 3
        global pucPciData, puiPciDataLen
        pucPciData = (c_ubyte * 32788)()
        puiPciDataLen = c_uint(32788)
        ret = gm.SDF_dmsPCI_SegMentKeyThreshold(hSessionHandle, uiSgmNum, uiRecoverNum,
                                                pcManagePin.encode(), pucPciData, byref(puiPciDataLen))
        if ret == 0:
            self.output.append("SDF_dmsPCI_SegMentKeyThreshold success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_SegMentKeyThreshold fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_GetSegMentKeyThreshold(self):
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入保护秘钥分割数据的公钥的索引值Index（1~49）：")
            return 0
        #导出公钥
        pPubKey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, int(uiKeyIndex), byref(pPubKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)

        global pCipherKey, pCipherKeyTemp
        pCipherKey = (c_ubyte * 196 * 5)()
        pCipherKeyTemp = (c_ubyte * 196)()
        for i in range(uiSgmNum):
            ret = gm.SDF_dmsPCI_GetSegMentKeyThreshold(hSessionHandle, byref(pPubKey), pCipherKeyTemp)
            if ret == 0:
                self.output.append("第%s次：SDF_dmsPCI_GetSegMentKeyThreshold success" % (i + 1))
                memmove(byref(pCipherKey, 196 * i), pCipherKeyTemp, 196)
            else:
                self.output.append("SDF_dmsPCI_GetSegMentKeyThreshold fail, ret = 0x%08x" % ret)
                return 0

    def SDF_dmsPCI_KeyRecoveryInitThreshold(self):
        pPubKeyTmp = ECCrefPublicKey()
        ret = gm.SDF_dmsPCI_KeyRecoveryInitThreshold(hSessionHandle, uiRecoverNum, byref(pPubKeyTmp))
        if ret == 0:
            self.output.append("SDF_dmsPCI_KeyRecoveryInitThreshold success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_KeyRecoveryInitThreshold fail, ret = 0x%08x" % ret)
        # 数字信封交换
        uiAlgID = SGD_SM2_3
        uiKeyIndex = self.input1.text()
        if uiKeyIndex == '':
            self.output.append("请输入保护秘钥分割数据的公钥的索引值Index（1~49）：")
            return 0
        global pCipherKeyEx, pCipherKeyExTemp
        pCipherKeyEx = (c_ubyte * 196 * 5)()
        pCipherKeyExTemp = (c_ubyte * 196)()
        for i in range(uiRecoverNum):
            memmove(pCipherKeyTemp, byref(pCipherKey, 196 * i), 196)
            ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, int(uiKeyIndex), uiAlgID, byref(pPubKeyTmp), pCipherKeyTemp, pCipherKeyExTemp)
            if ret == 0:
                self.output.append("第%s次SDF_ExchangeDigitEnvelopeBaseOnECC success" % (i + 1))
                memmove(byref(pCipherKeyEx, 196 * i), pCipherKeyExTemp, 196)
            else:
                self.output.append("SDF_ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)

    def SDF_dmsPCI_ImportSegmentKeyThreshold(self):
        for i in range(uiRecoverNum):
            memmove(pCipherKeyExTemp, byref(pCipherKeyEx, 196 * i), 196)
            ret = gm.SDF_dmsPCI_ImportSegmentKeyThreshold(hSessionHandle, pCipherKeyExTemp)
            if ret == 0:
                self.output.append("第%s次SDF_dmsPCI_ImportSegmentKeyThreshold success" % (i + 1))

            else:
                self.output.append("SDF_dmsPCI_ImportSegmentKeyThreshold fail, ret = 0x%08x" % ret)


    def SDF_dmsPCI_KeyRecoveryThreshold(self):
        ret = gm.SDF_dmsPCI_KeyRecoveryThreshold(hSessionHandle, pucPciData, puiPciDataLen)
        if ret == 0:
            self.output.append("SDF_dmsPCI_KeyRecoveryThreshold success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsPCI_KeyRecoveryThreshold fail, ret = 0x%08x" % ret)

    def SDF_dmsCMRandomSingleDetection(self):
        ret = gm.SDF_dmsCMRandomSingleDetection(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_dmsCMRandomSingleDetection success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsCMRandomSingleDetection fail, ret = 0x%08x" % ret)

    def SDF_dmsCMRandomPowerOnSelfTest(self):
        ret = gm.SDF_dmsCMRandomPowerOnSelfTest(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_dmsCMRandomPowerOnSelfTest success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsCMRandomPowerOnSelfTest fail, ret = 0x%08x" % ret)

    def SDF_dmsCMRandomCycleDetection(self):
        ret = gm.SDF_dmsCMRandomCycleDetection(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_dmsCMRandomCycleDetection success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_dmsCMRandomCycleDetection fail, ret = 0x%08x" % ret)





    #-------------------------全功能测试--------------------------------------
    def SDF_FullFunction(self):
        ret = gm.SDF_OpenDevice(byref(hDeviceHandle))
        # 打开设备
        if ret == 0:
            self.output.append("SDF_Opendevice success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_Opendevice fail, ret = 0x%08x" % ret)

        # 打开会话
        ret = gm.SDF_OpenSession(hDeviceHandle, byref(hSessionHandle))
        if ret == 0:
            self.output.append("SDF_OpenSession success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_OpenSession fail, ret = 0x%08x" % ret)

        # 获取设备信息
        pstDeviceInfo = DEVICEINFO()
        ret = gm.SDF_GetDeviceInfo(hSessionHandle, byref(pstDeviceInfo))
        if ret == 0:
            self.output.append("SDF_GetDeviceInfo success, IssuerName = 0x%x" % ret)
        else:
            self.output.append("SDF_GetDeviceInfo fail, ret = 0x%08x" % ret)

        # 产生随机数
        uiLength = 32
        pucRandom = (c_ubyte * 32)()
        ret = gm.SDF_GenerateRandom(hSessionHandle, uiLength, pucRandom)
        if ret == 0:
            self.output.append('SDF_GenerateRandom success, ret = 0x%x' % ret)
        else:
            self.output.append("SDF_GenerateRandom fail, ret = 0x%08x" % ret)

        # 获取私钥权限
        uiKeyIndex = 1
        pucPassword = b'dms123456'
        uiPwdLength = 9
        ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex, pucPassword, uiPwdLength)
        if ret == 0:
            self.output.append("SDF_GetPrivateKeyAccessRight success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)

        # 释放私钥权限
        uiKeyIndex = 1
        ret = gm.SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiKeyIndex)
        if ret == 0:
            self.output.append("SDF_ReleasePrivateKeyAccessRight success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ReleasePrivateKeyAccessRight fail, ret = 0x%08x" % ret)

        # 导出签名公钥
        uiKeyIndex = 1
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)

        # 导出加密公钥
        uiKeyIndex = 1
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)

        # 生成ECC密钥对
        uiAlgID = SGD_SM2
        uiKeyBits = 64
        pucPublicKey = ECCrefPublicKey()
        pucPrivateKey = ECCrefPrivateKey()
        ret = gm.SDF_GenerateKeyPair_ECC(hSessionHandle, uiAlgID, uiKeyBits, byref(pucPublicKey), byref(pucPrivateKey))
        if ret == 0:
            self.output.append("SDF_GenerateKeyPair_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyPair_ECC fail, ret = 0x%08x" % ret)

        #生成会话密钥并用内部ECC 公钥加密输出
        uiIPKIndex = 1
        uiKeyBits = 64
        phKeyHandle  = c_void_p()
        ret = gm.SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiIPKIndex, uiKeyBits, byref(pucKey), byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithIPK_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithIPK_ECC fail, ret = 0x%08x" % ret)

        # 销毁会话密钥
        ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
        if ret == 0:
            self.output.append("SDF_DestroyKey success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DestroyKey fail, ret = 0x%08x" % ret)

        #生成会话密钥并用外部ECC 公钥加密输出
        uiKeyBits = 64
        uiAlgID = SGD_SM2_3
        pucPublicKey = ECCrefPublicKey()
        uiKeyIndex = 1
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail, ret = 0x%08x" % ret)
        ret = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, uiKeyBits, uiAlgID, byref(pucPublicKey), byref(pucKey),
                                            byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithEPK_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithEPK_ECC fail, ret = 0x%08x" % ret)
        # 销毁会话密钥
        ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
        if ret == 0:
            self.output.append("SDF_DestroyKey success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DestroyKey fail, ret = 0x%08x" % ret)

        #导入会话密钥并用内部 ECC 私钥解密
        uiISKIndex = 1
        ret = gm.SDF_ImportKeyWithISK_ECC(hSessionHandle, uiISKIndex, byref(pucKey), byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_ImportKeyWithISK_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ImportKeyWithISK_ECC fail, ret = 0x%08x" % ret)
        # 销毁会话密钥
        ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
        if ret == 0:
            self.output.append("SDF_DestroyKey success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DestroyKey fail, ret = 0x%08x" % ret)

        #生成密钥协商参数并输出
        uiKeyIndex = uiISKIndex = 1
        uiKeyBits = 64
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, byref(pucSponsorPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        ret = gm.SDF_GenerateAgreementDataWithECC(hSessionHandle, uiISKIndex, uiKeyBits, pucSponsorID.encode(),
                                                  uiSponsorIDLength, byref(pucSponsorPublicKey),
                                                  byref(pucSponsorTmpPublicKey), byref(phAgreementHandle))
        if ret == 0:
            self.output.append("SDF_GenerateAgreementDataWithECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateAgreementDataWithECC fail, ret = 0x%08x" % ret)

        #产生协商数据并计算会话密钥
        uiISKIndex = 1
        uiKeyBits = 64
        ret = gm.SDF_GenerateAgreementDataAndKeyWithECC(hSessionHandle, uiISKIndex, uiKeyBits,
                                                        pucResponseID.encode(),
                                                        uiResponseIDLength, pucSponsorID.encode(),
                                                        uiSponsorIDLength,
                                                        byref(pucSponsorPublicKey), byref(pucSponsorTmpPublicKey),
                                                        byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey),
                                                        byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateAgreementDataAndKeyWithECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateAgreementDataAndKeyWithECC fail, ret = 0x%08x" % ret)

        # 计算会话密钥
        ret = gm.SDF_GenerateKeyWithECC(hSessionHandle, pucResponseID.encode(), uiResponseIDLength,
                                        byref(pucResponsePublicKey), byref(pucResponseTmpPublicKey),
                                        phAgreementHandle,
                                        byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithECC fail, ret = 0x%08x" % ret)
        #销毁会话密钥
        ret = gm.SDF_DestroyKey(hSessionHandle, phKeyHandle)
        if ret == 0:
            self.output.append("SDF_DestroyKey success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DestroyKey fail, ret = 0x%08x" % ret)

        #基于ECC 算法的数字信封转换
        testPublicKey = ECCrefPublicKey()
        pucPublicKey = ECCrefPublicKey()
        pucEncDataIn = ECCCipher()
        pucEncDataOut = ECCCipher()
        phKeyHandle = c_void_p()
        uiKeyBits = 64
        uiAlgID = SGD_SM2_3
        uiKeyIndex = 1
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 2, byref(testPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success index = 2, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail index = 2, ret = 0x%08x" % ret)
        ret = gm.SDF_ExportEncPublicKey_ECC(hSessionHandle, 1, byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportEncPublicKey_ECC success index = 1, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportEncPublicKey_ECC fail index = 1, ret = 0x%08x" % ret)

        ret = gm.SDF_GenerateKeyWithEPK_ECC(hSessionHandle, uiKeyBits, uiAlgID, byref(pucPublicKey),
                                            byref(pucEncDataIn),
                                            byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithEPK_ECC success, index = 1 ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithEPK_ECC fail, index = 1 ret = 0x%08x" % ret)
        uiAlgID = SGD_SM2_3
        ret = gm.SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle, uiKeyIndex, uiAlgID, byref(testPublicKey),
                                                    byref(pucEncDataIn), byref(pucEncDataOut))
        if ret == 0:
            self.output.append("SDF_ExchangeDigitEnvelopeBaseOnECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExchangeDigitEnvelopeBaseOnECC fail, ret = 0x%08x" % ret)
        #生成会话密钥并密钥加密密钥加密输出
        uiKEKIndex = 1
        uiKeyBits = 64
        uiAlgID = SGD_SM4_ECB
        puiKeyLength = c_uint()
        ret = gm.SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, uiAlgID, uiKEKIndex, byref(pucKey),
                                        byref(puiKeyLength), byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_GenerateKeyWithKEK success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GenerateKeyWithKEK fail, ret = 0x%08x" % ret)

        #导入会话密钥并密钥加密密钥解密
        uiKEKIndex = 1
        uiAlgID = SGD_SM4_ECB
        puiKeyLength = c_uint()
        ret = gm.SDF_ImportKeyWithKEK(hSessionHandle, uiAlgID, uiKEKIndex, byref(pucKey), puiKeyLength,
                                      byref(phKeyHandle))
        if ret == 0:
            self.output.append("SDF_ImportKeyWithKEK success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ImportKeyWithKEK fail, ret = 0x%08x" % ret)

        #内部密钥 ECC 签名
        uiIndex = 1
        memset(Hash, 0x11, sizeof(Hash))
        ret = gm.SDF_GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex, pucPassword, uiPwdLength)
        if ret == 0:
            self.output.append("SDF_GetPrivateKeyAccessRight success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_GetPrivateKeyAccessRight fail, ret = 0x%08x" % ret)
        ret = gm.SDF_InternalSign_ECC(hSessionHandle, uiIndex, Hash, HashLength, byref(sign))
        if ret == 0:
            self.output.append("SDF_InternalSign_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_InternalSign_ECC fail, ret = 0x%08x" % ret)

        #内部密钥 ECC 验证
        uiIndex = 1
        ret = gm.SDF_InternalVerify_ECC(hSessionHandle, uiIndex, Hash, HashLength, byref(sign))
        if ret == 0:
            self.output.append("SDF_InternalVerify_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_InternalVerify_ECC fail, ret = 0x%08x" % ret)

        #外部密钥 ECC 验证
        uiIndex = 1
        pbBlob = ECCrefPublicKey()
        memset(Hash, 0x11, sizeof(Hash))
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, uiIndex, byref(pbBlob))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        ret = gm.SDF_ExternalVerify_ECC(hSessionHandle, SGD_SM2_1, byref(pbBlob), Hash, HashLength, byref(sign))
        if ret == 0:
            self.output.append("SDF_ExternalVerify_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExternalVerify_ECC fail, ret = 0x%08x" % ret)

        #外部密钥 ECC 公钥加密
        uiIndex = 1
        pucPublickey = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, uiIndex, byref(pucPublickey))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        uiAlgID = SGD_SM2_3
        memset(Hash, 0x11, sizeof(Hash))
        pucEncData = ECCCipher()
        ret = gm.SDF_ExternalEncrypt_ECC(hSessionHandle, uiAlgID, byref(pucPublickey), Hash, HashLength, byref(pucEncData))
        if ret == 0:
            self.output.append("SDF_ExternalVerify_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExternalVerify_ECC fail, ret = 0x%08x" % ret)

        #对称加密
        uiDataLength = 32
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        uiAlgID = SGD_SM4_ECB
        memset(pucIV, 0x00, sizeof(pucIV))
        uiEncDataLength = c_uint(uiDataLength)
        ret = gm.SDF_Encrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData,
                             byref(uiEncDataLength))
        if ret == 0:
            self.output.append("SDF_Encrypt success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_Encrypt fail, ret = 0x%08x" % ret)

        #对称解密
        uiDataLength = 32
        uiAlgID = SGD_SM4_ECB
        plain = (c_ubyte * 65536)()
        uiEncDataLength = uiDataLength
        plainLength = c_uint(uiDataLength)
        memset(pucIV, 0x00, sizeof(pucIV))
        ret = gm.SDF_Decrypt(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, plain,
                             byref(plainLength))
        if ret == 0:
            self.output.append("SDF_Decrypt success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_Decrypt fail, ret = 0x%08x" % ret)

        #MAC计算
        uiInDataLength = 32
        uiAlgID = SGD_SM4_MAC
        memset(pucIV, 0x11, sizeof(pucIV))
        pucInData = arr1024()
        pucMAC = arr4()
        uiMACLength = c_uint(4)
        ret = gm.SDF_CalculateMAC(hSessionHandle, phKeyHandle, uiAlgID, pucIV, pucInData, uiInDataLength, pucMAC,
                                  byref(uiMACLength))
        if ret == 0:
            self.output.append("SDF_CalculateMAC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CalculateMAC fail, ret = 0x%08x" % ret)

        #杂凑初始化
        uiKeyIndex = 1
        pucPublicKey = ECCrefPublicKey()
        ret = gm.SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, byref(pucPublicKey))
        if ret == 0:
            self.output.append("SDF_ExportSignPublicKey_ECC success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ExportSignPublicKey_ECC fail, ret = 0x%08x" % ret)
        AlgID = SGD_SM3
        pucID = "12345678"
        uiIDLength = 8
        ret = gm.SDF_HashInit(hSessionHandle, AlgID, pucPublicKey, pucID, uiIDLength)
        if ret == 0:
            self.output.append("SDF_HashInit success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_HashInit fail, ret = 0x%08x" % ret)

        #多包杂凑运算
        uiDataLength = 32
        for i in range(uiDataLength):
            pucData[i] = int(i % 256)
        ret = gm.SDF_HashUpdate(hSessionHandle, pucData, uiDataLength)
        if ret == 0:
            self.output.append("SDF_HashUpdate success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_HashUpdate fail, ret = 0x%08x" % ret)

        #多包杂凑结束
        pucHash = arr32()
        uiHashLength = c_uint()
        ret = gm.SDF_HashFinal(hSessionHandle, pucHash, byref(uiHashLength))
        if ret == 0:
            self.output.append("SDF_HashFinal success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_HashFinal fail, ret = 0x%08x" % ret)

        #创建文件
        pucFileName = "ahdms"
        uiNameLen = len(pucFileName)
        uiFileSize = 1024
        ret = gm.SDF_CreateFile(hSessionHandle, pucFileName.encode(), uiNameLen, int(uiFileSize))
        if ret == 0:
            self.output.append("SDF_CreateFile success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CreateFile fail, ret = 0x%08x" % ret)

        #读文件
        pucFileName = "ahdms"
        puiFileLength = 1024
        uiOffset = 0
        uiNameLen = len(pucFileName)
        pucBuffer = (c_ubyte * puiFileLength)()
        ret = gm.SDF_ReadFile(hSessionHandle, pucFileName.encode(), uiNameLen, uiOffset,
                              byref(c_uint(puiFileLength)), pucBuffer)
        if ret == 0:
            self.output.append("SDF_ReadFile success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_ReadFile fail, ret = 0x%08x" % ret)

        #写文件
        pucFileName = "ahdms"
        uiNameLen = len(pucFileName)
        uiOffset = 0
        puiFileLength = 1024
        pucBuffer = (c_ubyte * 32678)()
        for i in range(puiFileLength):
            pucBuffer[i] = int(i % 256)
        ret = gm.SDF_WriteFile(hSessionHandle, pucFileName.encode(), uiNameLen, uiOffset, puiFileLength, pucBuffer)
        if ret == 0:
            self.output.append("SDF_WriteFile success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_WriteFile fail, ret = 0x%08x" % ret)

        # 枚举文件
        szFileList = (c_byte * 1024)()
        pulSize = c_uint(1024)
        ret = gm.SDF_EnumFiles(hSessionHandle, szFileList, byref(pulSize))
        if ret == 0:
            self.output.append("SDF_EnumFiles success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_EnumFiles fail, ret = 0x%08x" % ret)

        #删除文件
        pucFileName = "ahdms"
        nameLen = len(pucFileName)
        ret = gm.SDF_DeleteFile(hSessionHandle, pucFileName.encode(), nameLen)
        if ret == 0:
            self.output.append("SDF_DeleteFile success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_DeleteFile fail, ret = 0x%08x" % ret)

        # 关闭会话
        ret = gm.SDF_CloseSession(hSessionHandle)
        if ret == 0:
            self.output.append("SDF_CloseSession success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CloseSession fail, ret = 0x%08x" % ret)

        # 关闭设备
        ret = gm.SDF_CloseDevice(hDeviceHandle)
        if ret == 0:
            self.output.append("SDF_CloseDevice success, ret = 0x%x" % ret)
        else:
            self.output.append("SDF_CloseDevice fail, ret = 0x%08x" % ret)


if __name__ == '__main__':
    gm = WinDLL('CipherMachineInterface.dll')
    app = QApplication(sys.argv)
    win = UiUkey()
    win.show()
    sys.exit(app.exec_())
