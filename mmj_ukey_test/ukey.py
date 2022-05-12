import sys
import time
from threading import Thread
from ctypes import *
# from PyQt5 import QtCore
from functools import wraps
from PyQt5.QtWidgets import QWidget, QPushButton, QApplication, QMainWindow, QLabel, QLineEdit, QTextBrowser


def async_(f):
    @wraps(f)
    def decorate(*args):
        thr = Thread(target=f, args=args)
        thr.start()

    return decorate

ECC_MAX_XCOORDINATE_BITS_LEN = 512
ECC_MAX_YCOORDINATE_BITS_LEN = 512
ECC_MAX_MODULUS_BITS_LEN = 512
MAX_IV_LEN = 32

Arr64K = c_ubyte*65536 #64k
Arr2048 = c_ubyte*2048
Arr1024 = c_ubyte*1024
ArrX = c_ubyte*(int(ECC_MAX_XCOORDINATE_BITS_LEN / 8))
ArrY = c_ubyte*(int(ECC_MAX_YCOORDINATE_BITS_LEN / 8))
ArrIV = c_ubyte*(MAX_IV_LEN)
Arr200 = c_ubyte*200
Arr180 = c_ubyte*180
Arr132 = c_ubyte*132
Arr128 = c_ubyte*128
Arr100 = c_ubyte*100
Arr65 = c_ubyte*65
Arr64 = c_ubyte*64
Arr54 = c_ubyte*54
Arr32 = c_ubyte*32
Arr16 = c_ubyte*16
Arr8 = c_ubyte*8
Arr4 = c_ubyte*4
Arr1 = c_ubyte*1
ArrPKM = c_ubyte*34000
ArrChar32 = c_char*32
ArrChar64 = c_char*64
ArrChar100 = c_char*100

class VERSION(Structure):
    _fields_ = [('major', c_ubyte),
                ('minor', c_ubyte)]

class DEVINFO(Structure):
    _fields_ = [('Version', VERSION),
                ('Manufacturer', ArrChar64),
                ('Issuer', ArrChar64),
                ('Label', ArrChar32),
                ('SerialNumber', ArrChar32),
                ('HWVersion', VERSION),
                ('FirmwareVersion', VERSION),
                ('AlgSymCap', c_ulong),
                ('AlgAsymCap', c_ulong),
                ('AlgHashCap', c_ulong),
                ('DevAuthAlgId', c_ulong),
                ('TotalSpace', c_ulong),
                ('FreeSpace', c_ulong),
                ('MaxECCBufferSize', c_ulong),
                ('MaxBufferSize', c_ulong),
                ('Reserved', Arr64)]


class ECCPUBLICKEYBLOB(Structure):
    _fields_ =[('BitLen', c_ulong ),
               ('XCoordinate', ArrX),
               ('YCoordinate', ArrY)]

class ECCCIPHERBLOB(Structure):
    _fields_ = [('XCoordinate', ArrX),
                ('YCoordinate', ArrY),
                ('HASH', Arr32),
                ('CipherLen', c_ulong),
                ('Cipher', Arr1)]

class ENVELOPEDKEYBLOB(Structure):
    _fields_ = [('Version', c_ulong ),
                ('ulSymmAlgID', c_ulong),
                ('ulBits', c_ulong),
                ('cbEncryptedPriKey', Arr64),
                ('PubKey', ECCPUBLICKEYBLOB),
                ('ECCCipherBlob', ECCCIPHERBLOB)]

class BLOCKCIPHERPARAM(Structure):
    _fields_ = [('IV', ArrIV),
                ('IVLen', c_ulong),
                ('PaddingType', c_long),
                ('FeedBitLen', c_ulong)]

class ECCSIGNATUREBLOB(Structure):
    _fields_ = [('r', ArrX),
                ('s', ArrY)]

class FILEATTRIBUTE(Structure):
    _fields_ = [('FileName', ArrChar32),
                ('FileSize', c_ulong),
                ('ReadRights', c_ulong),
                ('WriteRights', c_ulong)]

szNameList = None

szAppName = ''

phDev = c_void_p()
phApplication = c_void_p()
phContainer = c_void_p()
phSessionKey = c_void_p()

PKH = ECCPUBLICKEYBLOB()     #保护公钥
pBlob = ECCPUBLICKEYBLOB()   #签名公钥
pData = ECCCIPHERBLOB()      #会话密钥密文
pSignature = ECCSIGNATUREBLOB()   #签名值
pSignBlob = ECCPUBLICKEYBLOB()

SGD_ECB = 0x00000001
SGD_SM3 = 0x00000001
SGD_SM2_1 = 0x00020200
SGD_SM2_3 = 0x00020800
SGD_SMS4_ECB = 0x00000401    #SMS4算法ECB加密模式
SGD_SMS4_CBC = 0x00000402	 #SM4算法CBC加密模式
SGD_SMS4_CFB = 0x00000404	 #SM4算法CFB加密模式
SGD_SMS4_OFB = 0x00000408	 #SM4算法OFB加密模式

gl_Digest_hHash = c_void_p() #HASH句柄
cipherText = Arr1024()
cipherLen = c_uint()

pSessionKeyData = ECCCIPHERBLOB() #生成并导出的会话密钥
SessionKey = c_void_p()

Agreement_hostID = Arr64(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9)
Agreement_hostTempPubkey = ECCPUBLICKEYBLOB()
Agreement_slaveID = Arr64(1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9)
Agreement_slaveTempPubkey = ECCPUBLICKEYBLOB()
phAgreementHandle = c_void_p()
phAgreementHandleVPN = c_void_p()

plainTextXN = Arr64K()
cipherTextXN = Arr64K()



class UiUkey(QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        #设备管理
        btn1 = QPushButton("枚举设备", self)
        btn1.move(30, 30)
        btn2 = QPushButton("连接设备", self)
        btn2.move(30, 70)
        btn3 = QPushButton("断开设备", self)
        btn3.move(30, 110)
        btn4 = QPushButton("设置设备标签", self)
        btn4.move(30, 150)
        btn5 = QPushButton("获取设备状态", self)
        btn5.move(30, 190)
        btn6 = QPushButton("获取设备信息", self)
        btn6.move(30, 230)
        btn7 = QPushButton("锁定设备", self)
        btn7.move(30, 270)
        btn8 = QPushButton("解锁设备", self)
        btn8.move(30, 310)
        btn9 = QPushButton("等待拔插", self)
        btn9.move(30, 350)
        btn10 = QPushButton("取消等待拔插", self)
        btn10.move(30, 390)

        #访问认证管理
        btn11 = QPushButton("修改设备密钥", self)
        btn11.move(140, 30)
        btn12 = QPushButton("设备认证", self)
        btn12.move(140, 70)
        btn13 = QPushButton("校验用户PIN码", self)
        btn13.move(140, 110)
        btn14 = QPushButton("修改用户PIN码", self)
        btn14.move(140, 150)
        btn15 = QPushButton("校验管理员PIN码", self)
        btn15.move(140, 190)
        btn16 = QPushButton("修改管理员PIN码", self)
        btn16.move(140, 230)
        btn17 = QPushButton("获取PIN码信息", self)
        btn17.move(140, 270)
        btn18 = QPushButton("解锁PIN码", self)
        btn18.move(140, 310)
        btn19 = QPushButton("清除应用安全状态", self)
        btn19.move(140, 350)

        #应用管理
        btn20 = QPushButton("创建应用", self)
        btn20.move(250, 110)
        btn21 = QPushButton("枚举应用", self)
        btn21.move(250, 150)
        btn22 = QPushButton("删除应用", self)
        btn22.move(250, 190)
        btn23 = QPushButton("打开应用", self)
        btn23.move(250, 230)
        btn24 = QPushButton("关闭应用", self)
        btn24.move(250, 270)

        #文件管理
        btn25 = QPushButton("创建文件", self)
        btn25.move(360, 110)
        btn26 = QPushButton("删除文件", self)
        btn26.move(360, 150)
        btn27 = QPushButton("枚举文件", self)
        btn27.move(360, 190)
        btn28 = QPushButton("获取文件属性", self)
        btn28.move(360, 230)
        btn29 = QPushButton("读文件", self)
        btn29.move(360, 270)
        btn30 = QPushButton("写文件", self)
        btn30.move(360, 310)

        # 容器管理
        btn31 = QPushButton("创建容器", self)
        btn31.move(470, 110)
        btn32 = QPushButton("删除容器", self)
        btn32.move(470, 150)
        btn33 = QPushButton("打开容器", self)
        btn33.move(470, 190)
        btn34 = QPushButton("关闭容器", self)
        btn34.move(470, 230)
        btn35 = QPushButton("枚举容器", self)
        btn35.move(470, 270)
        btn36 = QPushButton("获取容器类型", self)
        btn36.move(470, 310)
        btn37 = QPushButton("导入数字证书", self)
        btn37.move(470, 350)
        btn38 = QPushButton("导出数字证书", self)
        btn38.move(470, 390)

        # 密钥服务
        btn39 = QPushButton("生成随机数", self)
        btn39.move(580, 110)
        btn40 = QPushButton("生成保护密钥对", self)
        btn40.move(580, 150)
        btn41 = QPushButton("生成部分签名", self)
        btn41.move(580, 190)
        btn42 = QPushButton("导入加密密钥对", self)
        btn42.move(580, 230)
        btn43 = QPushButton("ECC签名", self)
        btn43.move(580, 270)
        btn44 = QPushButton("ECC验签", self)
        btn44.move(580, 310)
        btn45 = QPushButton("导出会话密钥", self)
        btn45.move(580, 350)
        btn46 = QPushButton("导入会话密钥", self)
        btn46.move(580, 390)
        btn47 = QPushButton("导出签名公钥", self)
        btn47.move(690, 110)
        btn47.resize(130, 30)
        btn48 = QPushButton("导出加密公钥", self)
        btn48.move(690, 150)
        btn48.resize(130, 30)
        btn49 = QPushButton("导出保护公钥", self)
        btn49.move(690, 190)
        btn49.resize(130, 30)
        btn50 = QPushButton("外来公钥加密", self)
        btn50.move(690, 230)
        btn50.resize(130, 30)
        btn51 = QPushButton("发方生成协商参数", self)
        btn51.move(690, 270)
        btn51.resize(130, 30)
        btn52 = QPushButton("收方计算会话密钥", self)
        btn52.move(690, 310)
        btn52.resize(130, 30)
        btn53 = QPushButton("发方计算会话密钥", self)
        btn53.move(690, 350)
        btn53.resize(130, 30)
        btn54 = QPushButton("加密初始化", self)
        btn54.move(830, 110)
        btn55 = QPushButton("多组数据加密", self)
        btn55.move(830, 150)
        btn56 = QPushButton("结束加密", self)
        btn56.move(830, 190)
        btn57 = QPushButton("解密初始化", self)
        btn57.move(830, 230)
        btn58 = QPushButton("多组数据解密", self)
        btn58.move(830, 270)
        btn59 = QPushButton("结束解密", self)
        btn59.move(830, 310)
        btn60 = QPushButton("杂凑初始化", self)
        btn60.move(950, 510)
        btn61 = QPushButton("单组杂凑", self)
        btn61.move(950, 550)
        btn62 = QPushButton("多组杂凑", self)
        btn62.move(950, 590)
        btn63 = QPushButton("结束杂凑", self)
        btn63.move(950, 630)
        btn64 = QPushButton("MAC初始化", self)
        btn64.move(1090, 510)
        btn65 = QPushButton("单组MAC", self)
        btn65.move(1090, 550)
        btn66 = QPushButton("多组MAC", self)
        btn66.move(1090, 590)
        btn67 = QPushButton("结束MAC", self)
        btn67.move(1090, 630)

        #IKI自主接口
        btn68 = QPushButton("导入实体身份", self)
        btn68.move(950, 30)
        btn68.resize(130, 30)
        btn69 = QPushButton("导出实体身份", self)
        btn69.move(950, 70)
        btn69.resize(130, 30)
        btn70 = QPushButton("导入矩阵", self)
        btn70.move(950, 110)
        btn70.resize(130, 30)
        btn71 = QPushButton("导出矩阵", self)
        btn71.move(950, 150)
        btn71.resize(130, 30)
        btn72 = QPushButton("删除矩阵", self)
        btn72.move(950, 190)
        btn72.resize(130, 30)
        btn73 = QPushButton("标识计算公钥", self)
        btn73.move(950, 230)
        btn73.resize(130, 30)
        btn74 = QPushButton("加域计算公钥", self)
        btn74.move(950, 270)
        btn74.resize(130, 30)
        btn75 = QPushButton("IKI导出会话密钥", self)
        btn75.move(950, 310)
        btn75.resize(130, 30)
        btn76 = QPushButton("IKI导出服务端密钥", self)
        btn76.move(950, 350)
        btn76.resize(130, 30)
        btn77 = QPushButton("销毁会话密钥", self)
        btn77.move(950, 390)
        btn77.resize(130, 30)
        btn78 = QPushButton("导入RPK", self)
        btn78.move(950, 430)
        btn78.resize(130, 30)
        btn79 = QPushButton("导出RPK", self)
        btn79.move(1090, 30)
        btn79.resize(130, 30)
        btn80 = QPushButton("随机数检测", self)
        btn80.move(1090, 70)
        btn80.resize(130, 30)
        btn81 = QPushButton("随机数单次检测", self)
        btn81.move(1090, 110)
        btn81.resize(130, 30)
        btn82 = QPushButton("快速Hash初始化", self)
        btn82.move(1090, 150)
        btn82.resize(130, 30)
        btn83 = QPushButton("多组快速Hash", self)
        btn83.move(1090, 190)
        btn83.resize(130, 30)
        btn84 = QPushButton("结束多组快速Hash", self)
        btn84.move(1090, 230)
        btn84.resize(130, 30)
        btn85 = QPushButton("VPN发方生成协商参数", self)
        btn85.move(1090, 270)
        btn85.resize(130, 30)
        btn86 = QPushButton("VPN收方计算会话秘钥", self)
        btn86.move(1090, 310)
        btn86.resize(130, 30)
        btn87 = QPushButton("VPN发方计算会话秘钥", self)
        btn87.move(1090, 350)
        btn87.resize(130, 30)
        btn88 = QPushButton("SM2签名", self)
        btn88.move(1090, 390)
        btn88.resize(130, 30)
        btn89 = QPushButton("SM2验签", self)
        btn89.move(1090, 430)
        btn89.resize(130, 30)

        #清空输出日志
        btn90 = QPushButton("清空输出日志", self)
        btn90.move(315, 630)

        #性能测试
        btn91 = QPushButton("生成密钥对", self)
        btn91.move(470, 460)
        btn92 = QPushButton("SM2签名", self)
        btn92.move(470, 500)
        btn93 = QPushButton("SM2验签", self)
        btn93.move(470, 540)
        btn94 = QPushButton("SM2加密", self)
        btn94.move(470, 580)
        btn95 = QPushButton("SM2解密", self)
        btn95.move(470, 620)
        btn96 = QPushButton("SM3杂凑", self)
        btn96.move(580, 460)
        btn97 = QPushButton("SM4加密", self)
        btn97.move(580, 500)
        btn98 = QPushButton("SM4解密", self)
        btn98.move(580, 540)
        btn99 = QPushButton("写文件", self)
        btn99.move(580, 580)
        btn100 = QPushButton("读文件", self)
        btn100.move(580, 620)

        inLabel = QLabel(self)
        inLabel.setText("应用/容器/PIN:")
        inLabel.move(250, 30)
        inLabe2 = QLabel(self)
        inLabe2.setText("New PIN:")
        inLabe2.move(250, 70)
        inLabe3 = QLabel(self)
        inLabe3.setText("UserType/Cert:")
        inLabe3.move(580, 30)
        inLabe4 = QLabel(self)
        inLabe4.setText("Random/KeyBits:")
        inLabe4.move(580, 70)
        self.input1 = QLineEdit(self)
        self.input1.setGeometry(340, 30, 230, 30)
        self.input2 = QLineEdit(self)
        self.input2.setGeometry(340, 70, 230, 30)
        self.input3 = QLineEdit(self)
        self.input3.setGeometry(690, 30, 240, 30)
        self.input4 = QLineEdit(self)
        self.input4.setGeometry(690, 70, 240, 30)
        outLabel = QLabel(self)
        outLabel.setText("输出:")
        outLabel.move(30, 430)
        self.output = QTextBrowser(self)
        self.output.setGeometry(30, 460, 385, 160)

        outLabel2 = QLabel(self)
        outLabel2.setText("性能测试:")
        outLabel2.move(470, 430)


        #设备管理
        btn1.clicked.connect(self.SKF_EnumDev)
        btn2.clicked.connect(self.SKF_ConnectDev)
        btn3.clicked.connect(self.SKF_DisConnectDev)
        btn4.clicked.connect(self.SKF_SetLabel)
        btn5.clicked.connect(self.SKF_GetDevState)
        btn6.clicked.connect(self.SKF_GetDevInfo)
        btn7.clicked.connect(self.SKF_LockDev)
        btn8.clicked.connect(self.SKF_UnlockDev)
        btn9.clicked.connect(self.SKF_WaitForDevEvent)
        btn10.clicked.connect(self.SKF_CancelWaitForDevEvent)
        #访问控制
        btn11.clicked.connect(self.SKF_ChangeDevAuthKey)
        btn12.clicked.connect(self.SKF_DevAuth)
        btn13.clicked.connect(self.SKF_VerifyUserPIN)
        btn14.clicked.connect(self.SKF_ChangeUserPIN)
        btn15.clicked.connect(self.SKF_VerifyAdminPIN)
        btn16.clicked.connect(self.SKF_ChangeAdminPIN)
        btn17.clicked.connect(self.SKF_GetPINInfo)
        btn18.clicked.connect(self.SKF_UnblockPIN)
        btn19.clicked.connect(self.SKF_ClearSecureState)
        #应用管理
        btn20.clicked.connect(self.SKF_CreateApplication)
        btn21.clicked.connect(self.SKF_EnumApplication)
        btn22.clicked.connect(self.SKF_DeleteApplication)
        btn23.clicked.connect(self.SKF_OpenApplication)
        btn24.clicked.connect(self.SKF_CloseApplication)
        #文件管理
        btn25.clicked.connect(self.SKF_CreateFile)
        btn26.clicked.connect(self.SKF_DeleteFile)
        btn27.clicked.connect(self.SKF_EnumFiles)
        btn28.clicked.connect(self.SKF_GetFileInfo)
        btn29.clicked.connect(self.SKF_ReadFile)
        btn30.clicked.connect(self.SKF_WriteFile)
        #容器管理
        btn31.clicked.connect(self.SKF_CreateContainer)
        btn32.clicked.connect(self.SKF_DeleteContainer)
        btn33.clicked.connect(self.SKF_OpenContainer)
        btn34.clicked.connect(self.SKF_CloseContainer)
        btn35.clicked.connect(self.SKF_EnumContainer)
        btn36.clicked.connect(self.SKF_GetContainerType)
        btn37.clicked.connect(self.SKF_ImportCertificate)
        btn38.clicked.connect(self.SKF_ExportCertificate)
        #密钥服务
        btn39.clicked.connect(self.SKF_GenRandom)
        btn40.clicked.connect(self.SKF_GenECCKeyPairH)
        btn41.clicked.connect(self.SKF_GenECCKeyPair)
        btn42.clicked.connect(self.SKF_ImportECCKeyPair)
        btn43.clicked.connect(self.SKF_ECCSignData)
        btn44.clicked.connect(self.SKF_ECCVerify)
        btn45.clicked.connect(self.SKF_ECCExportSessionKey)
        btn46.clicked.connect(self.SKF_ImportSessionKey)
        btn47.clicked.connect(self.SKF_ExportSignPublicKey)
        btn48.clicked.connect(self.SKF_ExportEncrypPublicKey)
        btn49.clicked.connect(self.SKF_ExportPublicKeyH)
        btn50.clicked.connect(self.SKF_ExtECCEncrypt)
        btn51.clicked.connect(self.SKF_GenerateAgreementDataWithECC)
        btn52.clicked.connect(self.SKF_GenerateAgreementDataAndKeyWithECC)
        btn53.clicked.connect(self.SKF_GenerateKeyWithECC)
        btn54.clicked.connect(self.SKF_EncryptInit)
        btn55.clicked.connect(self.SKF_EncryptUpdate)
        btn56.clicked.connect(self.SKF_EncryptFinal)
        btn57.clicked.connect(self.SKF_DecryptInit)
        btn58.clicked.connect(self.SKF_DecryptUpdate)
        btn59.clicked.connect(self.SKF_DecryptFinal)
        btn60.clicked.connect(self.SKF_DigestInit)
        btn61.clicked.connect(self.SKF_Digest)
        btn62.clicked.connect(self.SKF_DigestUpdate)
        btn63.clicked.connect(self.SKF_DigestFinal)
        btn64.clicked.connect(self.SKF_MacInit)
        btn65.clicked.connect(self.SKF_Mac)
        btn66.clicked.connect(self.SKF_MacUpdate)
        btn67.clicked.connect(self.SKF_MacFinal)
        # IKI自主服务接口
        btn68.clicked.connect(self.SKF_ImportIdentify)
        btn69.clicked.connect(self.SKF_ExportIdentify)
        btn70.clicked.connect(self.SKF_ImportPubMatrix)
        btn71.clicked.connect(self.SKF_ExportPubMatrix)
        btn72.clicked.connect(self.SKF_DeletePubMatrix)
        btn73.clicked.connect(self.SKF_CalculatePubKey)
        btn74.clicked.connect(self.SKF_CalculatePubKeyAddField)
        btn75.clicked.connect(self.SKF_ECCExportSessionKeyEx)
        btn76.clicked.connect(self.SKF_GenerateKDFSessionKey)
        btn77.clicked.connect(self.SKF_DestroySessionKey)
        btn78.clicked.connect(self.SKF_ImportPublicKeyRPK)
        btn79.clicked.connect(self.SKF_ExportPublicKeyRPK)
        btn80.clicked.connect(self.SKF_UkeyRandomTest)
        btn81.clicked.connect(self.SKF_RandomSingleTest)
        btn82.clicked.connect(self.SKF_HashInitFast)
        btn83.clicked.connect(self.SKF_HashUpdateFast)
        btn84.clicked.connect(self.SKF_HashFinalFast)
        btn85.clicked.connect(self.SKF_GenerateAgreementDataWithECC_VPN)
        btn86.clicked.connect(self.SKF_GenAgreementDataAndKeyWithECC_VPN)
        btn87.clicked.connect(self.SKF_GenerateKeyWithECC_VPN)
        btn88.clicked.connect(self.dmsUK_Hsign)
        btn89.clicked.connect(self.dmsUK_HEccVerify)
        btn90.clicked.connect(self.clearLog)
        #性能测试
        btn91.clicked.connect(self.SKF_GenECCKeyPair_XN)
        btn92.clicked.connect(self.SKF_ECCSignData_XN)
        btn93.clicked.connect(self.SKF_ECCVerify_XN)
        btn94.clicked.connect(self.SKF_ExtECCEncrypt_XN)
        btn95.clicked.connect(self.SKF_ImportSessionKey_XN)
        btn96.clicked.connect(self.SKF_Hash_XN)
        btn97.clicked.connect(self.SKF_Encrypt_XN)
        btn98.clicked.connect(self.SKF_Decrypt_XN)
        btn99.clicked.connect(self.write_file_XN)
        btn100.clicked.connect(self.read_file_XN)

        self.setGeometry(300, 150, 1246, 678)
        self.setWindowTitle('UKey Test')
        self.show()

    def clearLog(self):
        self.output.document().clear()

    #设备管理-------------------------------------------------------------------------
    def SKF_EnumDev(self):
        global szNameList
        bPresent = c_bool(True)
        pulSize = pointer(c_uint())
        szNameList = create_string_buffer(32)
        ret = gm.SKF_EnumDev(bPresent, szNameList, pulSize)
        if 0 == ret and szNameList.value != b'':
            self.output.append("枚举设备成功，ret=" + hex(ret))
            self.input1.setText(szNameList.value.decode())
        else:
            self.output.append("枚举设备失败")


    def SKF_ConnectDev(self):
        if not szNameList:
            return self.output.append("请先枚举设备成功")
        szName = szNameList
        ret = gm.SKF_ConnectDev(szName, byref(phDev))
        if 0 == ret:
            self.output.append("连接设备成功，ret=" + hex(ret))
        else:
            self.output.append("连接设备失败，ret=" + hex(ret))

    def SKF_DisConnectDev(self):
        ret = gm.SKF_DisConnectDev(phDev)
        if 0 == ret:
            self.output.append("断开设备成功，ret=" + hex(ret))
        else:
            self.output.append("断开设备失败，ret=" + hex(ret))

    def SKF_GetDevState(self):
        # ULONG DEVAPISKF_GetDevState(LPSTR szDevName, ULONG * pulDevState);
        szDevName = szNameList.value
        pulDevState = c_ulong()
        ret = gm.SKF_GetDevState(szDevName, byref(pulDevState))
        if 0 == ret:
            self.output.append("获取设备状态成功，ret=" + hex(ret))
            if  pulDevState.value == 0x01:
                self.output.append("设备已存在")
            elif pulDevState.value == 0x0:
                self.output.append("设备已断开")
            else:
                self.output.append("设备状态位置")
        else:
            self.output.append("获取设备状态失败，ret=" + hex(ret))

    def SKF_SetLabel(self):
        szLabel = self.input1.text()
        ret = gm.SKF_SetLabel(phDev, szLabel.encode())
        if 0 == ret:
            self.output.append("设置设备标签成功，ret=" + hex(ret))
        else:
            self.output.append("设置设备标签失败，ret=" + hex(ret))


    def SKF_GetDevInfo(self):
        devInfo = DEVINFO()
        ret = gm.SKF_GetDevInfo(phDev, byref(devInfo))
        if 0 == ret:
            self.output.append("获取设备信息成功，ret=" + hex(ret))
            self.output.append("设备厂商信息: %s" %devInfo.Manufacturer.decode())
            self.output.append("应用发行者信恿: %s" %devInfo.Issuer.decode())
            self.output.append("设备标签: %s" %devInfo.Label.decode())
            self.output.append("序列号: %s" % devInfo.SerialNumber)
            self.output.append("设备硬件版本: %02x%02x" %(devInfo.HWVersion.major, devInfo.HWVersion.minor))
            self.output.append("设备本身固件版本: %02x%02x" %(devInfo.FirmwareVersion.major, devInfo.FirmwareVersion.minor))
            self.output.append("分组密码算法标识: 0x%08x" %devInfo.AlgSymCap)
            self.output.append("非对称密码算法标识: 0x%08x" %devInfo.AlgAsymCap)
            self.output.append("密码杂凑算法标识: 0x%08x"  %devInfo.AlgHashCap)
            self.output.append("设备认证使用的分组算法标识: 0x%08x" %devInfo.DevAuthAlgId)
            self.output.append("设备总空间大小: 0x%08x" %devInfo.TotalSpace)
            self.output.append("用户可用空间大小: 0x%08x" %devInfo.FreeSpace)
            self.output.append("MaxECCBufferSize: 0x%08x" %devInfo.MaxECCBufferSize)
            self.output.append("MaxBufferSize: 0x%08x" %devInfo.MaxBufferSize)
            # self.output.append("Reserved: 0x%08x" % devInfo.Reserved)
        else:
            self.output.append("获取设备信息失败，ret=" + hex(ret))

    def SKF_LockDev(self):
        ulTimeOut = c_ulong(0x0000EA60)
        ret = gm.SKF_LockDev(phDev, ulTimeOut)
        if 0 == ret:
            self.output.append("锁定设备成功，ret=" + hex(ret))
        else:
            self.output.append("锁定设备失败，ret=" + hex(ret))

    def SKF_UnlockDev(self):
        ret = gm.SKF_UnlockDev(phDev)
        if 0 == ret:
            self.output.append("解锁设备成功，ret=" + hex(ret))
        else:
            self.output.append("解锁设备失败，ret=" + hex(ret))

    def SKF_WaitForDevEvent(self):
        pulDevNameLen = c_ulong()
        pulEvent = c_ulong()
        szDevName = ArrChar100()
        ret = gm.SKF_WaitForDevEvent(szDevName, byref(pulDevNameLen), byref(pulEvent))
        if 0 == ret:
            self.output.append("等待设备拔插成功，ret=" + hex(ret))
            if pulEvent.value == 1:
                self.output.append("设备已插入，ret=" + hex(pulEvent.value))
            else:
                self.output.append("设备已拔出，ret=" + hex(pulEvent.value))
        else:
            self.output.append("等待设备拔插失败，ret=" + hex(ret))
            return 1


    def SKF_CancelWaitForDevEvent(self):
        ret = gm.SKF_CancelWaitForDevEvent()
        if 0 == ret:
            self.output.append("取消等待设备拔插成功，ret=" + hex(ret))
        else:
            self.output.append("取消等待设备拔插失败，ret=" + hex(ret))

    #访问控制--------------------------------------------------------------------------
    def SKF_ChangeDevAuthKey(self):
        pbKeyValue = self.input1.text()
        ulKeyLen = len(pbKeyValue.encode())
        ret = gm.SKF_ChangeDevAuthKey(phDev, pbKeyValue.encode(), ulKeyLen)
        if ret == 0:
            self.output.append("修改设备认证PIN码成功，ret=" + hex(ret))
        else:
            self.output.append("修改设备认证PIN码失败，ret=" + hex(ret))

    def SKF_DevAuth(self):
        pbAuthData = self.input1.text()
        ulLen = len(pbAuthData)
        ret = gm.SKF_DevAuth(phDev, pbAuthData.encode(), ulLen)
        if 0 == ret:
            self.output.append("设备认证成功，ret=" + hex(ret))
        else:
            self.output.append("设备认证失败，ret=" + hex(ret))

    def SKF_VerifyUserPIN(self):
        pulRetryCount = pointer(c_uint())
        usrPIN = self.input1.text()
        USER_TYPE = 1
        ret = gm.SKF_VerifyPIN(phApplication, USER_TYPE, usrPIN.encode(), pulRetryCount)
        if 0 == ret:
            self.output.append("校验用户PIN码成功，ret=" + hex(ret))
        else:
            self.output.append("校验用户PIN码失败，ret=" + hex(ret))

    def SKF_VerifyAdminPIN(self):
        pulRetryCount = pointer(c_uint())
        usrPIN = self.input1.text()
        USER_TYPE = 0
        ret = gm.SKF_VerifyPIN(phApplication, USER_TYPE, usrPIN.encode(), pulRetryCount)
        if 0 == ret:
            self.output.append("校验管理员PIN码成功，ret=" + hex(ret))
        else:
            self.output.append("校验管理员PIN码失败，ret=" + hex(ret))

    def SKF_ChangeUserPIN(self):
        #SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount)
        ulPINType = 1
        szOldPin = self.input1.text()
        szNewPin = self.input2.text()
        pulRetryCount = c_uint()
        ret = gm.SKF_ChangePIN(phApplication, ulPINType, szOldPin.encode(), szNewPin.encode(), byref(pulRetryCount))
        if ret == 0:
            self.output.append("修改用户PIN码成功，ret=" + hex(ret))
        else:
            self.output.append("修改用户PIN码失败，ret=" + hex(ret))

    def SKF_ChangeAdminPIN(self):
        #SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount)
        ulPINType = 0
        szOldPin = self.input1.text()
        szNewPin = self.input2.text()
        pulRetryCount = c_uint()
        ret = gm.SKF_ChangePIN(phApplication, ulPINType, szOldPin.encode(), szNewPin.encode(), byref(pulRetryCount))
        if ret == 0:
            self.output.append("修改管理员PIN码成功，ret=" + hex(ret))
        else:
            self.output.append("修改管理员PIN码失败，ret=" + hex(ret))

    def SKF_GetPINInfo(self):
        ulPINType = self.input3.text()
        if ulPINType == '':
            self.output.append("请输入正确的UserType:1 or 0 ")
            return 0
        elif int(ulPINType) !=0 and int(ulPINType) !=1:
            self.output.append("请输入正确的UserType:1 or 0 ")
            return 0
        pulMaxRetryCount = c_ulong()
        pulRemainRetryCount = c_ulong()
        pbDefaultPin = c_bool()
        ret = gm.SKF_GetPINInfo(phApplication, int(ulPINType), byref(pulMaxRetryCount), byref(pulRemainRetryCount), byref(pbDefaultPin))
        if ret == 0:
            if int(ulPINType) == 0:
                self.output.append("获取Admin PIN信息成功")
                self.output.append("最大重试次数：%d" %pulMaxRetryCount.value)
                self.output.append("剩余重试次数：%d" %pulRemainRetryCount.value)
                self.output.append("PIN码状态:%d" %pbDefaultPin.value)
            elif int(ulPINType) == 1:
                self.output.append("获取User PIN信息成功")
                self.output.append("最大重试次数：%d" % pulMaxRetryCount.value)
                self.output.append("剩余重试次数：%d" % pulRemainRetryCount.value)
                self.output.append("PIN码状态:%d" % pbDefaultPin.value)
        else:
            self.output.append("获取PIN码信息失败，ret=" + hex(ret))

    def SKF_UnblockPIN(self):
        szAdminPIN = self.input1.text()
        szNewUserPIN = self.input2.text()
        pulRetryCount = c_uint()
        ret = gm.SKF_UnblockPIN(phApplication, szAdminPIN.encode(), szNewUserPIN.encode(),byref(pulRetryCount))
        if ret == 0:
            self.output.append("解锁用户PIN码成功，ret=" + hex(ret))
        else:
            self.output.append("解锁用户PIN码失败，ret=" + hex(ret))

    def SKF_ClearSecureState(self):
        ret = gm.SKF_ClearSecureState(phApplication)
        if ret == 0:
            self.output.append("清除安全状态成功，ret=" + hex(ret))
        else:
            self.output.append("清除安全状态失败，ret=" + hex(ret))

    #应用灌流-------------------------------------------------------------------------
    def SKF_CreateApplication(self):
        gm.SKF_CreateApplication.argtypes = (c_void_p, c_char_p, c_char_p, c_uint, c_char_p, c_uint, c_uint, POINTER(c_void_p))
        szAppName = self.input1.text()
        ret = gm.SKF_CreateApplication(phDev, szAppName.encode(), b'12345678', 10, b'12345678', 10, 1, phApplication)
        if 0 == ret:
            self.output.append("创建应用成功，ret=" + hex(ret))
        else:
            self.output.append("创建应用失败，ret=" + hex(ret))

    def SKF_EnumApplication(self):
        #SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName, ULONG * pulSize);
        szAppName = create_string_buffer(32)
        pulSize = pointer(c_ulong())
        ret = gm.SKF_EnumApplication(phDev, szAppName, pulSize)
        if 0 == ret:
            self.output.append("枚举应用成功，ret=" + repr(szAppName.raw.decode()))
        else:
            self.output.append("枚举应用失败，ret=" + hex(ret))

    def SKF_DeleteApplication(self):
        # SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName)
        szAppName = self.input1.text()
        ret = gm.SKF_DeleteApplication(phDev, szAppName.encode())
        if 0 == ret:
            self.output.append("删除应用成功，ret=" + hex(ret))
        else:
            self.output.append("删除应用失败，ret=" + hex(ret))

    def SKF_OpenApplication(self):
        szAppName = self.input1.text()
        if szAppName == '':
            self.output.append("请在文本框输入应用名称：")
            return 0
        ret = gm.SKF_OpenApplication(phDev, szAppName.encode(), byref(phApplication))
        if 0 == ret:
            self.output.append("打开应用成功，ret="+hex(ret))
        else:
            self.output.append("打开应用失败，ret="+hex(ret))

    def SKF_CloseApplication(self):
        ret = gm.SKF_CloseApplication(phApplication)
        if 0 == ret:
            self.output.append("关闭应用成功，ret=" + hex(ret))
        else:
            self.output.append("关闭应用失败，ret=" + hex(ret))

    #文件管理---------------------------------------------------------------------
    def SKF_CreateFile(self):
        SECURE_USER_ACCOUNT = 0x00000010 #用户
        SECURE_ADM_ACCOUNT = 0x00000001  # 管理员
        ulFileSize =  c_uint()
        szFileName = self.input1.text()
        ret = gm.SKF_CreateFile(phApplication, szFileName.encode(), 20480, SECURE_USER_ACCOUNT, SECURE_ADM_ACCOUNT)
        if ret == 0:
            self.output.append("创建文件成功，ret=" + hex(ret))
        else:
            self.output.append("创建文件失败，ret=" + hex(ret))

    def SKF_DeleteFile(self):
        szFileName = self.input1.text()
        ret = gm.SKF_DeleteFile(phApplication, szFileName.encode())
        if ret == 0:
            self.output.append("删除文件成功，ret=" + hex(ret))
        else:
            self.output.append("删除文件失败，ret=" + hex(ret))

    def SKF_EnumFiles(self):
        FileList = create_string_buffer(100)
        pulSize = c_uint()
        ret =  gm.SKF_EnumFiles(phApplication, FileList, byref(pulSize))
        if ret == 0:
            self.output.append("枚举文件成功，ret=" + repr(FileList.raw.decode()))
        else:
            self.output.append("枚举文件失败，ret=" + hex(ret))

    def SKF_GetFileInfo(self):
        szFileName = self.input1.text()
        pFileInfo = FILEATTRIBUTE()
        ret = gm.SKF_GetFileInfo(phApplication, szFileName.encode(), byref(pFileInfo))
        if ret == 0:
            self.output.append("获取文件信息成功，ret=" + hex(ret))
        else:
            self.output.append("获取文件信息失败，ret=" + hex(ret))

    def SKF_ReadFile(self):
        pbOutData = Arr2048()
        pulOutLen = c_uint()
        szFileName = self.input1.text()
        ret = gm.SKF_ReadFile(phApplication, szFileName.encode(), 0 , 128, pbOutData, byref(pulOutLen))
        if ret == 0:
            self.output.append("读文件成功，ret=" + hex(ret))
            for i in range(128):
                print(pbOutData[i], end=' ')
        else:
            self.output.append("读文件失败，ret=" + hex(ret))

    def SKF_WriteFile(self):
        Indata = Arr128(0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF)
        szFileName = self.input1.text()
        ret = gm.SKF_WriteFile(phApplication, szFileName.encode(), 1024, Indata, 128)
        if ret == 0:
            self.output.append("写文件成功，ret=" + hex(ret))
        else:
            self.output.append("写文件失败，ret=" + hex(ret))

    #容器管理---------------------------------------------------------------------
    def SKF_CreateContainer(self):
        # SKF_CreateContainer(HAPPLICATION hApplication,LPSTR szContainerName, HCONTAINER *phContainer)
        gm.SKF_CreateContainer.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
        szContainerName = self.input1.text()
        ret = gm.SKF_CreateContainer(phApplication, szContainerName.encode(), phContainer)
        if 0 == ret:
            self.output.append("创建容器成功，ret=" + hex(ret))
        else:
            self.output.append("创建容器失败，ret=" + hex(ret))

    def SKF_DeleteContainer(self):
        #SKF_DeleteContainer(HAPPLICATION hApplication,LPSTR szContainerName)
        szContainerName = self.input1.text()
        ret = gm.SKF_DeleteContainer(phApplication, szContainerName.encode())
        if 0 == ret:
            self.output.append("删除容器成功，ret=" + hex(ret))
        else:
            self.output.append("删除容器失败，ret=" + hex(ret))

    def SKF_OpenContainer(self):
        gm.SKF_OpenContainer.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
        szContainerName = self.input1.text()
        ret = gm.SKF_OpenContainer(phApplication, szContainerName.encode(), phContainer)
        if 0 == ret:
            self.output.append("打开容器成功，ret=" + hex(ret))
        else:
            self.output.append("打开容器失败，ret=" + hex(ret))

    def SKF_CloseContainer(self):
        ret = gm.SKF_CloseContainer(phContainer)
        if 0 == ret:
            self.output.append("关闭容器成功，ret=" + hex(ret))
        else:
            self.output.append("关闭容器失败，ret=" + hex(ret))

    def SKF_GetContainerType(self):
        pulContainerType = c_ulong()
        szContainerName = self.input1.text()
        ret = gm.SKF_GetContainerType(phApplication, szContainerName.encode(), byref(pulContainerType))
        if 0 == ret:
            self.output.append("获取容器类型成功，ret=" + hex(ret))
            if pulContainerType.value ==2:
                self.output.append("容器类型为ECC容器:2" )
            elif pulContainerType.value ==1:
                self.output.append("容器类型为RSA容器:1")
            elif pulContainerType.value ==0:
                self.output.append("未定、尚未分配类型或者为空容器未定:0")
        else:
            self.output.append("获取容器类型失败，ret=" + hex(ret))

    def SKF_EnumContainer(self):
        szContainerName = create_string_buffer(32)
        pulSize = pointer(c_uint())
        ret = gm.SKF_EnumContainer(phApplication, szContainerName, pulSize)
        if 0 == ret:
            self.output.append("枚举容器成功，ret=" + hex(ret)+ repr(szContainerName.raw.decode()))
        else:
            self.output.append("枚举容器失败，ret=" + hex(ret))

    def SKF_ImportCertificate(self):
        pbCert = Arr2048()
        with open('F:\\aidraserver.cer', 'rb+') as f:
            str = f.read()
        arr = list(str)
        for i in range(len(arr)):
            pbCert[i] = arr[i]
        bSignFlag = self.input3.text()
        if bSignFlag == '':
            self.output.append("请导入数字证书类型：1位签名证书，0为加密证书")
            return 0
        ulCertLen = len(arr)
        ret = gm.SKF_ImportCertificate(phContainer, int(bSignFlag), byref(pbCert), ulCertLen)
        if ret == 0 and int(bSignFlag) == 1:
            self.output.append("导入签名证书成功，ret=" + hex(ret))
        elif ret == 0 and int(bSignFlag) == 0:
            self.output.append("导入加密证书成功，ret=" + hex(ret))
        else:
            self.output.append("导入数字证书失败，ret=0x%x" %ret)

    def SKF_ExportCertificate(self):
        #SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE *pbCert, ULONG *pulCertLen)
        pbCert = Arr2048()
        pulCertLen = c_uint()
        bSignFlag = self.input3.text()
        if bSignFlag == '':
            self.output.append("请导出数字证书类型：1位签名证书，0为加密证书")
            return 0
        ret = gm.SKF_ExportCertificate(phContainer, int(bSignFlag), byref(pbCert), byref(pulCertLen))
        if ret == 0 and int(bSignFlag) == 1:
            self.output.append("导出签名证书成功，ret=" + hex(ret))
        elif ret == 0 and int(bSignFlag) == 0:
            self.output.append("导出加密证书成功，ret=" + hex(ret))
        else:
            self.output.append("导出数字证书失败，ret=0x%x" % ret)
        with open('F:\\2222.cer', 'wb+') as f:
            f.write(pbCert)

    #密钥服务-------------------------------------------------------------------
    def SKF_GenRandom(self):
        pbRandom = (c_ubyte * 2048)()
        ulRandomLen = int(self.input4.text())
        ret = gm.SKF_GenRandom(phDev, pbRandom, ulRandomLen)
        if 0 == ret:
            self.output.append("生成随机数成功，ret=" + hex(ret))
            seq = []
            for i in range(ulRandomLen):
                seq.append(hex(pbRandom[i]))
            self.output.append("随机数：\n%s" % seq)
        else:
            self.output.append("生成随机数失败，ret=" + hex(ret))

    def SKF_GenECCKeyPairH(self):
        ret = gm.SKF_GenECCKeyPairH(phContainer, SGD_SM2_3, byref(PKH))
        if 0 == ret:
            self.output.append("生成临时密钥对成功，ret=" + hex(ret))
        else:
            self.output.append("生成临时密钥对失败，ret=" + hex(ret))

    def SKF_GenECCKeyPair(self):
        ret = gm.SKF_GenECCKeyPair(phContainer, SGD_SM2_1, byref(pBlob))
        if 0 == ret:
            self.output.append("生成签名密钥对成功，ret=" + hex(ret))
        else:
            self.output.append("生成签名密钥对失败，ret=" + hex(ret))

    #old*****************加密模式**************************************
    # def SKF_ImportECCKeyPair(self):
    #     #********生成并导出会话密钥***************保护公钥对会话密钥加密（随机数），输出密文数据结构以及会话密钥句柄
    #     ret = gm.SKF_ECCExportSessionKey(phContainer, SGD_SMS4_ECB, byref(PKH), byref(pData), byref(SessionKey))
    #     if ret == 0:
    #         self.output.append("生成并导出会话秘钥成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("生成并导出会话秘钥失败，ret=" + hex(ret))
    #     #**********加密初始化**********************
    #     EncryptParam = BLOCKCIPHERPARAM()
    #     EncryptParam.IVLen = 16
    #     memset(EncryptParam.IV, 0x11, 16)
    #     EncryptParam.PaddingType = SGD_ECB
    #     ret = gm.SKF_EncryptInit(SessionKey, EncryptParam)
    #     if ret == 0:
    #         self.output.append("加密初始化成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("加密初始化失败，ret=" + hex(ret))
    #     #***********多组数据加密**********************
    #     X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
    #               0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
    #               0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
    #               0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)
    #
    #     Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
    #               0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
    #     plainText = Arr1024()
    #     plainTextLen = 32
    #     cipherText = Arr1024()
    #     cipherLen = c_uint()
    #     memmove(plainText, Y, 32)
    #     # gm.SKF_EncryptUpdate.argtypes = [c_void_p,  POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
    #     ret = gm.SKF_EncryptUpdate(SessionKey, plainText, plainTextLen, cipherText, byref(cipherLen))
    #     if ret == 0:
    #         self.output.append("多组数据加密成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("多组数据加密失败，ret=" + hex(ret))
    #
    #     #************结束加密********************
    #     ret = gm.SKF_EncryptFinal(SessionKey, cipherText, byref(cipherLen))
    #     if ret == 0:
    #         self.output.append("结束加密成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("结束加密失败，ret=" + hex(ret))
    #
    #     #*********销毁会话密钥*********************
    #     ret = gm.SKF_DestroySessionKey(SessionKey)
    #     if ret == 0:
    #         self.output.append("销毁会话密钥成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("销毁会话密钥失败，ret=" + hex(ret))
    #
    #     #*************数据复制************************
    #     pEnvelopedKeyBlob = ENVELOPEDKEYBLOB()
    #     pEnvelopedKeyBlob.ulSymmAlgID = SGD_SMS4_ECB
    #     memmove(pEnvelopedKeyBlob.cbEncryptedPriKey, cipherText, 32)
    #     pEnvelopedKeyBlob.PubKey.BitLen = 32*8
    #     memmove(pEnvelopedKeyBlob.PubKey.XCoordinate, X, 32)
    #     memmove(pEnvelopedKeyBlob.PubKey.YCoordinate, byref(X, 32), 32)
    #
    #     pEnvelopedKeyBlob.ECCCipherBlob.CipherLen = pData.CipherLen
    #     memmove(pEnvelopedKeyBlob.ECCCipherBlob.Cipher, pData.Cipher, pData.CipherLen)
    #     memmove(pEnvelopedKeyBlob.ECCCipherBlob.XCoordinate, pData.XCoordinate, 32)
    #     memmove(pEnvelopedKeyBlob.ECCCipherBlob.YCoordinate, pData.YCoordinate, 32)
    #     memmove(pEnvelopedKeyBlob.ECCCipherBlob.HASH, pData.HASH, 64)
    #
    #     ret = gm.SKF_ImportECCKeyPair(phContainer, byref(pEnvelopedKeyBlob))
    #     if ret == 0:
    #         self.output.append("导入加密密钥对成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("导入加密密钥对失败，ret=" + hex(ret))


    def SKF_ImportECCKeyPair(self):
        #********生成并导出会话密钥***************保护公钥对会话密钥加密（随机数），输出密文数据结构以及会话密钥句柄
        ret = gm.SKF_ECCExportSessionKey(phContainer, SGD_SMS4_ECB, byref(PKH), byref(pData), byref(SessionKey))
        if ret == 0:
            self.output.append("生成并导出会话秘钥成功，ret=" + hex(ret))
        else:
            self.output.append("生成并导出会话秘钥失败，ret=" + hex(ret))
        #**********加密初始化**********************
        EncryptParam = BLOCKCIPHERPARAM()
        EncryptParam.IVLen = 16
        memset(EncryptParam.IV, 0x11, 16)
        EncryptParam.PaddingType = SGD_ECB
        ret = gm.SKF_EncryptInit(SessionKey, EncryptParam)
        if ret == 0:
            self.output.append("加密初始化成功，ret=" + hex(ret))
        else:
            self.output.append("加密初始化失败，ret=" + hex(ret))
        #***********多组数据加密**********************
        X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
                  0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
                  0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
                  0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)

        Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
                  0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
        plainText = Arr1024()
        plainTextLen = 32
        cipherText = Arr1024()
        cipherLen = c_uint()
        memmove(plainText, Y, 32)
        # gm.SKF_EncryptUpdate.argtypes = [c_void_p,  POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
        ret = gm.SKF_EncryptUpdate(SessionKey, plainText, plainTextLen, cipherText, byref(cipherLen))
        if ret == 0:
            self.output.append("多组数据加密成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据加密失败，ret=" + hex(ret))

        #************结束加密********************
        ret = gm.SKF_EncryptFinal(SessionKey, cipherText, byref(cipherLen))
        if ret == 0:
            self.output.append("结束加密成功，ret=" + hex(ret))
        else:
            self.output.append("结束加密失败，ret=" + hex(ret))

        #*********销毁会话密钥*********************
        ret = gm.SKF_DestroySessionKey(SessionKey)
        if ret == 0:
            self.output.append("销毁会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("销毁会话密钥失败，ret=" + hex(ret))

        #*************数据复制************************
        pEnvelopedKeyBlob = ENVELOPEDKEYBLOB()
        pEnvelopedKeyBlob.ulSymmAlgID = SGD_SMS4_ECB
        memmove(pEnvelopedKeyBlob.cbEncryptedPriKey, cipherText, 32)
        pEnvelopedKeyBlob.PubKey.BitLen = 32*8
        memmove(pEnvelopedKeyBlob.PubKey.XCoordinate, X, 32)
        memmove(pEnvelopedKeyBlob.PubKey.YCoordinate, byref(X, 32), 32)

        pEnvelopedKeyBlob.ECCCipherBlob.CipherLen = pData.CipherLen
        memmove(pEnvelopedKeyBlob.ECCCipherBlob.Cipher, pData.Cipher, pData.CipherLen)
        memmove(pEnvelopedKeyBlob.ECCCipherBlob.XCoordinate, pData.XCoordinate, 32)
        memmove(pEnvelopedKeyBlob.ECCCipherBlob.YCoordinate, pData.YCoordinate, 32)
        memmove(pEnvelopedKeyBlob.ECCCipherBlob.HASH, pData.HASH, 64)

        ret = gm.SKF_ImportECCKeyPair(phContainer, byref(pEnvelopedKeyBlob))
        if ret == 0:
            self.output.append("导入加密密钥对成功，ret=" + hex(ret))
        else:
            self.output.append("导入加密密钥对失败，ret=" + hex(ret))

    def SKF_ECCSignData(self):
        #SKF_ECCSignData(HCONTAINER hContainer, BYTE *pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature)
        pSignData = Arr32(0xB2,0xE9,0xA4,0x8F,0xB4,0x0C,0x56,0xA2,0x97,0x3A,0x6A,0x01,0x86,0x01,0x53,0x8E,
                       0x9E,0xE1,0x69,0x0B,0x14,0xF2,0x9E,0x52,0x15,0xD5,0x48,0x48,0x57,0xA0,0xD7,0xA6)
        ulSignDataLen = 32
        self.pSignature = Arr128()
        ret = gm.SKF_ECCSignData(phContainer, byref(pSignData), ulSignDataLen, self.pSignature)
        if ret == 0:
            self.output.append("ECC签名成功，ret=" + hex(ret))
        else:
            self.output.append("ECC签名失败，ret=" + hex(ret))

    def SKF_ECCVerify(self):
        # 导出签名公钥
        PUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = True
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, PUBK, pulBlobLen)
        if ret == 0:
            self.output.append("导出签名公钥成功，ret=" + hex(ret))
        else:
            self.output.append("导出签名公钥失败，ret=" + hex(ret))
        # 验证签名
        HASH = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                     0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        pBlob = ECCPUBLICKEYBLOB()
        pBlob.BitLen = 256
        memmove(pBlob.XCoordinate, byref(PUBK, 4), 64)
        memmove(pBlob.YCoordinate, byref(PUBK, 68), 64)
        Signature = ECCSIGNATUREBLOB()
        memmove(Signature.r, self.pSignature, 64)
        memmove(Signature.s, byref(self.pSignature, 64), 64)
        ret = gm.SKF_ECCVerify(phDev, byref(pBlob), HASH, 32, Signature)
        if ret == 0:
            self.output.append("EccVerify成功，ret=" + hex(ret))
        else:
            self.output.append("EccVerify失败，ret=" + hex(ret))

    def SKF_ECCExportSessionKey(self):
        # ********生成并导出会话密钥***************保护公钥对会话密钥加密（随机数），输出密文数据结构以及会话密钥句柄
        ret = gm.SKF_ECCExportSessionKey(phContainer, SGD_SMS4_ECB, byref(PKH), byref(pSessionKeyData), byref(SessionKey))
        if ret == 0:
            self.output.append("生成并导出会话秘钥成功，ret=" + hex(ret))
        else:
            self.output.append("生成并导出会话秘钥失败，ret=" + hex(ret))

    def SKF_ImportSessionKey(self):
        # 导出加密公钥
        encPUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = False
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, encPUBK, pulBlobLen)
        if ret == 0:
            self.output.append("导出加密公钥成功，ret=" + hex(ret))
        else:
            self.output.append("导出加密公钥失败，ret=" + hex(ret))
        # 生成并导出会话密钥
        pSessionKeyData = Arr1024()
        ret = gm.SKF_ECCExportSessionKey(phContainer, SGD_SMS4_ECB, byref(encPUBK), pSessionKeyData, byref(SessionKey))
        if ret == 0:
            self.output.append("生成并导出会话秘钥成功，ret=" + hex(ret))

        else:
            self.output.append("生成并导出会话秘钥失败，ret=" + hex(ret))
        #销毁会话密钥
        ret = gm.SKF_DestroySessionKey(SessionKey)
        if ret == 0:
            self.output.append("销毁会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("销毁会话密钥失败，ret=" + hex(ret))
        #导入会话密钥
        #SKF_ImportSessionKey(HCONTAINER hContainer, ULONG ulAlgId,BYTE *pbWrapedData, ULONG ulWrapedLen, HANDLE *phKey)
        ulAlgId = SGD_SMS4_ECB
        phKey = c_void_p()
        ret = gm.SKF_ImportSessionKey(phContainer, ulAlgId, pSessionKeyData, 1024, byref(phKey))
        if ret == 0:
            self.output.append("导入加密会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("导入加密会话密钥失败，ret=" + hex(ret))

    def SKF_ExportSignPublicKey(self):
        #SKF_ExportPublicKey(HCONTAINER hContainer, BYTE bSignFlag, ECCPUBLICKEYBLOB * pbBlob, ULONG * pulBlobLen)
        pulBlobLen = pointer(c_void_p())
        bSignFlag = c_ubyte(True)
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, pSignBlob, pulBlobLen)
        if ret == 0:
            self.output.append("导出签名公钥成功，ret=" + hex(ret))
            # print('XCoordinate = %X'%pBlob.contents.XCoordinate[:])
            # print('YCoordinate = %X'%pBlob.contents.YCoordinate[:])
        else:
            self.output.append("导出签名公钥失败，ret=" + hex(ret))

    def SKF_ExportEncrypPublicKey(self):
        #SKF_ExportPublicKey(HCONTAINER hContainer, BYTE bSignFlag, ECCPUBLICKEYBLOB * pbBlob, ULONG * pulBlobLen)
        pEncrypBlob = ECCPUBLICKEYBLOB()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = c_ubyte(False)
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, pEncrypBlob, pulBlobLen)
        if ret == 0:
            self.output.append("导出加密公钥成功，ret=" + hex(ret))
            # print('XCoordinate = %X'%pBlob.contents.XCoordinate[:])
            # print('YCoordinate = %X'%pBlob.contents.YCoordinate[:])
        else:
            self.output.append("导出加密公钥失败，ret=" + hex(ret))

    def SKF_ExportPublicKeyH(self):
        pbBlob = ECCCIPHERBLOB()
        pulBlobLen = pointer(c_uint())
        ret = gm.SKF_ExportPublicKeyH(phContainer, pbBlob, pulBlobLen)
        if 0 == ret:
            self.output.append("导出临时公钥成功，ret=" + hex(ret))
        else:
            self.output.append("导出临时公钥失败，ret=" + hex(ret))
    #old 加密模式
    # def SKF_ExtECCEncrypt(self):
    #     X = Arr32(0xae,0xec,0x7b,0x42,0xb9,0xb6,0x7e,0xe4,0x10,0x6a,0x56,0x95,0x1b,0xfd,0xd0,0xda,0x8d,0x10,0x38,0xd3,0xef,0x5b,0x30,0x8b,0x13,0x54,0xce,0x6f,0x43,0xca,0xf9,0x3a)
    #     Y = Arr32(0x1a,0x37,0xa2,0xc4,0x5b,0xfd,0x14,0xa4,0x43,0x84,0x10,0xe3,0x48,0xae,0x54,0x3f,0x60,0xb0,0x47,0xb8,0x7f,0x75,0xc8,0xbd,0xab,0xc4,0xbf,0x77,0xca,0xbb,0x95,0x3a)
    #     ECCPubKeyBlob = ECCPUBLICKEYBLOB()
    #     ECCPubKeyBlob.BitLen = 256
    #     memmove(ECCPubKeyBlob.XCoordinate, X, 32)
    #     memmove(ECCPubKeyBlob.YCoordinate, Y, 32)
    #     #外部公钥加密数据
    #     pbPlainText = (c_ubyte * 2048)()
    #     ulPlainTextLen = int(self.input4.text())
    #     ret = gm.SKF_GenRandom(phDev, pbPlainText, ulPlainTextLen)
    #     if 0 == ret:
    #         self.output.append("加密数据长度：%d" %ulPlainTextLen)
    #         seq = []
    #         for i in range(ulPlainTextLen):
    #             seq.append(hex(pbPlainText[i]))
    #         self.output.append("加密数据：%s" % seq)
    #     else:
    #         self.output.append("生成加密数据失败，ret=" + hex(ret))
    #     pCipherText = ECCCIPHERBLOB()
    #     ret = gm.SKF_ExtECCEncrypt(phDev, byref(ECCPubKeyBlob), pbPlainText, ulPlainTextLen, pCipherText)
    #     if ret == 0:
    #         self.output.append("ECC外来公钥加密成功，ret=" + hex(ret))
    #     else:
    #         self.output.append("ECC外来公钥加密失败，ret=" + hex(ret))

    def SKF_ExtECCEncrypt(self):
        X = Arr32(0xae,0xec,0x7b,0x42,0xb9,0xb6,0x7e,0xe4,0x10,0x6a,0x56,0x95,0x1b,0xfd,0xd0,0xda,0x8d,0x10,0x38,0xd3,0xef,0x5b,0x30,0x8b,0x13,0x54,0xce,0x6f,0x43,0xca,0xf9,0x3a)
        Y = Arr32(0x1a,0x37,0xa2,0xc4,0x5b,0xfd,0x14,0xa4,0x43,0x84,0x10,0xe3,0x48,0xae,0x54,0x3f,0x60,0xb0,0x47,0xb8,0x7f,0x75,0xc8,0xbd,0xab,0xc4,0xbf,0x77,0xca,0xbb,0x95,0x3a)
        ECCPubKeyBlob = ECCPUBLICKEYBLOB()
        ECCPubKeyBlob.BitLen = 256
        memmove(ECCPubKeyBlob.XCoordinate, X, 32)
        memmove(ECCPubKeyBlob.YCoordinate, Y, 32)
        #外部公钥加密数据
        pbPlainText = (c_ubyte * 2048)()
        ulPlainTextLen = int(self.input4.text())
        ret = gm.SKF_GenRandom(phDev, pbPlainText, ulPlainTextLen)
        if 0 == ret:
            self.output.append("加密数据长度：%d" %ulPlainTextLen)
            seq = []
            for i in range(ulPlainTextLen):
                seq.append(hex(pbPlainText[i]))
            self.output.append("加密数据：%s" % seq)
        else:
            self.output.append("生成加密数据失败，ret=" + hex(ret))
        pCipherText = ECCCIPHERBLOB()
        ret = gm.SKF_ExtECCEncrypt(phDev, byref(ECCPubKeyBlob), pbPlainText, ulPlainTextLen, pCipherText)
        if ret == 0:
            self.output.append("ECC外来公钥加密成功，ret=" + hex(ret))
        else:
            self.output.append("ECC外来公钥加密失败，ret=" + hex(ret))


    def SKF_GenerateAgreementDataWithECC(self):
        ret = gm.SKF_GenerateAgreementDataWithECC(phContainer, 0x000004, byref(Agreement_hostTempPubkey),
                                                  Agreement_hostID, 32, byref(phAgreementHandle))
        if ret == 0:
            self.output.append("发方生成密钥协商参数成功，ret=" + hex(ret))
        else:
            self.output.append("发方生成密钥协商参数失败，ret=" + hex(ret))

    def SKF_GenerateAgreementDataAndKeyWithECC(self):
        ulAlgId = SGD_SMS4_ECB
        pSponsorECCPubKeyBlob = ECCPUBLICKEYBLOB()
        A = Arr132(0x00, 0x00, 0x10, 0x00,
                   0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                   0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,)
        # 发起方固有公钥
        pSponsorECCPubKeyBlob.BitLen = 256
        memmove(pSponsorECCPubKeyBlob.XCoordinate, byref(A, 4), 64)
        memmove(pSponsorECCPubKeyBlob.YCoordinate, byref(A, 68), 64)
        ret = gm.SKF_GenerateAgreementDataAndKeyWithECC(
            phContainer, ulAlgId, byref(pSponsorECCPubKeyBlob), byref(Agreement_hostTempPubkey),
            byref(Agreement_slaveTempPubkey), Agreement_hostID, 33, Agreement_slaveID, 33, byref(SessionKey))
        if ret == 0:
            self.output.append("收方计算会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("收方计算会话密钥失败，ret=" + hex(ret))

    def SKF_GenerateKeyWithECC(self):
        # 响应方固定公钥
        reponseECCPubKeyBlob = ECCPUBLICKEYBLOB()
        B = Arr132(0x00, 0x00, 0x10, 0x00,
                   0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                   0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26, )
        reponseECCPubKeyBlob.BitLen = 256
        memmove(reponseECCPubKeyBlob.XCoordinate, byref(B, 4), 64)
        memmove(reponseECCPubKeyBlob.YCoordinate, byref(B, 68), 64)
        ret = gm.SKF_GenerateKeyWithECC(phAgreementHandle, byref(reponseECCPubKeyBlob),
                                        byref(Agreement_slaveTempPubkey), Agreement_slaveID, 33, byref(SessionKey))
        if ret == 0:
            self.output.append("发方计算会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("发方计算会话密钥失败，ret=" + hex(ret))

    def SKF_EncryptInit(self):
        # **********加密初始化**********************
        EncryptParam = BLOCKCIPHERPARAM()
        EncryptParam.IVLen = 16
        SGD_ECB = 0x00000001
        memset(EncryptParam.IV, 0X11, 16)
        EncryptParam.PaddingType = SGD_ECB
        ret = gm.SKF_EncryptInit(SessionKey, EncryptParam)
        if ret == 0:
            self.output.append("加密初始化成功，ret=" + hex(ret))
        else:
            self.output.append("加密初始化失败，ret=" + hex(ret))

    def SKF_EncryptUpdate(self):
        # ***********多组数据加密**********************
        X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
                  0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
                  0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
                  0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)

        Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
                  0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
        plainText = Arr1024()
        plainTextLen = 32
        memmove(plainText, Y, 32)
        gm.SKF_EncryptUpdate.argtypes = [c_void_p, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
        ret = gm.SKF_EncryptUpdate(SessionKey, plainText, plainTextLen, cipherText, byref(cipherLen))
        if ret == 0:
            self.output.append("多组数据加密成功，ret=" + hex(ret))
            print(cipherText[:])
            print(cipherLen)
        else:
            self.output.append("多组数据加密失败，ret=" + hex(ret))

    def SKF_EncryptFinal(self):
        # ************结束加密********************
        # SF_EncryptFinal(HANDLE Key, BYTE * pbEncryptedData, LONG * ulEncryptedDataLen);
        ret = gm.SKF_EncryptFinal(SessionKey, cipherText, byref(cipherLen))
        if ret == 0:
            self.output.append("结束加密成功，ret=" + hex(ret))
        else:
            self.output.append("结束加密失败，ret=" + hex(ret))

    def SKF_DecryptInit(self):
        # **********加密初始化**********************
        # SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam)
        DecryptParam = BLOCKCIPHERPARAM()
        DecryptParam.IVLen = 16
        memset(DecryptParam.IV, 0X11, 16)
        DecryptParam.PaddingType = SGD_ECB
        ret = gm.SKF_DecryptInit(SessionKey, DecryptParam)
        if ret == 0:
            self.output.append("解密初始化成功，ret=" + hex(ret))
        else:
            self.output.append("解密初始化失败，ret=" + hex(ret))

    def SKF_DecryptUpdate(self):
        # ***********多组数据解密**********************
        X = Arr64(0X09, 0XF9, 0XDF, 0X31, 0X1E, 0X54, 0X21, 0XA1, 0X50, 0XDD, 0X7D, 0X16, 0X1E, 0X4B, 0XC5, 0XC6,
                  0X72, 0X17, 0X9F, 0XAD, 0X18, 0X33, 0XFC, 0X07, 0X6B, 0XB0, 0X8F, 0XF3, 0X56, 0XF3, 0X50, 0X20,
                  0XCC, 0XEA, 0X49, 0X0C, 0XE2, 0X67, 0X75, 0XA5, 0X2D, 0XC6, 0XEA, 0X71, 0X8C, 0XC1, 0XAA, 0X60,
                  0X0A, 0XED, 0X05, 0XFB, 0XF3, 0X5E, 0X08, 0X4A, 0X66, 0X32, 0XF6, 0X07, 0X2D, 0XA9, 0XAD, 0X13)

        Y = Arr32(0X39, 0X45, 0X20, 0X8F, 0X7B, 0X21, 0X44, 0XB1, 0X3F, 0X36, 0XE3, 0X8A, 0XC6, 0XD3, 0X9F, 0X95,
                  0X88, 0X93, 0X93, 0X69, 0X28, 0X60, 0XB5, 0X1A, 0X42, 0XFB, 0X81, 0XEF, 0X4D, 0XF7, 0XC5, 0XB8)
        plainText = Arr1024()
        plainTextLen = c_uint()
        # SKF_DecryptUpdate(HANDLE hKey, BYTE *pbEncryptedData, ULONG ulEncryptedLen, BYTE *pbData, ULONG *pulDataLen)
        gm.SKF_DecryptUpdate.argtypes = [c_void_p, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint)]
        ret = gm.SKF_DecryptUpdate(SessionKey, cipherText, cipherLen, plainText, byref(plainTextLen))
        if ret == 0:
            self.output.append("多组数据解密成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据解密失败，ret=" + hex(ret))

    def SKF_DecryptFinal(self):
        # SKF_DecryptFinal(HANDLE hKey, BYTE *pbData, ULONG *pulDataLen);
        pbDecryptedData = Arr100()
        ulDecryptedDataLen = c_uint()
        ret = gm.SKF_DecryptFinal(SessionKey, pbDecryptedData, byref(ulDecryptedDataLen))
        if ret == 0:
            self.output.append("结束解密成功，ret=" + hex(ret))
        else:
            self.output.append("结束解密失败，ret=" + hex(ret))

    def SKF_DigestInit(self):
        #SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash)
        pInput = self.input1.text()
        pPubKey = ECCPUBLICKEYBLOB()
        pInputLen = 0 #表示进行标准的杂凑
        ret = gm.SKF_DigestInit(phDev, SGD_SM3, byref(pPubKey), pInput, pInputLen, byref(gl_Digest_hHash))
        if ret == 0:
            self.output.append("密码杂凑初始化成功，ret=" + hex(ret))
        else:
            self.output.append("密码杂凑初始化失败，ret=" + hex(ret))

    def SKF_Digest(self):
        #SKF_Digest(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen)
        pbData = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
        ulDataLen = 64
        pbHashData = Arr32()
        ulHashLen = c_int()
        ret = gm.SKF_Digest(gl_Digest_hHash, pbHashData, ulDataLen, pbHashData, byref(ulHashLen))
        if ret == 0:
            self.output.append("单组数据密码杂凑成功，ret=" + hex(ret))
        else:
            self.output.append("单组数据密码杂凑失败，ret=" + hex(ret))

    def SKF_DigestUpdate(self):
        phData = Arr128(0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,)
        ulDataLen = 128
        # SKF_DigestUpdate(HANDLE hHash, BYTE *pbData, ULONG ulDataLen)
        ret = gm.SKF_DigestUpdate(gl_Digest_hHash, phData, ulDataLen)
        if ret == 0:
            self.output.append("多组数据密码杂凑成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据密码杂凑失败，ret=" + hex(ret))

    def SKF_DigestFinal(self):
        pbData = Arr200(0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
						0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,
                        0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68, 0x65, 0x66, 0x67, 0x68,)
        SM3_BLOCK_SIZE = 64
        group = int(176/SM3_BLOCK_SIZE)
        ulDataLen = int(176%SM3_BLOCK_SIZE)
        pbHashData = Arr100()
        ulHashLen = c_uint()
        memmove(pbHashData, byref(pbData, group*SM3_BLOCK_SIZE), ulDataLen)
        ret = gm.SKF_DigestFinal(gl_Digest_hHash, pbHashData, byref(ulHashLen))
        if ret == 0:
            self.output.append("结束密码杂凑成功，ret=" + hex(ret))
        else:
            self.output.append("结束密码杂凑失败，ret=" + hex(ret))

    def SKF_MacInit(self):
        #SKF_MacInit(DEVHANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE *phMac)
        pMacParam = BLOCKCIPHERPARAM()
        memset(pMacParam.IV, 0, 32)
        pMacParam.IVLen = 16
        pMacParam.PaddingType = 0x00000001
        global  phMac
        phMac = c_void_p()
        ret = gm.SKF_MacInit(SessionKey, byref(pMacParam), byref(phMac))
        if ret == 0:
            self.output.append("Mac初始化成功，ret=" + hex(ret))
        else:
            self.output.append("Mac初始化失败，ret=" + hex(ret))

    def SKF_Mac(self):
        #SKF_Mac(HANDLE hMac, BYTE *pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen)
        pbData = Arr32(0xD1,0xC4 ,0x20 ,0xF4 ,0x25 ,0xC0 ,0xC7 ,0xBD ,0x50 ,0xBA ,0x40 ,0x4E ,0x95 ,0x42 ,0x46 ,0x88 ,
                       0x07 ,0xB2 ,0x32 ,0xE0 ,0x5D ,0xA3 ,0x0E ,0xB8 ,0x02 ,0x38 ,0x6A ,0xA3 ,0x93 ,0x7D ,0xC3 ,0x0D)
        ulDataLen = 16
        pbMacData = Arr4()
        pulMacDataLen = c_uint()
        ret = gm.SKF_Mac(phMac, pbData, ulDataLen, pbMacData, byref(pulMacDataLen))
        if ret == 0:
            self.output.append("单组数据Mac成功，ret=" + hex(ret))
        else:
            self.output.append("单组数据Mac失败，ret=" + hex(ret))

    def SKF_MacUpdate(self):
        #SKF_MacUpdate(HANDLE hMac, BYTE *pbData, ULONG ulDataLen)
        pbData = Arr32(0xD1, 0xC4, 0x20, 0xF4, 0x25, 0xC0, 0xC7, 0xBD, 0x50, 0xBA, 0x40, 0x4E, 0x95, 0x42, 0x46, 0x88,
                       0x07, 0xB2, 0x32, 0xE0, 0x5D, 0xA3, 0x0E, 0xB8, 0x02, 0x38, 0x6A, 0xA3, 0x93, 0x7D, 0xC3, 0x0D)
        ulDataLen = 32
        ret = gm.SKF_MacUpdate(phMac, pbData, ulDataLen)
        if ret == 0:
            self.output.append("多组数据Mac成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据Mac失败，ret=" + hex(ret))

    def SKF_MacFinal(self):
        #SKF_MacFinal(HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen)
        pbMacData = Arr4()
        pulMacDataLen = c_uint()
        ret = gm.SKF_MacFinal(phMac, pbMacData, pbMacData)
        if ret == 0:
            self.output.append("Mac结束成功，ret=" + hex(ret))
        else:
            self.output.append("Mac结束失败，ret=" + hex(ret))

    #IKI自定义接口--------------------------------------------------------
    def SKF_ImportIdentify(self):
        # SKF_ImportIdentify(HCONTAINER hContainer, LPSTR pbIden, ULONG len)
        pbKeyValue = self.input1.text()
        pbIden = c_char_p(pbKeyValue.encode())
        ret = gm.SKF_ImportIdentify(phContainer, pbIden, len(pbKeyValue.encode()))
        if ret == 0:
            self.output.append("导入实体标识成功，ret=" + hex(ret))
        else:
            self.output.append("导入实体标识失败，ret=" + hex(ret))

    def SKF_ExportIdentify(self):
        # SKF_ExportIdentify(HCONTAINER hContainer, LPSTR pbIden, ULONG * len)
        pbIden = ArrChar32()
        len = c_ulong()
        ret = gm.SKF_ExportIdentify(phContainer, pbIden, byref(len))
        if ret == 0:
            self.output.append("导出实体标识成功，ret=" + hex(ret))
            for i in pbIden: print(i)
        else:
            self.output.append("导出实体标识失败，ret=" + hex(ret))

    def SKF_ImportPubMatrix(self):
        #SKF_ImportPubMatrix(HAPPLICATION hApplication, BYTE * pbPubMatrix,ULONG ulMatLen, BOOL Flag)
        pbPubMatrix = ArrPKM()
        with open('F:\\pkm.cer', 'rb+') as f:
            str = f.read()
        arr = list(str)
        for i in range(len(arr)):
            pbPubMatrix[i] = arr[i]
        Flag = True
        ulMatLen = len(arr)
        ret = gm.SKF_ImportPubMatrix(phApplication, byref(pbPubMatrix), ulMatLen, Flag)
        if ret == 0:
            self.output.append("导入矩阵成功，ret=" + hex(ret))
        else:
            self.output.append("导入矩阵失败，ret=" + hex(ret))

    def SKF_ExportPubMatrix(self):
        #SKF_ExportPubMatrix(HAPPLICATION hApplication, BYTE *pbPubMatrix,ULONG *ulMatLen, BOOL Flag)
        pbPubMatrix = ArrPKM()
        ulMatLen = c_uint()
        Flag = True
        ret = gm.SKF_ExportPubMatrix(phApplication, byref(pbPubMatrix), byref(ulMatLen), Flag)
        if ret == 0:
            self.output.append("导出矩阵成功，ret=" + hex(ret))
        else:
            self.output.append("导出矩阵失败，ret=" + hex(ret))
        # with open('F:\\pkmout.cer', 'wb+') as f:
        #     for i in range(sizeof(pbPubMatrix)):
        #         f.writelines(pbPubMatrix[i])

    def SKF_DeletePubMatrix(self):
        ret = gm.SKF_DeletePubMatrix(phApplication, 2)
        if ret == 0:
            self.output.append("删除矩阵成功，ret=" + hex(ret))
        else:
            self.output.append("删除矩阵失败，ret=" + hex(ret))

    def SKF_CalculatePubKey(self):
        pass

    def SKF_CalculatePubKeyAddField(self):
        pbKeyValue = self.input1.text()
        pbIden = c_char_p(pbKeyValue.encode())
        ECCPubKeyBlob = ECCPUBLICKEYBLOB()
        field = c_ubyte(11)
        ret = gm.SKF_CalculatePubKeyAddField(phApplication, pbIden, len(pbKeyValue.encode()), field, byref(ECCPubKeyBlob))
        if ret == 0:
            self.output.append("加域计算实体标识成功，ret=" + hex(ret))
        else:
            self.output.append("加域计算实体标识失败，ret=" + hex(ret))

    def SKF_ECCExportSessionKeyEx(self):
        pPubKey = ECCPUBLICKEYBLOB()
        pData = ECCCIPHERBLOB()
        ret = gm.SKF_ECCExportSessionKeyEx(SessionKey, byref(pPubKey), byref(pData))
        if ret == 0:
            self.output.append("IKI导出会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("IKI导出会话密钥失败，ret=" + hex(ret))

    def SKF_GenerateKDFSessionKey(self):
        uiKeyBits = 128
        Rs = b'12345678'
        rsLen = 8
        Rc = b'12345678'
        rcLen = 8
        keyHandle = SessionKey
        keyCipher = pData
        newKeyHandle = c_void_p()
        symAlgID = c_uint()
        iv = c_ubyte()
        ret = gm.SKF_GenerateKDFSessionKey(phContainer, uiKeyBits, Rs, rsLen, Rc, rcLen, keyHandle, byref(keyCipher), byref(newKeyHandle), symAlgID, iv);
        if ret == 0:
            self.output.append("GenerateKDFSessionKey成功，ret=" + hex(ret))
        else:
            self.output.append("GenerateKDFSessionKey失败，ret=" + hex(ret))

    def SKF_DestroySessionKey(self):
        ret = gm.SKF_DestroySessionKey(SessionKey)
        if ret == 0:
            self.output.append("销毁会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("销毁会话密钥失败，ret=" + hex(ret))

    def SKF_ImportPublicKeyRPK(self):
        pkm = ArrPKM()
        ret = gm.SKF_ImportPublicKeyRPK(phContainer, pkm, sizeof(ArrPKM))
        if 0 == ret:
            self.output.append("SKF_ImportPublicKeyRPK成功，ret=" + hex(ret))
        else:
            self.output.append("SKF_ImportPublicKeyRPK失败，ret=" + hex(ret))

    def SKF_ExportPublicKeyRPK(self):
        pkmLen = c_ulong()
        pkm = ArrPKM()
        ret = gm.SKF_ExportPublicKeyRPK(phContainer, pkm, byref(pkmLen))
        if 0 == ret:
            self.output.append("SKF_ExportPublicKeyRPK成功，ret=" + hex(ret))
        else:
            self.output.append("SKF_ExportPublicKeyRPK失败，ret=" + hex(ret))

    def SKF_UkeyRandomTest(self):
        mode = self.input1.text()
        ret = gm.SKF_UkeyRandomTest(phDev, int(mode))
        if 0 == ret:
            self.output.append("随机数检测成功，ret=" + hex(ret))
        else:
            self.output.append("随机数检测失败，ret=" + hex(ret))

    def SKF_RandomSingleTest(self):
        ret = gm.SKF_GenRandom(phDev, byref(self.pbRandom), int(self.ulRandomLen))
        if 0 == ret:
            self.output.append("随机数单次检测成功，ret=" + hex(ret))
        else:
            self.output.append("随机数单次检测失败，ret=" + hex(ret))

    def SKF_HashInitFast(self):
        uiAlgID = SGD_SM3
        # pucPublicKey = pSignBlob
        ret = gm.SKF_HashInitFast(uiAlgID, byref(pSignBlob), None, 0)
        if 0 == ret:
            self.output.append("快速Hash初始化成功，ret=" + hex(ret))
        else:
            self.output.append("快速Hash初始化失败，ret=" + hex(ret))

    def SKF_HashUpdateFast(self):
        pucData = self.input1.text()
        uiDataLength = len(pucData)
        ret = gm.SKF_HashUpdateFast(pucData.encode(), uiDataLength)
        if 0 == ret:
            self.output.append("多组快速Hash初始化成功，ret=" + hex(ret))
        else:
            self.output.append("多组快速Hash初始化失败，ret=" + hex(ret))


    def SKF_HashFinalFast(self):
        pHashData = Arr32()
        puiHashLength = c_uint()
        ret = gm.SKF_HashFinalFast(pHashData, byref(puiHashLength))
        if 0 == ret:
            self.output.append("多组快速Hash初始化成功，ret=" + hex(ret))
        else:
            self.output.append("多组快速Hash初始化失败，ret=" + hex(ret))

    def SKF_GenerateAgreementDataWithECC_VPN(self):
        SkeyLen = 17
        #SKF_GenerateAgreementDataWithECC_VPN(HCONTAINER hContainer, ULONG ulAlgId, ULONG SkeyLen, ECCPUBLICKEYBLOB *pTempECCPubKeyBlob, BYTE *pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);
        ret = gm.SKF_GenerateAgreementDataWithECC_VPN(phContainer, SGD_SMS4_ECB, SkeyLen, byref(Agreement_hostTempPubkey), Agreement_hostID, 8, byref(phAgreementHandleVPN))
        if ret == 0:
            self.output.append("VPN发方生成密钥协商参数成功，ret=" + hex(ret))
        else:
            self.output.append("VPN发方生成密钥协商参数失败，ret=" + hex(ret))

    def SKF_GenAgreementDataAndKeyWithECC_VPN(self):
        # SKF_GenAgreementDataAndKeyWithECC_VPN(
	    #                                     HCONTAINER hContainer,ULONG ulAlgId, ULONG SkeyLen,
	    #                                     ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
	    #                                     ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
	    #                                     ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	    #                                     BYTE *pbID, ULONG ulIDLen,BYTE *pbSponsorID,ULONG ulSponsorIDLen, HANDLE *phKeyHandle,
	    #                                     ULONG *SessionKeyLen,BYTE *SessionKey);
        ulAlgId = SGD_SMS4_ECB
        SkeyLen = 17
        pSponsorECCPubKeyBlob = ECCPUBLICKEYBLOB()
        SessionKeyLen = c_ulong()
        SessionKey = c_ubyte()

        A = Arr132(0x00, 0x00, 0x10, 0x00,
                   0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                   0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26)
        # 发起方固有公钥
        pSponsorECCPubKeyBlob.BitLen = 256
        memmove(pSponsorECCPubKeyBlob.XCoordinate, byref(A, 4), 64)
        memmove(pSponsorECCPubKeyBlob.YCoordinate, byref(A, 68), 64)
        phKeyHandle1 = c_void_p()
        ret = gm.SKF_GenAgreementDataAndKeyWithECC_VPN(
            phContainer, ulAlgId, SkeyLen, byref(pSponsorECCPubKeyBlob), byref(Agreement_hostTempPubkey),
            byref(Agreement_slaveTempPubkey), Agreement_hostID, 8, Agreement_slaveID, 8, byref(phKeyHandle1), byref(SessionKeyLen), byref(SessionKey))
        if ret == 0:
            self.output.append("VPN收方计算会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("VPN收方计算会话密钥失败，ret=" + hex(ret))

    def SKF_GenerateKeyWithECC_VPN(self):
        # SKF_GenerateKeyWithECC_VPN(HANDLE hAgreementHandle,
        #                         ECCPUBLICKEYBLOB *pECCPubKeyBlob,
        #                         ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
        #                         BYTE *pbID, ULONG ulIDLen,
        #                         HANDLE *phKeyHandle,
        #                         ULONG *SessionKeyLen, BYTE *SessionKey);
        reponseECCPubKeyBlob = ECCPUBLICKEYBLOB()
        phKeyHandle2 = c_void_p()
        SessionKeyLen = c_ulong()
        SessionKey = c_ubyte()
        B = Arr132(0x00, 0x00, 0x10, 0x00,
                   0xea, 0x84, 0x2e, 0x90, 0x93, 0xaf, 0xbb, 0x20, 0xa3, 0xf8, 0x98, 0x26, 0x14, 0xe4, 0x70, 0x28,
                   0x06, 0x6f, 0x71, 0x07, 0xf7, 0xf8, 0xd1, 0xdf, 0xdb, 0x40, 0x51, 0x40, 0xd9, 0xe4, 0xe4, 0xa6,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26,
                   0xc1, 0x5b, 0x6e, 0x04, 0x9a, 0x02, 0x59, 0x42, 0x56, 0xb0, 0xff, 0x3e, 0x08, 0xcf, 0x39, 0x3e,
                   0xd8, 0x7a, 0xe6, 0xfc, 0xff, 0x4a, 0xc9, 0x33, 0xed, 0xc4, 0x8b, 0x23, 0x8c, 0x9d, 0x9a, 0x26)
        reponseECCPubKeyBlob.BitLen = 256
        memmove(reponseECCPubKeyBlob.XCoordinate, byref(B, 4), 64)
        memmove(reponseECCPubKeyBlob.YCoordinate, byref(B, 68), 64)
        ret = gm.SKF_GenerateKeyWithECC_VPN(phAgreementHandleVPN, byref(reponseECCPubKeyBlob), byref(Agreement_slaveTempPubkey), Agreement_slaveID, 8, byref(phKeyHandle2), byref(SessionKeyLen), byref(SessionKey))
        if ret == 0:
            self.output.append("VPN发方计算会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("VPN发方计算会话密钥失败，ret=" + hex(ret))

    def dmsUK_Hsign(self):
        identify = self.input1.text()
        idLen = len(identify)
        plainText = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                          0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        plainTextLen = 32
        self.pSignature = Arr128()
        degestAlgorithmId = c_ulong()
        signatureAlgorithmId = c_ulong()
        ret = gm.dmsUK_Hsign(phDev, phContainer, identify, idLen, plainText, plainTextLen, self.pSignature, byref(degestAlgorithmId), byref(signatureAlgorithmId))
        if ret == 0:
            self.output.append("dmsUK_Hsign成功，ret=" + hex(ret))
        else:
            self.output.append("dmsUK_Hsign失败，ret=" + hex(ret))

    def dmsUK_HEccVerify(self):
        # 导出签名公钥
        PUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = True
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, PUBK, pulBlobLen)
        if ret == 0:
            self.output.append("导出签名公钥成功，ret=" + hex(ret))
        else:
            self.output.append("导出签名公钥失败，ret=" + hex(ret))
        #验证签名
        identify = self.input1.text()
        idLen = len(identify)
        plainText = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                          0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        plainTextLen = 32
        pBlob = ECCPUBLICKEYBLOB()
        pBlob.BitLen = 256
        memmove(pBlob.XCoordinate, byref(PUBK, 4), 64)
        memmove(pBlob.YCoordinate, byref(PUBK, 68), 64)
        Signature = ECCSIGNATUREBLOB()
        memmove(Signature.r, self.pSignature, 64)
        memmove(Signature.s, byref(self.pSignature, 64), 64)
        ret = gm.dmsUK_HEccVerify(phDev, identify, idLen, plainText, plainTextLen, byref(Signature), byref(pBlob))
        if ret == 0:
            self.output.append("dmsUK_HEccVerify成功，ret=" + hex(ret))
        else:
            self.output.append("dmsUK_HEccVerify失败，ret=" + hex(ret))

    #--------------------------------性能测试-------------------------------

    def SKF_GenECCKeyPair_XN(self):
        total_time = 0
        num = int(self.input1.text())
        for i in range(num):
            start_time = time.time_ns()
            ret = gm.SKF_GenECCKeyPair(phContainer, SGD_SM2_1, byref(pBlob))
            end_time = time.time_ns()
            if 0 == ret:
                total_time += (end_time - start_time)
            else:
                self.output.append("生成签名密钥对失败，ret=" + hex(ret))
        signle_time = (total_time / 10**6) / num
        self.output.append("单次平均执行时间：%d ms" % signle_time)
        result_xn = num / (total_time / 10**9)
        self.output.append("SKF_GenECCKeyPair性能测试结果：%d 次/秒" % result_xn)
    @async_
    def SKF_ECCSignData_XN(self, *args):
        pSignData = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                          0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        ulSignDataLen = 32
        self.pSignature = Arr128()
        total_time = 0
        num = int(self.input1.text())
        for i in range(num):
            start_time = time.time_ns()
            ret = gm.SKF_ECCSignData(phContainer, pSignData, ulSignDataLen, self.pSignature)
            end_time = time.time_ns()
            if 0 == ret:
                total_time += (end_time - start_time)
            else:
                self.output.append("ECC签名失败，ret=" + hex(ret))
        signle_time = (total_time / 10 ** 6) / num
        self.output.append("单次平均执行时间：%d ms" % signle_time)
        result_xn = num / (total_time / 10 ** 9)
        self.output.append("SKF_ECCSignData性能测试结果：%d 次/秒" % result_xn)

    def SKF_ECCVerify_XN(self):
        # 导出签名公钥
        PUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = True
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, PUBK, pulBlobLen)
        if ret == 0:
            self.output.append("导出签名公钥成功，ret=" + hex(ret))
        else:
            self.output.append("导出签名公钥失败，ret=" + hex(ret))
        # 验证签名
        HASH = Arr32(0xB2, 0xE9, 0xA4, 0x8F, 0xB4, 0x0C, 0x56, 0xA2, 0x97, 0x3A, 0x6A, 0x01, 0x86, 0x01, 0x53, 0x8E,
                     0x9E, 0xE1, 0x69, 0x0B, 0x14, 0xF2, 0x9E, 0x52, 0x15, 0xD5, 0x48, 0x48, 0x57, 0xA0, 0xD7, 0xA6)
        pBlob = ECCPUBLICKEYBLOB()
        pBlob.BitLen = 256
        memmove(pBlob.XCoordinate, byref(PUBK, 4), 64)
        memmove(pBlob.YCoordinate, byref(PUBK, 68), 64)
        Signature = ECCSIGNATUREBLOB()
        memmove(Signature.r, self.pSignature, 64)
        memmove(Signature.s, byref(self.pSignature, 64), 64)
        total_time = 0
        num = int(self.input1.text())
        for i in range(num):
            start_time = time.time_ns()
            ret = gm.SKF_ECCVerify(phDev, byref(pBlob), HASH, 32, Signature)
            end_time = time.time_ns()
            if 0 == ret:
                total_time += (end_time - start_time)
            else:
                self.output.append("EccVerify失败，ret=" + hex(ret))
        signle_time = (total_time / 10 ** 6) / num
        self.output.append("单次平均执行时间：%d ms" % signle_time)
        result_xn = num / (total_time / 10 ** 9)
        self.output.append("SKF_ECCVerify性能测试结果：%d 次/秒" % result_xn)

    def SKF_ExtECCEncrypt_XN(self):
        X = Arr32(0xae, 0xec, 0x7b, 0x42, 0xb9, 0xb6, 0x7e, 0xe4, 0x10, 0x6a, 0x56, 0x95, 0x1b, 0xfd, 0xd0, 0xda,
                  0x8d, 0x10, 0x38, 0xd3, 0xef, 0x5b, 0x30, 0x8b, 0x13, 0x54, 0xce, 0x6f, 0x43, 0xca, 0xf9, 0x3a)
        Y = Arr32(0x1a, 0x37, 0xa2, 0xc4, 0x5b, 0xfd, 0x14, 0xa4, 0x43, 0x84, 0x10, 0xe3, 0x48, 0xae, 0x54, 0x3f,
                  0x60, 0xb0, 0x47, 0xb8, 0x7f, 0x75, 0xc8, 0xbd, 0xab, 0xc4, 0xbf, 0x77, 0xca, 0xbb, 0x95, 0x3a)
        ECCPubKeyBlob = ECCPUBLICKEYBLOB()
        ECCPubKeyBlob.BitLen = 256
        memmove(ECCPubKeyBlob.XCoordinate, X, 32)
        memmove(ECCPubKeyBlob.YCoordinate, Y, 32)
        pbPlainText = Arr32(0x1a, 0x37, 0xa2, 0xc4, 0x5b, 0xfd, 0x14, 0xa4, 0x43, 0x84, 0x10, 0xe3, 0x48, 0xae, 0x54,
                            0x3f, 0x60, 0xb0, 0x47, 0xb8, 0x7f, 0x75, 0xc8, 0xbd, 0xab, 0xc4, 0xbf, 0x77, 0xca, 0xbb,
                            0x95, 0x3a)
        ulPlainTextLen = 32
        pCipherText = ECCCIPHERBLOB()
        total_time = 0
        num = int(self.input1.text())
        for i in range(num):
            start_time = time.time_ns()
            ret = gm.SKF_ExtECCEncrypt(phDev, byref(ECCPubKeyBlob), pbPlainText, ulPlainTextLen, pCipherText)
            end_time = time.time_ns()
            if 0 == ret:
                total_time += (end_time - start_time)
            else:
                self.output.append("ECC外来公钥加密失败，ret=" + hex(ret))
        signle_time = (total_time / 10 ** 6) / num
        self.output.append("单次平均执行时间：%d ms" % signle_time)
        result_xn = num / (total_time / 10 ** 9)
        self.output.append("SKF_ExtECCEncrypt性能测试结果：%d 次/秒" % result_xn)

    def SKF_ImportSessionKey_XN(self):
        # 导出加密公钥公钥
        encPUBK = Arr132()
        pulBlobLen = pointer(c_void_p())
        bSignFlag = False
        ret = gm.SKF_ExportPublicKey(phContainer, bSignFlag, encPUBK, pulBlobLen)
        if ret == 0:
            self.output.append("导出加密公钥成功，ret=" + hex(ret))
        else:
            self.output.append("导出加密公钥失败，ret=" + hex(ret))
        # 生成并导出会话密钥
        pSessionKeyData = Arr180()
        ret = gm.SKF_ECCExportSessionKey(phContainer, SGD_SMS4_ECB, byref(encPUBK), pSessionKeyData, byref(SessionKey))
        if ret == 0:
            self.output.append("生成并导出会话秘钥成功，ret=" + hex(ret))

        else:
            self.output.append("生成并导出会话秘钥失败，ret=" + hex(ret))
        #销毁会话密钥
        ret = gm.SKF_DestroySessionKey(SessionKey)
        if ret == 0:
            self.output.append("销毁会话密钥成功，ret=" + hex(ret))
        else:
            self.output.append("销毁会话密钥失败，ret=" + hex(ret))
        # 导入会话密钥
        ulAlgId = SGD_SMS4_ECB
        phKey = c_void_p()
        total_time = 0
        num = int(self.input1.text())
        for i in range(num):
            start_time = time.time_ns()
            ret = gm.SKF_ImportSessionKey(phContainer, ulAlgId, pSessionKeyData, 180, byref(phKey))
            end_time = time.time_ns()
            if 0 == ret:
                total_time += (end_time - start_time)
            else:
                self.output.append("导入加密会话密钥失败，ret=" + hex(ret))
            ret = gm.SKF_DestroySessionKey(phKey)
            if ret != 0:
                self.output.append("销毁会话密钥失败，ret=" + hex(ret))
        signle_time = (total_time / 10 ** 6) / num
        self.output.append("单次平均执行时间：%d ms" % signle_time)
        result_xn = num / (total_time / 10 ** 9)
        self.output.append("SKF_ImportSessionKey性能测试结果：%d 次/秒" % result_xn)

    def SKF_Hash_XN(self):
        #杂凑初始化
        pInput = self.input1.text()
        pPubKey = ECCPUBLICKEYBLOB()
        pInputLen = 0  # 表示进行标准的杂凑

        start_time = time.time_ns()
        ret = gm.SKF_DigestInit(phDev, SGD_SM3, None, None, 0, byref(gl_Digest_hHash))
        if ret == 0:
            self.output.append("密码杂凑初始化成功，ret=" + hex(ret))
        else:
            self.output.append("密码杂凑初始化失败，ret=" + hex(ret))
        #多组数据杂凑
        with open('F:\\1111.PDF', 'rb+') as f:
            str = f.read()
        phData = create_string_buffer(str, len(str))
        ulDataLen = len(str)
        ret = gm.SKF_DigestUpdate(gl_Digest_hHash, phData, ulDataLen)
        if ret == 0:
            self.output.append("多组数据密码杂凑成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据密码杂凑失败，ret=" + hex(ret))
        #结束杂凑
        pbHashData = Arr32()
        ulHashLen = c_uint()
        ret = gm.SKF_DigestFinal(gl_Digest_hHash, pbHashData, byref(ulHashLen))
        if ret == 0:
            self.output.append("结束密码杂凑成功，ret=" + hex(ret))
        else:
            self.output.append("结束密码杂凑失败，ret=" + hex(ret))
        end_time = time.time_ns()
        total_time = (end_time  - start_time) /(10 ** 6)
        self.output.append("file Hash time：%d ms" % total_time)
        speed = 1000 * ulDataLen / (1024 * total_time);
        self.output.append("Hash speed：%f KB/s" % speed)

    def SKF_Encrypt_XN(self):
        #*****************加密初始化********************
        EncryptParam = BLOCKCIPHERPARAM()
        EncryptParam.IVLen = 16
        SGD_ECB = 0x00000001
        memset(EncryptParam.IV, 0X00, 32)
        EncryptParam.PaddingType = SGD_ECB

        start_time = time.time_ns()
        ret = gm.SKF_EncryptInit(SessionKey, EncryptParam)
        if ret == 0:
            self.output.append("加密初始化成功，ret=" + hex(ret))
        else:
            self.output.append("加密初始化失败，ret=" + hex(ret))
        #****************多组数据加密********************
        plainTextLen = 65536
        cipherLen = c_ulong()
        ret = gm.SKF_EncryptUpdate(SessionKey, plainTextXN, plainTextLen, cipherTextXN, byref(cipherLen))
        if ret == 0:
            self.output.append("多组数据加密成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据加密失败，ret=" + hex(ret))
        #******************结束加密************************
        ret = gm.SKF_EncryptFinal(SessionKey, cipherTextXN, byref(cipherLen))
        if ret == 0:
            self.output.append("结束加密成功，ret=" + hex(ret))
        else:
            self.output.append("结束加密失败，ret=" + hex(ret))

        end_time = time.time_ns()
        total_time = (end_time - start_time) / (10 ** 6)
        self.output.append("Encrypt time：%d ms" % total_time)
        speed = 8000 * plainTextLen / (1024 * total_time)
        self.output.append("Encrypt speed：%f Kb/s" % speed)

    def SKF_Decrypt_XN(self):
        # **********解密初始化**********************
        DecryptParam = BLOCKCIPHERPARAM()
        DecryptParam.IVLen = 16
        memset(DecryptParam.IV, 0X00, 32)
        DecryptParam.PaddingType = SGD_ECB

        start_time = time.time_ns()
        ret = gm.SKF_DecryptInit(SessionKey, DecryptParam)
        if ret == 0:
            self.output.append("解密初始化成功，ret=" + hex(ret))
        else:
            self.output.append("解密初始化失败，ret=" + hex(ret))
        # *************多组数据解密******************
        cipherLen = 65536
        plainTextLen = c_ulong()
        ret = gm.SKF_DecryptUpdate(SessionKey, cipherTextXN, cipherLen, plainTextXN, byref(plainTextLen))
        if ret == 0:
            self.output.append("多组数据解密成功，ret=" + hex(ret))
        else:
            self.output.append("多组数据解密失败，ret=" + hex(ret))
        # ****************结束解密********************
        pbDecryptedData = Arr16()
        ulDecryptedDataLen = c_ulong()
        ret = gm.SKF_DecryptFinal(SessionKey, pbDecryptedData, byref(ulDecryptedDataLen))
        if ret == 0:
            self.output.append("结束解密成功，ret=" + hex(ret))
        else:
            self.output.append("结束解密失败，ret=" + hex(ret))

        end_time = time.time_ns()
        total_time = (end_time - start_time) / (10 ** 6)
        self.output.append("Decrypt time：%d ms" % total_time)
        speed = 1000 * cipherLen / (1024 * total_time);
        self.output.append("Decrypt speed：%f KB/s" % speed)

    def write_file_XN(self):
        szFileName = self.input1.text()
        Indata = Arr128(0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
                        0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF)
        start_time = time.time_ns()
        for i in range(0, 20480, 128):
            ret = gm.SKF_WriteFile(phApplication, szFileName.encode(), i, Indata, 128)
            if ret != 0:
                self.output.append("写文件失败，ret=" + hex(ret))
        end_time = time.time_ns()
        total_time = (end_time - start_time) / (10 ** 6)
        self.output.append("SKF_WriteFile time：%d ms" % total_time)
        speed = 1000 * (128 * 160) / (1024 * total_time);
        self.output.append("SKF_WriteFile speed：%f KB/s" % speed)

    def read_file_XN(self):
        pbOutData = Arr1024()
        pulOutLen = c_uint()
        szFileName = self.input1.text()
        start_time = time.time_ns()
        for i in range(0, 20480, 128):
            ret = gm.SKF_ReadFile(phApplication, szFileName.encode(), i, 128, pbOutData, byref(pulOutLen))
            if ret != 0:
                self.output.append("读文件失败，ret=" + hex(ret))
        end_time = time.time_ns()
        total_time = (end_time - start_time) / (10 ** 6)
        self.output.append("SKF_ReadFile time：%d ms" % total_time)
        speed = 1000 * (128 * 160) / (1024 * total_time);
        self.output.append("SKF_ReadFile speed：%f KB/s" % speed)



if __name__ == '__main__':
    gm = WinDLL('GUOMI.dll')
    app = QApplication(sys.argv)
    win = UiUkey()
    win.show()
    sys.exit(app.exec_())