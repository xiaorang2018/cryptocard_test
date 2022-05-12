from ahdms.browserengine import BrowserEngine
from ahdms.codelogin import CodeLogin
from ahdms.mysql import Mysql
from ahdms.register import Register
from ahdms.phonegenerate import PhoneNOGenerate
from ahdms.randomstring import GenerateRandom
from ahdms.identity import Identity
from ahdms.ukey_manager import UkeyManager
import time

#打开浏览器,
browser = BrowserEngine()
driver = browser.getBrowser()
driver.get("https://ra.teikitid.org/#/login")


#注册用户
user = PhoneNOGenerate().phoneNORandomGenerate()
register = Register()
register.registerSendCode(driver, user)
db = Mysql("172.16.1.10", 3306, "root", "AHdms520", "iki-ra")
time.sleep(2)
sql = "select verification_code from verification_code where is_valid = '1' and mobile_phone = '%s' ORDER BY send_date DESC"%(user)
code = db.execQuery(sql)
register.register(driver, code[0])
time.sleep(3)

#标识管理流程
#产生随机标识
pin = "12345678"
reasion = "abcd1234"
random = GenerateRandom()
identity = random.generateRandom(20)

#开始申请标识
apply = Identity()
apply.applyIdentity(driver, identity, pin)

#下载标识
time.sleep(1)
apply.downIdentity(driver, pin)

#挂起标识
time.sleep(1)
apply.holdIdentity(driver, reasion, pin)

#解挂标识
time.sleep(1)
apply.unHoldIdentity(driver, reasion, pin)

#更新标识
time.sleep(1)
apply.updateIdentity(driver, pin)

#下载标识
time.sleep(1)
apply.downIdentity(driver, pin)

#吊销标识
time.sleep(1)
apply.revokeIdentity(driver, reasion, pin)


#删除UKey应用
time.sleep(1)
UkeyManager().delete_application()

#关闭浏览器
driver.close()