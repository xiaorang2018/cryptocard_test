from ahdms.browserengine import BrowserEngine
from ahdms.codelogin import CodeLogin
from ahdms.mysql import Mysql
from ahdms.randomstring import GenerateRandom
from ahdms.application_identity import ApplicationIdentity
import time

#打开浏览器,
browser = BrowserEngine()
driver = browser.getBrowser()
driver.get("https://ra.teikiaid.org/#/login")


#注册用户
user = "15888888888"

#发送验证码
login = CodeLogin()
login.sendCode(driver, user)

#验证码登录
db = Mysql("172.16.200.191", 8066, "root", "AHdms520", "iki-ra")
time.sleep(2)
sql = "select verification_code from verification_code where is_valid = '1' and mobile_phone = '%s' ORDER BY send_date DESC"%(user)
code = db.execQuery(sql)
login.codeLogin(driver, code[0])

#产生表单输入数据
random = GenerateRandom().generateRandom(20)
organization_code = "77651122-2"
organization_code_path = "F:\\test.png"
apply_p10_path = "F:\\test.p10"

#开始申请应用标识
ApplicationIdentity().apply_app_identity(driver, random, organization_code, organization_code_path, apply_p10_path)

















