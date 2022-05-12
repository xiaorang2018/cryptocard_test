from ahdms.browserengine import BrowserEngine
from ahdms.codelogin import CodeLogin
from ahdms.mysql import Mysql
from ahdms.register import Register
from ahdms.phonegenerate import PhoneNOGenerate
from ahdms.randomstring import GenerateRandom
from ahdms.change_pin import ChangePIN

import time

#打开浏览器,
browser = BrowserEngine()
driver = browser.getBrowser()
driver.get("https://ra.teikitid.org/#/login")


#注册用户
user = "15873158639"
pin = "12345678"
reasion = "kindsofreasion"

#发送验证码
login = CodeLogin()
login.sendCode(driver, user)

#验证码登录
db = Mysql("172.16.1.10", 3306, "root", "AHdms520", "iki-ra")
time.sleep(2)
sql = "select verification_code from verification_code where is_valid = '1' and mobile_phone = '%s' ORDER BY send_date DESC"%(user)
code = db.execQuery(sql)
login.codeLogin(driver, code[0])

#修改PIN码
changepin = ChangePIN(driver)
oldPin = '12345678'
newPin = 'abcd1234'
confirmPin = 'abcd1234'
changepin.change_pin(oldPin, newPin, confirmPin)