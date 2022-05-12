from ahdms.browserengine import BrowserEngine
from ahdms.codelogin import CodeLogin
from ahdms.mysql import Mysql
from ahdms.register import Register
from ahdms.phonegenerate import PhoneNOGenerate
from ahdms.randomstring import GenerateRandom
from ahdms.identity import Identity
from ahdms.email_generate import RandomEmail
from ahdms.bind_email import BindEmail
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
login.codeLogin(driver, code[0][0])

#绑定邮箱
email = RandomEmail().random_email(email_type=None, rang=15)
bindemail = BindEmail(driver)
bindemail.input_email(email)
db1 = Mysql("172.16.1.10", "root", "AHdms520", "iki-ra")
time.sleep(2)
sql = "select verification_code from verification_code where is_valid='1' and email = '%s' ORDER BY send_date DESC"%(email)
code = db1.execQuery(sql)
bindemail.input_code(code[0][0])









