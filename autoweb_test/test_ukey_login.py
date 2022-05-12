from ahdms.browserengine import BrowserEngine
from ahdms.codelogin import CodeLogin
from ahdms.mysql import Mysql
from ahdms.register import Register
from ahdms.phonegenerate import PhoneNOGenerate
from ahdms.randomstring import GenerateRandom
from ahdms.identity import Identity
from ahdms.email_generate import RandomEmail
from ahdms.bind_email import BindEmail
from ahdms.ukey_login import UkeyLogin
import time

#打开浏览器,
browser = BrowserEngine()
driver = browser.getBrowser()
driver.get("https://ra.teikitid.org/#/login")

#ukey登录
pin = "12345678"
login = UkeyLogin(driver)
login.ukey_login(pin)