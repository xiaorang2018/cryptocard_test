import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from ahdms.logger import Logger
logger = Logger(logger = "BindEmail").getLog()

class BindEmail(object):

    def __init__(self, driver):
        # 进入用户管理主页
        self.driver = driver
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div[1]/div[2]/ul/li[2]/a").click()
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div[2]/div/div[2]/div/div[2]/div/div[2]/div[4]/div[2]").click()

    def input_email(self, email):
        #输入验证码和邮箱
        self.driver.find_element_by_xpath("//*[@id='bindEmail']/div[2]/form/div[1]/div/div/div/input").send_keys(email)
        self.driver.find_element_by_xpath("//*[@id='newEmailVerify']").click()

    def input_code(self, code):
        self.driver.find_element_by_xpath("//*[@id='bindEmail']/div[2]/form/div[2]/div/div/div/input").send_keys(code)
        self.driver.find_element_by_xpath("//*[@id='bindEmail']/div[2]/form/div[3]/div[1]/button").click()
        #邮箱绑定确认操作
        textelement = "/html/body/div[2]/div/div[2]/div[1]/p/div/div[2]"
        ret = WebDriverWait(self.driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "绑定成功"))  # 等待确认文本出现
        self.driver.find_element_by_xpath("/html/body/div[2]/div/div[3]/button").click()
        if ret != True:
            logger.error("绑定邮箱失败！")
            return -1
