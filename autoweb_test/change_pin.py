import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from ahdms.browserengine import BrowserEngine
from ahdms.logger import Logger
logger = Logger(logger = "BindEmail").getLog()

class ChangePIN(object):
    """
    修改Ukey PIN码
    """
    def __init__(self, driver):
        self.driver = driver
        self.driver.find_element_by_xpath("//*[@id='app']/div[1]/div[1]/div[2]/ul/li[4]/a/span").click()
        mes = self.driver.find_element_by_xpath("//*[@id='UKeyManage']/div[2]/form/div[1]/div[1]/div[2]").text
        while mes == "请插入要操作的UKey":
            if self.driver.find_element_by_xpath("//*[@id='UKeyManage']/div[2]/form/div[1]/div[1]/div[2]").text == "UKey已插入":
                break
            print("请插入要操作的UKey")

    def change_pin(self, oldPin, newPin, confirmPin):
        self.driver.find_element_by_xpath("//*[@id='UKeyManage']/div[2]/form/div[1]/div[2]/div/div[1]/input").send_keys(oldPin)
        self.driver.find_element_by_xpath("//*[@id='UKeyManage']/div[2]/form/div[1]/div[3]/div/div[1]/input").send_keys(newPin)
        self.driver.find_element_by_xpath("//*[@id='UKeyManage']/div[2]/form/div[1]/div[4]/div/div[1]/input").send_keys(confirmPin)
        self.driver.find_element_by_xpath("//*[@id='UKeyManage']/div[2]/form/div[2]/button").click()
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(self.driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "修改成功"))  # 等待确认文本出现
        self.driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()

