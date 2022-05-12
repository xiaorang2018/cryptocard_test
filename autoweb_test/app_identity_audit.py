from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from ahdms.logger import Logger
import os
import time
logger = Logger(logger = "Identity").getLog()

class AppIdentityAudit(object):

    def __init__(self, driver, pin):
        self.driver = driver
        self.pin = pin
        driver.find_element_by_xpath("//*[@id='mydiv']/div[3]/div/div[2]/form/div[2]/div/input").send_keys(pin)
        driver.find_element_by_xpath("//*[@id='mydiv']/div[3]/div/div[2]/form/div[4]/button").click()
        driver.find_element_by_xpath("//*[@id='J_navlist']/li[2]/div/p[3]").click()

    def app_identity_audit(self, identity, reason):
        #定位应用可信标识按钮
        self.driver.find_element_by_xpath("//*[@id='myTab']/li[2]/a").click()
        #定位搜索输入input
        self.driver.find_element_by_xpath("/html/body/div[2]/div[2]/ui-view/div/div/ui-view/div[1]/div[1]/div/div/input").send_keys(identity)
        #定位搜索img
        self.driver.find_element_by_xpath("/html/body/div[2]/div[2]/ui-view/div/div/ui-view/div[1]/div[1]/div/div/img").click()
        #定位审核button
        time.sleep(2)
        self.driver.find_element_by_xpath("//*[@id='ramaneger_table']/tbody/tr/td[5]/button[2]").click()
        #定位审核理由textarea
        self.driver.find_element_by_xpath("//*[@id='InformationAuditUser']/div/div/form/div/div[1]/div[7]/div[2]/div/textarea").send_keys(reason)
        #定位通过button
        self.driver.find_element_by_xpath("//*[@id='InformationAuditUser']/div/div/form/div/div[2]/button[1]").click()
        #定位PIN码input
        self.driver.find_element_by_xpath("//*[@id='inputToken']").send_keys(self.pin)
        #定位确定button
        self.driver.find_element_by_xpath("//*[@id='insertUKey']/div/div/div/form/div[3]/div/button").click()