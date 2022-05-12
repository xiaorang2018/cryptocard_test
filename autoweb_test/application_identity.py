from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from ahdms.logger import Logger
import os
logger = Logger(logger = "Identity").getLog()

class ApplicationIdentity(object):

    def apply_app_identity(self, driver, random, organization_code, organization_code_path, apply_p10_path):
        #跳转到应用标识申请页面
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div[1]/div[2]/ul/li[3]/a/span").click()
        driver.find_element_by_id("tab-Aid").click()
        driver.find_element_by_id("addBtn").click()
        #定位企业名称input
        enterprise_name = random
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[1]/div/div[1]/input").send_keys(enterprise_name)
        #定位组织结构input
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[2]/div/div[1]/input").send_keys(organization_code)
        #定位组织机构文件file
        #organization_code_path = 'file:///' + os.path.abspath('test.png')
        #driver.get(organization_code_path)
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[3]/div/div/input").send_keys(organization_code_path)
        #定位应用名称input
        apply_name = random
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[4]/div/div/input").send_keys(apply_name)
        #定位实体标识input
        entity_identity = random
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[5]/div/div/input").send_keys(entity_identity)
        #定位应用描述input
        apply_describe = random
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[6]/div/div/textarea").send_keys(apply_describe)
        #定位标识模板
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[7]/div/div[1]/div/input").click()
        # driver.find_element_by_xpath("/html/body/div[3]/div[1]/div[1]/ul/li[2]").click()
        #定位申请文件file
        #apply_p10_path = 'file:///' + os.path.abspath('test.p10')
        #driver.get(apply_p10_path)
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[1]/div[8]/div/div/input").send_keys(apply_p10_path)
        #定位申请按钮button
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[2]/button[1]").click()
        # 标识申请成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "申请请求提交成功，请等待审核!"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()

    def down_app_identity(self, driver, pin):

        driver.find_element_by_xpath("//*[@id='UKeyIdentity']/div[2]/table/tbody/tr[1]/td[8]/button[2]").click()
        # pin码输入页面操作
        pin_element = "//*[@id='downloadTid']/form/div[2]/div/div/div/input"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, pin_element)))  # 等待pin输入框出现
        driver.find_element_by_xpath(pin_element).send_keys(pin)
        driver.find_element_by_xpath("//*[@id='downloadTid']/form/div[3]/div/button[1]").click()
        # 标识下载成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "下载成功"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()


    def hold_app_identity(self, driver, reasion, pin):

        driver.find_element_by_xpath("//*[@id='UKeyIdentity']/div[2]/table/tbody/tr[1]/td[8]/button[6]").click()
        reasion_element = "//*[@id='hangUp']/div[2]/form/div/div/div/textarea"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, reasion_element)))  # 等待reasion输入框出现
        driver.find_element_by_xpath(reasion_element).send_keys(reasion)
        driver.find_element_by_xpath("//*[@id='hangUp']/div[4]/div/button[1]").click()
        # pin码输入页面操作
        pin_element = "//*[@id='UKeyModal']/div/div[2]/div/form/div[1]/div/div[2]/div/div[1]/input"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, pin_element)))  # 等待pin输入框出现
        driver.find_element_by_xpath(pin_element).send_keys(pin)
        driver.find_element_by_xpath("//*[@id='UKeyModal']/div/div[2]/div/form/div[2]/button").click()
        # 标识挂起成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "挂起请求提交成功，请等待管理员审核！"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()

    def unhold_app_identity(self, driver, reasion, pin):
        driver.find_element_by_xpath("//*[@id='UKeyIdentity']/div[2]/table/tbody/tr[1]/td[8]/button[4]").click()
        reasion_element = "//*[@id='solution']/div[2]/form/div/div/div/textarea"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, reasion_element)))  # 等待reasion输入框出现
        driver.find_element_by_xpath(reasion_element).send_keys(reasion)
        driver.find_element_by_xpath("//*[@id='solution']/div[4]/div/button[1]").click()
        # pin码输入页面操作
        pin_element = "//*[@id='UKeyModal']/div/div[2]/div/form/div[1]/div/div[2]/div/div[1]/input"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, pin_element)))  # 等待pin输入框出现
        driver.find_element_by_xpath(pin_element).send_keys(pin)
        driver.find_element_by_xpath("//*[@id='UKeyModal']/div/div[2]/div/form/div[2]/button").click()
        # 标识解挂成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "解挂请求提交成功，请等待管理员审核！"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()


    def update_app_identity(self, driver, pin):

        driver.find_element_by_xpath("//*[@id='UKeyIdentity']/div[2]/table/tbody/tr[1]/td[8]/button[5]").click()
        # pin码输入页面操作
        pin_element = "//*[@id='update']/div[2]/form/div[1]/div[2]/div/div/input"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, pin_element)))  # 等待pin输入框出现
        driver.find_element_by_xpath(pin_element).send_keys(pin)
        driver.find_element_by_xpath("//*[@id='update']/div[2]/form/div[2]/button[1]").click()
        # 标识下载成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "更新请求提交成功，请等待管理员审核！"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()



    def revoke_app_identity(self, driver, reasion, pin):

        driver.find_element_by_xpath("//*[@id='UKeyIdentity']/div[2]/table/tbody/tr[1]/td[8]/button[7]").click()
        reasion_element = "//*[@id='revoke']/div[2]/form/div/div/div/textarea"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, reasion_element)))  # 等待reasion输入框出现
        driver.find_element_by_xpath(reasion_element).send_keys(reasion)
        driver.find_element_by_xpath("//*[@id='revoke']/div[4]/div/button[1]").click()
        # pin码输入页面操作
        pin_element = "//*[@id='UKeyModal']/div/div[2]/div/form/div[1]/div/div[2]/div/div[1]/input"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, pin_element)))  # 等待pin输入框出现
        driver.find_element_by_xpath(pin_element).send_keys(pin)
        driver.find_element_by_xpath("//*[@id='UKeyModal']/div/div[2]/div/form/div[2]/button").click()
        # 标识挂起成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "吊销请求提交成功，请等待管理员审核！"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()






