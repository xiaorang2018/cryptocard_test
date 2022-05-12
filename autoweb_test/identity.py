from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from ahdms.logger import Logger

logger = Logger(logger = "Identity").getLog()

class Identity(object):

    def applyIdentity(self, driver, identity, pin):
        #跳转到首页
        # driver.find_element_by_class_name(".homeMenu.homeActive").click()
        # element = driver.find_element_by_css_selector('.router-link-exact-active.router-link-active')
        # driver.execute_script('arguments[0].click()', element);
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div[1]/div[2]/ul/li[1]/a").click()
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div[2]/div/div[2]/div/div[2]/div[1]/div/div[2]/button").click()
        # 标识输入页面操作
        input_element = "//*[@id='request']/div[2]/form/div[1]/div/div/div[1]/input"
        WebDriverWait(driver, 3).until(EC.visibility_of_element_located((By.XPATH, input_element)))  # 等待identity输入框出现
        driver.find_element_by_xpath(input_element).send_keys(identity)
        driver.find_element_by_xpath("//*[@id='request']/div[2]/form/div[2]/button[1]").click()
        # pin码输入页面操作
        pin_element = "//*[@id='UKeyModal']/div/div[2]/div/form/div[1]/div/div[2]/div/div[1]/input"
        WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.XPATH, pin_element)))  # 等待pin输入框出现
        if pin != "12345678":
            logger.error("PIN码错误！")
        else:
            logger.info("PIN码正确！")
        driver.find_element_by_xpath(pin_element).send_keys(pin)
        driver.find_element_by_xpath("//*[@id='UKeyModal']/div/div[2]/div/form/div[2]/button").click()
        # 标识申请成功确认操作
        textelement = "/html/body/div[3]/div/div[2]/div[1]/p/div/div[2]"
        WebDriverWait(driver, 3).until(EC.text_to_be_present_in_element((By.XPATH, textelement), "申请请求提交成功,请等待审核!"))  # 等待确认文本出现
        driver.find_element_by_xpath("/html/body/div[3]/div/div[3]/button").click()


    def downIdentity(self, driver, pin):

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


    def holdIdentity(self, driver, reasion, pin):

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

    def unHoldIdentity(self, driver, reasion, pin):
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


    def updateIdentity(self, driver, pin):

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



    def revokeIdentity(self, driver, reasion, pin):

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


