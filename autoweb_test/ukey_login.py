from ahdms.logger import Logger
logger = Logger(logger = "UkeyLogin").getLog()

class UkeyLogin(object):
    """
    ukey登录RA
    """
    def __init__(self, driver):
        self.driver =  driver
        self.driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[1]/div[2]").click()
        mes = self.driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[2]/form/div[1]/div").text
        while mes == "请插入UKey":
            if self.driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[2]/form/div[1]/div").text == "UKey已插入":
                break
            print("请插入要操作的UKey")

    def ukey_login(self, pin):
        self.driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[2]/form/div[2]/div/div/div[1]/input").send_keys(pin)
        self.driver.find_element_by_xpath("//*[@id='UKeyLogin']").click()
