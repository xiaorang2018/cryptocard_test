from selenium import webdriver

class BrowserEngine(object):


    def getBrowser(self):
        driver = webdriver.Chrome()
        #driver = webdriver.Firefox()
        driver.maximize_window()
        driver.implicitly_wait(2)

        return driver