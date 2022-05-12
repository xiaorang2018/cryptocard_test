
class Register(object):

    def registerSendCode(self, driver, phoneEmail):
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[3]/a").click()
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[1]/form/"\
                                     "div[2]/div/div/div[1]/input").send_keys(phoneEmail)
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[1]/form/div[4]/button").click()

    def register(self, driver, code):
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[2]/form/div[2]/div/div/div/input").send_keys(code)
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]/div[2]/form/div[4]/button").click()



