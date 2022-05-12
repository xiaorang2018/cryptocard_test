
class CodeLogin(object):
    """
    包括验证码、ukey2种登录形式
    """
    def sendCode(self, driver, user):
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]" \
                                     "/div[1]/form/div[1]/div/div/div/input").send_keys(user)
        driver.find_element_by_xpath("//*[@id='newEmailVerify']").click()

    def codeLogin(self, driver, code):
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]/div[2]" \
                                     "/div[1]/form/div[2]/div/div/div/input").send_keys(code)
        driver.find_element_by_xpath("//*[@id='app']/div[1]/div/div[1]/div[3]" \
                                     "/div[2]/div[1]/form/div[3]/div/button").click()










