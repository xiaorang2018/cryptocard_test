import requests

class UkeyManager(object):

    def __init__(self):
        # 获取用户列表
        url = "http://127.0.0.1:4433/SOF_GetUserList? "
        response = requests.post(url)
        # UKey登录
        url = "http://127.0.0.1:4433/SOF_Login?"
        parameter = {
            "appName": "dmsUK",
            "passWd": "12345678"
        }
        response = requests.get(url, params=parameter)


    def delete_application(self):
        url = "http://127.0.0.1:4433/SOF_DeviceReset?"
        parameter = {
            "appName": "dmsUK"
        }
        response = requests.get(url, params=parameter)
        print(response)  # <Response [200]>
        print(response.text)  # Json格式



