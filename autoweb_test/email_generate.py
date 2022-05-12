import  random

class RandomEmail(object):
    def random_email(self, email_type=None, rang=None):
        default_email_type = ["@qq.com", "@163.com", "@126.com", "@189.com"]
        #如果没有指定邮箱类型，默认在中default_email_type列表中随机一个
        if email_type == None:
            email_type = random.choice(default_email_type)
        else:
            email_type = email_type
        #如果没有指定邮箱长度，默认在4-10之间随机
        if  rang == None:
            rang = random.randint(4, 10)
        else:
            rang = int(rang)
        number = "0123456789qbcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPWRSTUVWXYZ"
        random_number = "".join(random.choice(number) for i in range(rang))
        email = random_number + email_type

        return email

