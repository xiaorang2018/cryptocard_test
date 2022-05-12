import random
class GenerateRandom(object):
    """
    生成一个指定长度的随机数
    """
    def generateRandom(self, randomlength):
        random_str = ""
        base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefgh' \
                   'igklmnopqrstuvwxyz0123456789_-.@'
        length = len(base_str)-1
        for i in range(randomlength):
            random_str += base_str[random.randint(0, length)]

        return random_str