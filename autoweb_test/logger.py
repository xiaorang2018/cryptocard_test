import logging
import os.path
import time

class Logger(object):

    def __init__(self,logger):
        """
        指定保存日志的文件路径，日志级别，以及调用的文件将日志存入到指定的文件中
        """

        #创建一个logger
        self.logger=logging.getLogger(logger)
        self.logger.setLevel(logging.DEBUG)

        #创建一个handler，用于写入日志文件
        rq=time.strftime('%Y%m%d',time.localtime())
        log_path = os.path.dirname(os.path.abspath('.')) + '/log/'
        log_name=log_path+rq+'.log'
        fh=logging.FileHandler(log_name,encoding='utf-8')
        fh.setLevel(logging.ERROR)

        #再创建一个handler，用于输出控制台
        ch=logging.StreamHandler()
        ch.setLevel(logging.INFO)


        #定义handler的输出格式
        formatter=logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        #给logger添加handler
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def getLog(self):
        return self.logger

