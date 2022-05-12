import pymysql

class Mysql(object):
    """
    mysql连接以及相关操作
    """
    def __init__(self, host, user, pwd, db):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.db = db
        self.conn = self.getConnect()
        if(self.conn):
            self.cur = self.conn.cursor()


    def getConnect(self):
        conn = False
        try:
            conn = pymysql.connect(
                self.host,
                self.user,
                self.pwd,
                self.db
            )
        except Exception as err:
            print("连接数据库失败，%s"% err)
        else:
            return conn

    def execQuery(self, sql):
        res = ""
        try:
            self.cur.execute(sql)
            res = self.cur.fetchall()
            self.conn.close()
        except Exception as err:
            print("执行失败，%s"% err)
        else:
            return res

