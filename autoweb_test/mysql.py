import pymysql.cursors

class Mysql(object):
    """
    mysql连接以及相关操作
    """
    def __init__(self, host, port, user, password, db):

        self.conn = pymysql.connect(host=host,
                             port=port,
                             user=user,
                             password=password,
                             db=db
                             )
        if(self.conn == False):
            return -1


    def execQuery(self, sql):

        try:

            with self.conn.cursor() as cursor:
                # 读取单条记录
                cursor.execute(sql)
                result = cursor.fetchone()
                return result
        finally:
            self.conn.close()

