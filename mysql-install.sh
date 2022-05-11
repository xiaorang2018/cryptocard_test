#!/bin/bash
#==================== 安装mysql =========================

#行43~62主要用于彻底卸载mysql文件，新机器安装没有意义
yum -y remove mysql mysql-devel mysql-server mysql-libs compat-mysql51
data=`rpm -aq | grep -i mysql*`
rpm -e $data
rm -rf /var/lib/mysql
rm /etc/my.cnf

cd /var/lib/
rm -rf mysql/
rm -rf /var/lib/mysql

rm -rf /usr/lib64/mysql
rm -rf /usr/lib/mysql
rm -rf /usr/share/mysql

rm -rf /usr/my.cnf
rm -rf /root/.mysql_sercret
rm -rf /var/log/mysqld.log

chkconfig --list | grep -i mysql
chkconfig --list | grep -i mysql

#卸载系统自带的mariadb数据库
mariadb=`rpm -qa|grep mariadb`

if [ -f $mariadb ]
then
	rpm -e $mariadb --nodeps
else
	echo mariadb is not existed!
fi

#安装mysql
net_tools=`rpm -qa|grep net-tools*`
if [ ! -f ${net_tools} ]
then
         echo net-tools is installed!
else
         yum -y install net-tools
          echo net-tools install successfully!
fi

mysql_dir=/root/soft/
mysql_file=()
j=0
for i in `ls $mysql_dir | grep mysql*`
do
	mysql_file[j]=$i
	j=$[j+1]
done
echo 数组的元素为:${mysql_file[*]}
cd /root/soft
rpm -ivh ${mysql_file[*]} 

expect=`rpm -qa|grep expect`
if [ -f expect ]
then
	echo expect is existed!
else
	yum -y install expect
fi

#数据库初始化
mysqld --initialize --user=mysql
password=`grep 'temporary password' /var/log/mysqld.log | awk '{print $NF}'`
echo $password
echo .....................................................................
newpassword=AHdms520

systemctl start mysqld
/usr/bin/expect << EOF
set timeout 30
spawn mysql -u root -h 127.0.0.1 -p
expect "*password:"
send "$password\r"
expect "mysql>"
send "ALTER USER 'root'@'localhost' IDENTIFIED BY '$newpassword';\r"
send  "show databases;\r"
send  "exit;\r"
expect EOF
EOF

firewall-cmd --zone=public --add-port=3306/tcp --permanent
firewall-cmd --reload
firewall-cmd --zone=public --query-port=3306/tcp

/usr/bin/expect << EOF
spawn mysql -u root -h 127.0.0.1 -p
expect "*password:"
send "$newpassword\r"
expect "mysql>"
send "use mysql;\r"
send "update user set host='%' where user='root';\r"
send "select host, user from user;\r"
send "FLUSH PRIVILEGES;\r"
send "exit;\r"
expect EOF
EOF

