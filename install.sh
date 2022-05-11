#!/bin/bash

#创建数据库
#cd sql
#sh creat_cm_db.sh
#cd ..

#创建目录
if [ ! -d "/usr/local/cm/" ]; then
	mkdir /usr/local/cm/
	echo "mkdir  /usr/local/cm/ success!"
fi

if [ ! -d "/usr/local/cm/cm_manage_init" ]; then
	mkdir /usr/local/cm/cm_manage_init
	echo "mkdir  /usr/local/cm/cm_manage_init success!"
fi

if [ ! -d "/usr/local/software_check/" ]; then
	mkdir /usr/local/software_check/
	echo "mkdir  /usr/local/software_check/ success!"
fi


#放置白名单
if [ ! -f "/usr/local/cm/ipList.txt" ]; then
  	cp ipList.txt /usr/local/cm/
	echo "cp ipList.txt success!"
fi

#放置公钥矩阵
if [ ! -f "/usr/local/cm/cm_manage_init/pkm.cer" ]; then
  	cp pkm/pkm.cer /usr/local/cm/cm_manage_init
	echo "cp pkm.cer success!"
fi

#放置软件包消息签名值
if [ ! -f "/usr/local/software_check/manageServerSign" ]; then
  	cp software_check/manageServerSign /usr/local/software_check/
fi
if [ ! -f "/usr/local/software_check/gmServerSign" ]; then
  	cp software_check/gmServerSign /usr/local/software_check/
fi

#放置管理系统后台服务
if [ ! -d "/usr/local/service" ]; then
	cp -r service /usr/local
        echo "cp service to /usr/local/service success!"
else
	cp service/* /usr/local/service/ -rf
	echo "cp service/* to /usr/local/service/ success!"
fi

#注册管理服务开机启动
sh register.sh /etc/rc.local "sh /usr/local/service/cmService.sh &"
chmod +x /etc/rc.local
