#!/bin/bash

#设置密码主管可信标识的CN
read -p "please input device master_key_cn:" master_key_cn
echo $master_key_cn

#设置设备厂商名字
read -p "please input device company(Enter skip [北京迪曼森有限公司长沙分公司]):" company 
if [ -z "${company}" ];then
	company="北京迪曼森有限公司长沙分公司"
fi
echo $company

#设置设备类型
read -p "please input device type(Enter skip [服务器密码机]):" dev_type
if [ -z "${dev_type}" ];then
	dev_type="服务器密码机"
fi
echo $dev_type

#设置设备型号
read -p "please input device model(Enter skip [DMS-MMJ-3000.1]):" model 
if [ -z "${model}" ];then
	model="DMS-MMJ-3000.1"
fi
echo $model

#设置设备序列号
read -p "please input device serial_no(formate 2021041500100001):" serial_no
if [ -z "${serial_no}" ];then
	serial_no="2021041500100001"
fi
echo $serial_no


password=AHdms520

/usr/bin/expect << EOF
set timeout 30
spawn mysql -u root -h 127.0.0.1 -p
expect "*password:"
send "$password\r"
expect "mysql>"
send "use cm;\r"
send "update config_info set value='$master_key_cn' where sortID='superRole';\r"
send "update config_info set value='$company' where nodeID='manufacturer';\r"
send "update config_info set value='$dev_type' where nodeID='type';\r"
send "update config_info set value='$model' where nodeID='model';\r"
send "update config_info set value='$serial_no' where nodeID='serNumber';\r"
send "exit;\r"
expect EOF
EOF




