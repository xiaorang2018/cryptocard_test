#!/bin/bash
echo -e '\033[1;31m ********************************此脚本自动化安装JDK1.8_101******************************** \033[0m'
echo -e "\033[1;31m 1.创建jdk路径 \033[0m"
jdkdir="/usr/local/jdk"
if [ ! -d "${jdkdir}" ];then
  mkdir -p ${jdkdir}
fi
echo -e "\033[1;31m 2.解压Jdk的tar包 \033[0m"
var1=jdk-8u101-linux-x64.tar.gz
var2=$(pwd)
jdktar="${var2}/${var1}"
if [ -n "$1" ];then
 jdktar=$1
fi

tar -zxf ${jdktar} -C ${jdkdir}

jdk_file=$(ls $jdkdir/ -l| awk '/^d/{print $NF}')
jdk_home=$jdkdir/$jdk_file

echo -e "\033[1;31m 3.配置环境变量 \033[0m"
echo "export JAVA_HOME=${jdk_home}" >>/etc/profile
echo "export CLASSPATH=\$JAVA_HOME/lib" >> /etc/profile
echo "export PATH=\$PATH:\$JAVA_HOME/bin" >> /etc/profile

echo -e "\033[1;31m 4.环境变量生效 \033[0m"
source /etc/profile

echo -e "\033[1;31m 5.查看jdk安装版本 \033[0m"
java -version