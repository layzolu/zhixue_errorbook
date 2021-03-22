# zhixue_errorbook
智学网错题生成器  
 
## 注意：  
此项目使用Python3.8.7构建，不兼容Python2  

## 需要引用的库  
  os,sys,typing,requests,json,hashlib,random,time,datetime  
 其中，requests库可能python没有预装，可以在终端内使用指令`pip install requests==2.6.0`安装（新版本理论也行，我用的2.6.0）  

## 使用方法    
* 安装Python3环境（我使用的是Python3.8.7）  
* 下载，运行errorbook.py  
* 输入用户名和密码登陆  
* 根据提示选择学科的id  
* 输入起止时间  
* 等待  
* 完成后将会在当前目录下放置生成好的html文档，可用浏览器打开，并使用CTRL+P键进行打印，也可以用word打开。  
  
## Tip  
为需要研究网络传输的小伙伴开头留下变量isVerifysslCert，可以指定是否验证证书有效性。  
如果软件报SSLError的话也请把这个变量改为False  

## 国内gitee镜像地址  
https://gitee.com/w2016561536/zhixue_errorbook
  
## 致谢  
https://blog.csdn.net/shadow20112011/article/details/102873995  ---   rc4加密  
