# zhixue_errorbook
智学网错题生成器

#需要引用的库
  os,sys,typing,requests,json,hashlib,random,time,datetime

#使用方法
简单易用，下载errorbook.py，输入用户名和密码，根据提示选择学科的id，输入起止时间，等待，将会在当前目录下放置生成好的html文档，可用浏览器打开打印，也可以用word打开。

#Tip
需要研究网络传输的小伙伴在开头有个变量isVerifysslCert，可以指定是否验证证书有效性。
如果软件报SSLError的话也请把这个变量改为False

#致谢
https://blog.csdn.net/shadow20112011/article/details/102873995  ---   rc4加密
