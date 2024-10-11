# TXEHR----
同享TXEHR V15人力管理管理平台hdlUploadFile存在任意文件上传漏洞检测工具
![图片](https://github.com/user-attachments/assets/a3376bd9-4603-4e13-8dc4-be5428b23b3b)

```shell
漏洞描述：
智慧校园(安校易)管理系统 FileUpAd.aspx 接口处存在任意文件上传漏洞，未经身份验证的攻击者通过漏洞上传恶意后门文件，执行任意代码，从而获取到服务器权限。

fofa搜素语句:
title="智慧综合管理平台登入"

工具利用：
"-u", "--url",指定检测url
"-f", "--file"，指定批量检测漏洞的文件
 "-h","--help"，获取帮助信息

直接运行脚本获取帮助信息
检测成功的url会被输出至同目录下的upload.txt文件中
```
