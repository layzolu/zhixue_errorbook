import os
import sys
from typing import Pattern
import requests
from requests import utils
from requests import cookies
import json
from requests.api import head, request
import hashlib
from requests.models import Response
from requests.sessions import Session, session
import random
import time
import datetime

isVerifysslCert = True  # 需要调试请改为False

editheaders = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6'

}
global headerforerrbook
headerforerrbook = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.50',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
    'authbizcode': '100000000',
    'authtimestamp': '',
    'authguid': '',
    'authtoken': '',
    'XToken': 'null'
}

# rc4加密，来源于https://blog.csdn.net/shadow20112011/article/details/102873995


def bytesToHex(bytes):
    sb = ''
    for i in range(len(bytes)):
        hexs = hex(bytes[i] & 0xFF)[2:]
        if len(hexs) < 2:
            sb += '0'
        sb += hexs
    return sb


def hexToByte(inHex):
    hexlen = len(inHex)
    result = []
    if (hexlen % 2 == 1):
        hexlen += 1
        inHex = "0"+inHex
    for i in range(0, hexlen, 2):
        result.append(int(inHex[i:i+2], 16))
    return result


def initKey(aKey):
    state = list(range(256))
    bkey = [ord(i) for i in list(aKey)]
    index1 = 0
    index2 = 0
    if (len(bkey) == 0):
        return []
    for i in range(256):
        index2 = ((bkey[index1] & 0xff) + (state[i] & 0xff) + index2) & 0xff
        state[i], state[index2] = state[index2], state[i]
        index1 = (index1 + 1) % len(bkey)
    return state


def RC4Base(input, mKkey):
    x = 0
    y = 0
    key = initKey(mKkey)
    result = list(range(len(input)))
    for i in range(len(input)):
        x = (x + 1) & 0xff
        y = ((key[x] & 0xff) + y) & 0xff
        key[x], key[y] = key[y], key[x]
        xorIndex = ((key[x] & 0xff) + (key[y] & 0xff)) & 0xff
        result[i] = (input[i] ^ key[xorIndex])
    return result


def encryRC4Byte(data, key, chartSet='utf-8'):
    if not chartSet:
        bData = [ord(i) for i in data]
        return RC4Base(bData, key)
    else:
        bData = list(data.encode(chartSet))
        return RC4Base(bData, key)


def decryRC4(data, key, chartSet='utf-8'):
    r = RC4Base(hexToByte(data), key)
    return bytes(r).decode(chartSet)


def encryRC4String(data, key, chartSet='utf-8'):
    return bytesToHex(encryRC4Byte(data, key, chartSet))

# rc4加密方法结束


# 3-16 分割 补齐
def restart_program():
    python = sys.executable
    os.execl(python, python, * sys.argv)


def divideStringtoHex(str5):
    if len(str5) % 2 == 1:
        str1 = "0" + str5
    else:
        str1 = str5
    hexArray = []
    i = 0
    while (i < len(str1)):
        hexArray.append(str1[i:i+2])
        i += 2
    while (hexArray[0] == "00" or hexArray[0] == "0"):
        del hexArray[0]
    i = len(hexArray)-1
    while (i >= 0 and hexArray[i] == "00"):
        del hexArray[i]
        i -= 1
    return hexArray


patterner = "123456789abcde"


def paddind(fHexArray: list, keylen: int):
    if (len(fHexArray)) > keylen:
        print("密码过长，可能是智学网修改了算法")
        input("回车重启程序")
        restart_program()
    fHexArray.append("00")
    i = len(fHexArray)
    while (i <= keylen-3):
        appendstr = str(patterner[random.randint(0, 13)]) + \
            str(patterner[random.randint(0, 13)])
        fHexArray.append(appendstr)
        i += 1
    fHexArray.extend(["02", "00"])
    return fHexArray


def loginwithpwd(username, typepwd):
    # rc4-登陆
    weakpwdsession = requests.Session()
    password = encryRC4String(typepwd, "iflytzhixueweb", chartSet='utf-8')
    loginstatue = weakpwdsession.get(
        "https://www.zhixue.com/loginState/", verify=isVerifysslCert, headers=editheaders)
    casUrl = loginstatue.json()["casUrl"]
    serviceUrl = loginstatue.json()["serviceUrl"]
    #weakpwdsession.cookies = loginstatue.cookies
    weakpwdsession.cookies["loginUserName"] = username
    weaklogin = weakpwdsession.post("https://www.zhixue.com/weakPwdLogin/?from=web_login",
                                    verify=isVerifysslCert,
                                    headers=editheaders,
                                    data="loginName=" + username + "&password=" +
                                    password + "&code=&description=encrypt",
                                    cookies=weakpwdsession.cookies)
    resforweaklogin = weaklogin.json()
    if resforweaklogin["result"] == "success":
        print(resforweaklogin["data"])
        weakpwdsession.cookies["ui"] = resforweaklogin["data"]
    else:
        print("登陆失败："+resforweaklogin["message"])
        input("回车重启程序")
        restart_program()

    # rc4 登陆结束

    # 中央认证
    # 创建认证
    makeloginreq = weakpwdsession.post("https://www.zhixue.com/log/userActionLog/create",
                                       verify=isVerifysslCert,
                                       headers=editheaders, cookies=weakpwdsession.cookies,
                                       data="success=success&account=" + username + "&module=rq_web_login&opCode=1005&userId=" +
                                       resforweaklogin["data"] + "&sessionId=" +
                                       loginstatue.cookies["tlsysSessionId"]
                                       )
    if makeloginreq.json()["errorCode"] != 0:
        print("出错了！！\n响应码："+str(makeloginreq.json()["errorCode"]))
        input("回车重启程序")
        restart_program()

    # 获取LT
    centrallogin = requests.Session()
    LTres = centrallogin.get(
        casUrl+"sso/login?sso_from=zhixuesso&service=" + serviceUrl, verify=isVerifysslCert, cookies=centrallogin.cookies)

    LTrawtaext = LTres.text
    firstplace = int(LTrawtaext.find(r"('")+2)
    lastplace = int(LTrawtaext.rfind(r"')"))
    LTrawtaext = LTrawtaext[firstplace:lastplace]
    LTrawtaext = LTrawtaext.replace("\\", "")  # json化
    # print(LTrawtaext)
    LT_JSON = json.loads(LTrawtaext)
    # print(LT_JSON["data"]["lt"].encode().hex())
    LT = LT_JSON["data"]["lt"]
    execution = LT_JSON["data"]["execution"]
    # .encode().hex()
    # 构造RSA密码
    makepwd = str("LT/" + LT + "/" + typepwd).encode().hex()
    beforehexpwd = divideStringtoHex(makepwd)
    beforehexpwd = paddind(beforehexpwd, 128)
    beforehexpwd.reverse()
    makepwd = "".join(beforehexpwd)
    intpwd = int(makepwd, 16)
    encriedpwd = pow(intpwd, 65537, 143846244081099508648901372746659280006302505545479331274243675556721429123147854452215976399432374678014518658921467308832595550803689495835386150764953813095542106389384340697062624656038387147042232009506827653295712113445432238581040988464470584322208115885076367065603239952069923435605267625944018546121)
    #hexpwd = hex(encriedpwd)[2:]
    # 登陆
    Ticketreq = centrallogin.get(casUrl+"sso/login?sso_from=zhixuesso&service=" + serviceUrl +
                                 "&encode=true&sourceappname=tkyh%2Ctkyh&_eventId=submit&appId=zx-container-client&client=web&type=loginByNormal&key=auto&lt=" + LT + "&execution="+execution + "&customLogoutUrl=https%3A%2F%2Fwww.zhixue.com%2Flogin.html&ncetAppId=QLIqXrxyxFsURfFhp4Hmeyh09v6aYTq1&sysCode=&username=" + username + "&encodeType=R2%2FP%2FLT&password=" + hex(encriedpwd)[2:], verify=isVerifysslCert, cookies=centrallogin.cookies)
    stRawText = Ticketreq.text
    firstplace = int(stRawText.find(r"('")+2)
    lastplace = int(stRawText.rfind(r"')"))
    stRawText = stRawText[firstplace:lastplace]
    stRawText = stRawText.replace("\\", "")  # json化
    st_json = json.loads(stRawText)
    result = st_json["code"]
    if result == 1001:
        print("登陆成功")
        st_ticket = st_json["data"]["st"]
    else:
        print("登陆失败：" + "\n响应码：" + str(result) + "\n信息：" + st_json["message"])
        input("回车重启程序")
        restart_program()
    # 中央认证结束
    # 向智学网提交st
    verfiylogin = weakpwdsession.post(serviceUrl, data="action=login&ticket=" +
                                      st_ticket, verify=isVerifysslCert, cookies=weakpwdsession.cookies, headers=editheaders)
    if verfiylogin.text.index("success") != -1:
        print("登陆完成")

    timestamp = str(int(time.time() * 1000))
    getCurrentuser = weakpwdsession.get("https://www.zhixue.com/apicourse/web/getCurrentUser?token=&t=" +
                                        timestamp, verify=isVerifysslCert, headers=editheaders, cookies=weakpwdsession.cookies)

    userinfo = json.loads(getCurrentuser.text)
    if userinfo["errorCode"] == 0 and userinfo["errorInfo"] == "操作成功":
        print("获取用户信息成功！\n用户id：" + userinfo["result"]["currentUser"]
              ["loginName"]+"\n用户名：" + userinfo["result"]["currentUser"]["name"])
    else:
        print("登陆失败：" + "\n响应码：" +
              str(userinfo["errorCode"]) + "\n信息：" + userinfo["errorInfo"])
        input("回车重启程序")
        restart_program()
    # 获取用户信息结束
    return [weakpwdsession, userinfo["result"]["currentUser"]["loginName"], userinfo["result"]["currentUser"]["name"]]


def md5cacu(texts):
    hl = hashlib.md5()
    hl.update(texts.encode("utf-8"))
    return hl.hexdigest()


def makeauthtoken():
    authtimestamp = str(int(time.time() * 1000))
    authguid = ""
    i = 0
    while i < 36:
        authguid += patterner[random.randint(0, 13)]
        i += 1
    authguid = list(authguid)
    authguid[14] = "4"
    place = int(3 & int(authguid[19].encode().hex(), 16) | 8)
    authguid[19] = "0123456789abcdef"[place: place + 1]
    authguid[8] = authguid[13] = authguid[18] = authguid[23] = "-"
    authguid = "".join(authguid)
    authtoken = md5cacu(authguid+authtimestamp+"zxw?$%999userpwd")
    return [authtimestamp, authguid, authtoken]

# 获取Xtoken


def re_fresh_auth_token(heraders):
    authtoken = makeauthtoken()
    heraders["authtimestamp"] = authtoken[0]
    heraders["authguid"] = authtoken[1]
    heraders["authtoken"] = authtoken[2]


def getxtoken(session: Session):
    re_fresh_auth_token(headerforerrbook)
    resforindex = session.get("https://www.zhixue.com/addon/error/book/index",
                              verify=isVerifysslCert, headers=headerforerrbook, cookies=session.cookies)
    resforindex = resforindex.text
    resforindex = json.loads(resforindex)
    if resforindex["errorCode"] == 0:
        return resforindex["result"]
    else:
        print("登陆超时：" + "\n响应码：" +
              str(resforindex["errorCode"]) + "\n信息：" + resforindex["errorInfo"])
        input("回车重启程序")
        restart_program()


def timecovent(timestamp: str):
    timeArray = time.localtime(int(str(timestamp)[:-3]))
    otherStyleTime = time.strftime("%Y-%m-%d", timeArray)
    return otherStyleTime


def geterrorlists(session: Session, subject: str, begintime: str, endtime: str, subjectname: str):
    re_fresh_auth_token(headerforerrbook)
    rawrespond = session.get("https://www.zhixue.com/addon/app/errorbook/getErrorbookList?subjectCode=" +
                             subject+"&beginTime="+begintime+"&endTime="+endtime+"&pageIndex=1&pageSize=10", headers=headerforerrbook, verify=isVerifysslCert)
    rawrespond = json.loads(rawrespond.text)
    if rawrespond["errorCode"] != 0:
        print("登陆超时：" + "\n响应码：" +
              str(rawrespond["errorCode"]) + "\n信息：" + rawrespond["errorInfo"])
        input("回车重启程序")
        restart_program()
    pages: list = rawrespond["result"]["pageInfo"]["allPages"]
    if len(pages) == 0:
        print("无错题")
        exit()
    del pages[0]
    fstart = 0
    htmltext = "<p align=center style='text-align:center'><span style='font-size:22.0pt;mso-bidi-font-size:24.0pt'><strong>" + \
        username + "的" + subjectname + "错题本</strong></span></p><br>"
    processed = processerrorbook(rawrespond, fstart)
    htmltext += processed[0]
    fstart = processed[1]

    for page in pages:
        re_fresh_auth_token(headerforerrbook)
        rawrespond = session.get("https://www.zhixue.com/addon/app/errorbook/getErrorbookList?subjectCode=" +
                                 subject+"&beginTime="+begintime+"&endTime="+endtime+"&pageIndex=" + str(page) + "&pageSize=10", headers=headerforerrbook, verify=isVerifysslCert)
        rawrespond = json.loads(rawrespond.text)
        if rawrespond["errorCode"] != 0:
            print("登陆超时：" + "\n响应码：" +
                  str(rawrespond["errorCode"]) + "\n信息：" + rawrespond["errorInfo"])
            input("回车重启程序")
            restart_program()
        processed = processerrorbook(rawrespond, fstart)
        htmltext += processed[0]
        fstart = processed[1]
    return htmltext


def getsubject(session: Session):
    re_fresh_auth_token(headerforerrbook)
    rawrespond = session.get("https://www.zhixue.com/addon/app/errorbook/getSubjects",
                             headers=headerforerrbook, verify=isVerifysslCert)
    rawrespond = json.loads(rawrespond.text)
    subdict = {}
    if rawrespond["errorCode"] != 0:
        print("登陆超时：" + "\n响应码：" +
              str(rawrespond["errorCode"]) + "\n信息：" + rawrespond["errorInfo"])
        input("回车重启程序")
        restart_program()
    subjects = rawrespond["result"]["subjects"]
    for subject in subjects:
        subdict[str(subject["code"])] = str(subject["name"])
    for key, value in subdict.items():
        print('{key}:{value}'.format(key=key, value=value))
    return subdict


def writefile(aaaa, filename: str):
    with open(os.path.join(os.path.dirname(__file__), filename), "w+", encoding='utf-8') as f:
        f.write(str(aaaa))
        f.close()
    filepaths = os.path.join(os.path.dirname(__file__), filename)
    return filepaths


def processerrorbook(sourceerror, startfrom: int):
    before = "<p style='Margin:1px'><strong>第"
    errorbooklist = sourceerror["result"]["wrongTopics"]["list"]
    htmltext = ""
    questionlists = []
    analysislists = []
    useranswerlist = []
    answerlist = []
    source = []
    answertime = []
    questionorder = []
    subquestion = 0
    for question in errorbooklist:
        question = question["errorBookTopicDTO"]
        questionlists.append(question["contentHtml"].replace("\\", ""))
        analysislists.append(question["analysisHtml"].replace("\\", ""))
        answerlist.append(question["answerHtml"].replace("\\", ""))
        answertime.append(
            question["wrongTopicRecordArchive"]["userAnswerTime"])
        source.append(question["wrongTopicRecordArchive"]["topicSetName"])
        questionorder.append(question["order"])
        if "imageAnswers" in question["wrongTopicRecordArchive"]:
            useranswerlist.append(
                question["wrongTopicRecordArchive"]["imageAnswers"])
        else:
            useranswerlist.append(
                question["wrongTopicRecordArchive"]["userAnswer"])
    for i in range(0, len(questionlists)-1):
        if i != 0:
            if questionorder[i] == questionorder[i-1]:
                subquestion += 1
                htmltext += before + \
                    str(startfrom+questionorder[i]) + "-" + \
                    str(subquestion) + "题&nbsp;</srtong></p>"
            else:
                subquestion = 0
                htmltext += before + str(startfrom+questionorder[i]) + "题&nbsp;</srtong>来源：" + \
                    source[i] + "&nbsp;&nbsp;&nbsp;答题时间：" + \
                    timecovent(answertime[i]) + "</p>"
                htmltext += r"<p style='background:#DBDBDB;Margin:1px'><span style='font-size:14.0pt;color:green'>&nbsp;&nbsp;&nbsp;&nbsp;错题题目</span></p>"
                htmltext += questionlists[i]
        else:
            subquestion = 0
            htmltext += before + str(startfrom+questionorder[i]) + "题&nbsp;</srtong>来源：" + \
                source[i] + "&nbsp;&nbsp;&nbsp;答题时间：" + \
                timecovent(answertime[i]) + "</p>"
            htmltext += r"<p style='background:#DBDBDB;Margin:1px'><span style='font-size:14.0pt;color:green'>&nbsp;&nbsp;&nbsp;&nbsp;错题题目</span></p>"
            htmltext += questionlists[i]
        #htmltext += before+ str(startfrom)  +"题</srtong>来源：" + source[i] + "答题时间：" + timecovent(answertime[i]) + "</p>"

        htmltext += r"<p style='background:#DBDBDB;Margin:1px'><span style='font-size:12.0pt;color:green'>&nbsp;&nbsp;&nbsp;&nbsp;解析</span></p>"
        htmltext += analysislists[i]
        htmltext += r"<p style='background:#DBDBDB;Margin:1px'><span style='font-size:12.0pt;color:green'>&nbsp;&nbsp;&nbsp;&nbsp;我的答案</span></p>"
        if isinstance(useranswerlist[i], list):
            for pic in useranswerlist[i]:
                htmltext += "<img src=\""+pic+"\"><br>"
        else:
            htmltext += useranswerlist[i]
        htmltext += r"<p style='background:#DBDBDB;Margin:1px'><span style='font-size:12.0pt;color:green'>&nbsp;&nbsp;&nbsp;&nbsp;参考答案</span></p>"
        htmltext += answerlist[i]
        htmltext += "<br><br><br><br>"
    startfrom += questionorder[-1] - 1
    return [htmltext, startfrom]


print("欢迎使用智学网错题生成助手")
loginname = input("请输入用户名：")
loginpwd = input("请输入密码：")
loginrespond = loginwithpwd(loginname, loginpwd)
loginsession = loginrespond[0]
useruid = loginrespond[1]
username = loginrespond[2]
headerforerrbook["XToken"] = "null"
xtoken = getxtoken(loginsession)
headerforerrbook["XToken"] = xtoken
subjectdict = getsubject(loginsession)
subjectcode = input("请输入待生成学科的id：")
while not subjectcode in subjectdict:
    print("别瞎输入")
    subjectcode = input("请输入待生成学科的id：")
startdateraw = input("请输入起始时间，格式为yyyy/mm/dd，无需补0：")
global starttimestamp
global endtimestamp
flage = True
global recoginzedtime
global endrecoginzedtime
while flage:
    try :
        recoginzedtime = datetime.datetime.strptime(startdateraw, "%Y/%m/%d")
    except :
        startdateraw=input("时间格式错误，请重新输入")
        continue
    else:
        secondcheck = input(
            "识别到的数据为:" + recoginzedtime.strftime("%Y-%m-%d") + "是否正确?\n正确请留空，错误请重新输入")
        if secondcheck == "":
            flage = False
            starttimestamp = str(int(recoginzedtime.timestamp()) * 1000)
        else:
            startdateraw = secondcheck
# 以下其实为终止时间，变量名不想改了
enddateraw = input("请输入终止时间，留空为现在：")
if enddateraw == "":
    endtimestamp = str(int(time.mktime(time.localtime())) * 1000)
    endrecoginzedtime = datetime.datetime.now()
else:
    flage = True
    while flage:
        try :
            endrecoginzedtime = datetime.datetime.strptime(enddateraw, "%Y/%m/%d")
        except :
            enddateraw=input("时间格式错误，请重新输入")
            continue
        else:
            secondcheck = input(
                "识别到的数据为:" + endrecoginzedtime.strftime("%Y-%m-%d")+ "是否正确?\n正确请留空，错误请重新输入")
            if secondcheck == "":
                flage = False
                endtimestamp = str(int(endrecoginzedtime.timestamp()) * 1000)
            else:
                enddateraw = secondcheck
print("学科：" + subjectdict[subjectcode], "\n起始时间：", recoginzedtime.strftime(
    "%Y-%m-%d"), "\n终止时间：", endrecoginzedtime.strftime("%Y-%m-%d"))
print("正在获取数据")
htmltext = geterrorlists(loginsession, subjectcode,
                         starttimestamp, endtimestamp, subjectdict[subjectcode])
filepath = writefile(htmltext, username + "的" +
                     subjectdict[subjectcode] + "错题本" + str(time.mktime(time.localtime())) + ".html")
print("完成，保存在", filepath)
input()
