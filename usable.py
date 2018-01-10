# _*_ coding: utf-8 _*_

from bs4 import BeautifulSoup
import requests
import base64
from Crypto.Cipher import AES
import re
from PIL import Image
import time

req_with_session = requests.session()

def passwd_encode(raw_pass):
    key = 'As2Ssgk0AMikkiMA'
    IV = 'Bt4GtgCAb5k99k5b'
    mode = AES.MODE_CBC
    pad = 16 - len(raw_pass) % 16
    raw_pass = raw_pass + pad * chr(pad)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    encrypt_text = encryptor.encrypt(raw_pass)
    encrypt_text = base64.b64encode(encrypt_text)
    #print encrypt_text
    return encrypt_text

def get_captcha():
    """
    获取验证码本地显示
    返回你输入的验证码
    """
    captcha_url = "https://passport.etest.net.cn/CheckImage/LoadCheckImage"
    # 获取验证码也用同一个opener
    #image_data = req_with_session.post(captcha_url)
    #print (req_with_session.post(captcha_url, verify=False).content)
    image_url = re.findall('[a-zA-z]+://[^\s]*[$jpg]',req_with_session.post(captcha_url, verify=False).content)[0]
    #print (image_url)
    # 系统繁忙
    image_data = req_with_session.get(image_url, verify=False)
    #print (image_data)
    if not image_data:
        return False
    f = open('valcode.jpg', 'wb')
    f.write(image_data.content)
    f.close()
    im = Image.open('valcode.jpg')
    im.show()
    captcha = raw_input('本次登录需要输入验证码： ')
    return captcha

request = req_with_session.get('https://passport.etest.net.cn/', verify=False)
raw_token = re.findall('<input name="__RequestVerificationToken".*/>', request.content )
token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="','').replace('" />',"")


headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36',
           "Host": "passport.etest.net.cn",
           "Referer": "https://passport.etest.net.cn/LoginIframe.aspx?ReturnUrl=http://apchina.net.cn/Home/VerifyPassport/?LoginType=0&safe=1",
           }

username = '1548983578@qq.com'
passwd = '123456test!'

login_url = 'https://passport.etest.net.cn/'
data = {
    '__RequestVerificationToken': token,
    'txtUserName': username,
    'txtPassword': passwd_encode(passwd),
    'txtCheckImageValue': get_captcha(),
    'hdnLoginMode': '',
    'hdnReturnUrl': '',
    'hdnRedirectUrl': '',
    'HiddenAccessToken': '',
    'HiddenPublicKeyExponent': 'As2Ssgk0AMikkiMA',
    'HiddenPublicKeyModulus': 'Bt4GtgCAb5k99k5b',
    'HiddenThirdCode': '',
    'HiddenThirdName': '',
    'HiddenSafe': ''
}

result = req_with_session.post(login_url, data=data, headers=headers, verify=False)
result = req_with_session.get('https://passport.etest.net.cn/Manage/Jump?returnUrl=http://apchina.net.cn/Home/VerifyPassport/?LoginType=0&redirectUrl=&loginMode=0&safe=1', verify=False)
#print result.content

soup = BeautifulSoup(result.content, "html.parser")
for name in soup.find_all('input'):
    key = name.get('name')
    value= name.get('value')
    data[key] = value
#print data

login_session = requests.session()
headers = {
    'Host': 'apchina.net.cn',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded'
}
result = login_session.post('http://apchina.net.cn/Home/VerifyPassport/?LoginType=0',data=data)
# print result.content
# if "允许报名生日" in result.content:
#     print('login is okay')
raw_sid = re.findall('\'[0-9a-zA-Z]{32}\'', result.content)
sid = raw_sid[0].replace("'", "")

#def choice_subject():
result = login_session.get('http://apchina.net.cn/Student')
# index_parse = BeautifulSoup(result.content, "html.parser")
# token = index_parse.input['value']
raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content )
token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="','').replace('" />',"")
data = {
    '__RequestVerificationToken': token,
    'sid': sid
}
result = login_session.post('http://apchina.net.cn//Student/Detail', data=data)
# print result.content
#已进入信息页
#开始进入修改资料页面
raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content )
token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="','').replace('" />',"")
data = {
    '__RequestVerificationToken': token,
    'sid': sid
}
result = login_session.post('http://apchina.net.cn/Student/BaseInfo', data=data, headers=headers)
# print result.content
#资料页面进入完毕
#报名
##查询考位
# print result.content
raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content )
token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="','').replace('" />',"")
#print token
data = {
    'schoolcode': 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    'tccode': '996952'
}
result = login_session.post('http://apchina.net.cn/CodeTable/GetSubjectInfoByTCCodeAndSchoolCode', data=data, headers=headers)
# print result.content.decode('utf-8')

raw_calculus_code = re.findall('[0-9a-zA-Z]{32}_130', result.content )[1]
#print raw_calculus_code

data = {
    'sid': sid,
    'vIDType': '1',
    'vID': '330102200001013737',
    'vIDExpiration': '2025-01-01',
    'vLastNameCN': '姓',
    'vFirstNameCN': '名',
    'vLastNamePY': 'XING',
    'vFirstNamePY': 'ming',
    'vGender': '1',
    'vBirthDate': '2000-01-01',
    'vBirthplace': '杭州',
    'vNativePlace': '杭州',
    'vCountry': 'MAC',
    'vProvince': '36',
    'vSchoolCode': 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    'vGradeLevel': '1',
    'IsSocialCandidate': 't',
    'vHighSchool': '就读学校',
    'vTrainMode': '1',
    'IsOutSchoolTraining': 't',
    'vTrainSchool': '培训学校',
    'vMailingAddress': '邮寄地址',
    'vPostalCode': '310000',
    'vEmail': 'youxiang@example.com',
    'vTelAreaCode': '',
    'vTelNumber': '',
    'vFaxAreaCode': '',
    'vtFaxNumber': '',
    'vMobileNumber': '15397132032',
    'vGuardianName': '监护人名字',
    'vGuardianWorkUnit': '监护人工作单位',
    'vRelationship': '与监护人关系',
    'vGuardianMobileNumber': '15397132032',
    'vTestCenter': '996952',
    't_sStr': raw_calculus_code ,
    '__RequestVerificationToken': token
}

result = login_session.post('http://apchina.net.cn/Student/Save', data=data, headers=headers, allow_redirects= True, verify=False)

print(result.content)
