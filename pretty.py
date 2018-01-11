# _*_ coding: utf-8 _*_

import re
import base64
import requests
from PIL import Image
from bs4 import BeautifulSoup
from Crypto.Cipher import AES

req_with_session = requests.session()
login_session = requests.session()

def passwd_encode(raw_pass):
    key = 'As2Ssgk0AMikkiMA'
    IV = 'Bt4GtgCAb5k99k5b'
    mode = AES.MODE_CBC
    pad = 16 - len(raw_pass) % 16
    raw_pass = raw_pass + pad * chr(pad)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    encrypt_text = encryptor.encrypt(raw_pass)
    encrypt_text = base64.b64encode(encrypt_text)
    return encrypt_text

def get_captcha():
    captcha_url = "https://passport.etest.net.cn/CheckImage/LoadCheckImage"
    image_url = re.findall('[a-zA-z]+://[^\s]*[$jpg]',req_with_session.post(captcha_url, verify=False).content)[0]
    image_data = req_with_session.get(image_url, verify=False)
    if not image_data:
        return False
    f = open('valcode.jpg', 'wb')
    f.write(image_data.content)
    f.close()
    im = Image.open('valcode.jpg')
    im.show()
    captcha = raw_input('本次登录需要输入验证码： ')
    return captcha

def get_certificate():
    result  = req_with_session.get('https://passport.etest.net.cn/', verify=False)
    raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content)
    token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace('" />', "")
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36',
               "Host": "passport.etest.net.cn",
               "Referer": "https://passport.etest.net.cn/LoginIframe.aspx?ReturnUrl=http://apchina.net.cn/Home/VerifyPassport/?LoginType=0&safe=1",
               }
    username = raw_input('请输入您的账号')
    passwd = raw_input('请输入您的密码')
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
    if "通行证ID" in result.content:
        print('ETEST 通行证正确')
        result = req_with_session.get( 'https://passport.etest.net.cn/Manage/Jump?returnUrl=http://apchina.net.cn/Home/VerifyPassport/?LoginType=0&redirectUrl=&loginMode=0&safe=1',verify=False)
        soup = BeautifulSoup(result.content, "html.parser")
        for name in soup.find_all('input'):
            key = name.get('name')
            value = name.get('value')
            data[key] = value
        return data
    else:
        print ('请确认验证码以及通行证信息是否正确')
        return False

def fill_agree():
    headers = {
        'Host': 'apchina.net.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    result = login_session.get('http://apchina.net.cn/Student/Agreement')
    raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content)
    token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace('" />', "")
    data = {
        '__RequestVerificationToken':token,
        'sign': '1'
    }
    result = login_session.post('http://apchina.net.cn/Student/BaseInfo', data=data, headers=headers)
    if '考生报名表' in result.content:
        print('初始化成功')
        raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content)
        token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace('" />', "")
        return token
    else:
        print('初始化失败')
        print(result.content)


def APCHINA_login(data):
    headers = {
        'Host': 'apchina.net.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    result = login_session.post('http://apchina.net.cn/Home/VerifyPassport/?LoginType=0', data=data)
    global sid
    raw_sid = re.findall('\'[0-9a-zA-Z]{32}\'', result.content)
    if raw_sid:
        print ('获得APCHINA-SID成功')
        print login_session.cookies
        sid = raw_sid[0].replace("'", "")
        return True
    elif '开始报名' in result.content:
        print('检测到您是第一次登录，下面自动帮您完成初始化操作')
        return False

def get_in_index():
    headers = {
        'Host': 'apchina.net.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    result = login_session.get('http://apchina.net.cn/Student')
    if '允许报名生日' in result.content:
        print('登录APCHINA成功')
    else:
        print('登录APCHINA失败')
    raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content)
    token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace('" />',"")
    data = {
        '__RequestVerificationToken': token,
        'sid': sid
    }
    result = login_session.post('http://apchina.net.cn/Student/Detail', data=data)
    if '证件有效期' in result.content:
        print('进入个人信息页面成功')
    else:
        print('进入个人信息页面失败')
    raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content)
    token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace('" />',"")
    data = {
        '__RequestVerificationToken': token,
        'sid': sid
    }
    result = login_session.post('http://apchina.net.cn/Student/BaseInfo', data=data, headers=headers)
    if '考生报名表' in result.content:
        print('进入报名科目界面成功')
    else:
        print('进入报名科目界面失败')
    raw_token = re.findall('<input name="__RequestVerificationToken".*/>', result.content)
    token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace('" />',"")
    return token

def get_subject_code():
    headers = {
        'Host': 'apchina.net.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'schoolcode': 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        'tccode': raw_input('请输入您想报名的学校ID')
    }
    result = login_session.post('http://apchina.net.cn/CodeTable/GetSubjectInfoByTCCodeAndSchoolCode', data=data, headers=headers)
    raw_calculus_code = re.findall('[0-9a-zA-Z]{32}_130', result.content)[1]
    if raw_calculus_code:
        print('获取微积分科目报名编码成功')
        return  raw_calculus_code
    else:
        print('获取微积分科目报名编码失败')

def choice_subject(token, code):
    headers = {
        'Host': 'apchina.net.cn',
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'sid': '',
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
        'vTestCenter': raw_input('请再次确认您要选择的考试中心代码'),
        't_sStr': code,
        '__RequestVerificationToken': token
    }
    if 'sid' in dir():
        data['sid'] = sid
    result = login_session.post('http://apchina.net.cn/Student/Save', data=data, headers=headers, allow_redirects=True, verify=False)
    if '"ExceuteResultType":1' in result.content:
        print('恭喜你报名成功,快跳起来给你的小哥哥一个么么哒吧！')
    else:
        print('报名出现问题，问题为')
        print(result.content)



if APCHINA_login(get_certificate()):
    choice_subject(get_in_index(),get_subject_code())
else:
    choice_subject(fill_agree(), get_subject_code())
