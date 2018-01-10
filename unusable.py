# _*_ coding: utf-8 _*_

import re
import base64
import requests
from PIL import Image
from bs4 import BeautifulSoup
from Crypto.Cipher import AES

headers = {
    'Host': 'apchina.net.cn',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:57.0) Gecko/20100101 Firefox/57.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded'
}


#密码加密
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


# def login():
#
#     req_with_session = requests.session()
#     login_session = requests.session()
#
#     # username = raw_input('请输入您的ETEST ID: ')
#     # passwd = raw_input('请输入您的ETEST ID 密码: ')
#     username = '1548983578@qq.com'
#     passwd = '123456test!'
#
#     def get_captcha():
#         captcha_url = "https://passport.etest.net.cn/CheckImage/LoadCheckImage"
#         image_url = re.findall('[a-zA-z]+://[^\s]*[$jpg]',req_with_session.post(captcha_url, verify=False).content)[0]
#         image_data = req_with_session.get(image_url, verify=False)
#         if not image_data:
#             return False
#         f = open('valcode.jpg', 'wb')
#         f.write(image_data.content)
#         f.close()
#         im = Image.open('valcode.jpg')
#         im.show()
#         captcha = raw_input('本次登录需要输入验证码： ')
#         return captcha
#
#
#     def ETEST_login():
#         request = req_with_session.get('https://passport.etest.net.cn/', verify=False)
#         raw_token = re.findall('<input name="__RequestVerificationToken".*/>', request.content)
#         token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace( '" />', "")
#         login_url = 'https://passport.etest.net.cn/'
#         data = {
#             '__RequestVerificationToken': token,
#             'txtUserName': username,
#             'txtPassword': passwd_encode(passwd),
#             'txtCheckImageValue': get_captcha(),
#             'hdnLoginMode': '',
#             'hdnReturnUrl': '',
#             'hdnRedirectUrl': '',
#             'HiddenAccessToken': '',
#             'HiddenPublicKeyExponent': 'As2Ssgk0AMikkiMA',
#             'HiddenPublicKeyModulus': 'Bt4GtgCAb5k99k5b',
#             'HiddenThirdCode': '',
#             'HiddenThirdName': '',
#             'HiddenSafe': ''
#         }
#         result = req_with_session.post(login_url, data=data, headers=headers, verify=False)
#         if '通行证ID' in result.content:
#             print('ETEST 登录成功, 准备跳转到APCHINA...')
#         else:
#             print (result.content)
#         result = req_with_session.get( 'https://passport.etest.net.cn/Manage/Jump?returnUrl=http://apchina.net.cn/Home/VerifyPassport/?LoginType=0&redirectUrl=&loginMode=0&safe=1',verify=False)
#         soup = BeautifulSoup(result.content, "html.parser")
#         global data
#         for name in soup.find_all('input'):
#             key = name.get('name')
#             value = name.get('value')
#             data[key] = value
#         print data
#         return data
#
#     def APCHINA_login():
#         ETEST_login()
#         result = login_session.post('http://apchina.net.cn/Home/VerifyPassport/?LoginType=0', data=data)
#         if "允许报名生日" in result.content:
#             print('login success!')
#         else:
#             print result.content
#         raw_sid = re.findall('\'[0-9a-zA-Z]{32}\'', result.content)
#         sid = raw_sid[0].replace("'", "")
#
#
#     APCHINA_login()
#
# login()
req_with_session = requests.session()
login_session = requests.session()

# username = raw_input('请输入您的ETEST ID: ')
# passwd = raw_input('请输入您的ETEST ID 密码: ')
username = '1548983578@qq.com'
passwd = '123456test!'

class login:
    def get_captcha(self):
        captcha_url = "https://passport.etest.net.cn/CheckImage/LoadCheckImage"
        image_url = re.findall('[a-zA-z]+://[^\s]*[$jpg]', req_with_session.post(captcha_url, verify=False).content)[0]
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

    def ETEST_login(self):
        request = req_with_session.get('https://passport.etest.net.cn/', verify=False)
        raw_token = re.findall('<input name="__RequestVerificationToken".*/>', request.content)
        token = raw_token[0].replace('<input name="__RequestVerificationToken" type="hidden" value="', '').replace(
            '" />', "")
        login_url = 'https://passport.etest.net.cn/'
        data = {
            '__RequestVerificationToken': token,
            'txtUserName': username,
            'txtPassword': passwd_encode(passwd),
            'txtCheckImageValue': login.get_captcha(self),
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
        if '通行证ID' in result.content:
            print('ETEST 登录成功, 准备跳转到APCHINA...')
        else:
            print (result.content)
        result = req_with_session.get(
            'https://passport.etest.net.cn/Manage/Jump?returnUrl=http://apchina.net.cn/Home/VerifyPassport/?LoginType=0&redirectUrl=&loginMode=0&safe=1',
            verify=False)
        soup = BeautifulSoup(result.content, "html.parser")
        for name in soup.find_all('input'):
            key = name.get('name')
            value = name.get('value')
            data[key] = value
        print data
        return data

    def APCHINA_login(self):
        login.ETEST_login(self)
        result = login_session.post('http://apchina.net.cn/Home/VerifyPassport/?LoginType=0', data=data)
        if "允许报名生日" in result.content:
            print('login success!')
        else:
            print result.content
        raw_sid = re.findall('\'[0-9a-zA-Z]{32}\'', result.content)
        sid = raw_sid[0].replace("'", "")

user = login()

user.APCHINA_login()
