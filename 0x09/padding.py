import urllib.request
import ssl
import http.cookiejar
ssl._create_default_https_context = ssl._create_unverified_context

cj = http.cookiejar.CookieJar()  
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))  
r = opener.open('https://edu-ctf.csie.org:10190/login.php')
for i in cj:
    print(i.name)

#response = urllib.request.urlopen('https://edu-ctf.csie.org:10190/party.php')
#print(response.read().decode('utf-8'))

def get_cookie():
    # 声明一个CookieJar对象实例来保存cookie
    cookie = cookiejar.CookieJar()
    # 利用urllib.request库的HTTPCookieProcessor对象来创建cookie处理器,也就CookieHandler
    handler=request.HTTPCookieProcessor(cookie)
    # 通过CookieHandler创建opener
    opener = request.build_opener(handler)
    # 此处的open方法打开网页
    response = opener.open('https://edu-ctf.csie.org:10190')
    # 打印cookie信息
    for item in cookie:
        print('Name = %s' % item.name)
        print('Value = %s' % item.value)

"pMCWByG/IksdxGG0XfG6INHg1436FKcm6hk10c7l6TwgMHJ7Q65YeFU0Vvtt64sowwzgA2FevKvhNfAHF0eVehjf/n5wPI4xQmVg23n/5uGUbSRHYvIq5nYqlrH6KY74"
a = "CbN9PgfVXAqvUFZxVttez/S7vYGID0CsAuDJw/szqRyOFbo/qbf3n6LEENHZI5AlxqZth9WvV69tYbUzHLs396Hiv6jNbV0bHtGl+AJLqMeJGmEbiMcRgyNRZg/R+rIp"
print(a[-8:])
print(a[-16:-8])
print(ord('R'))

for i in range(3,4):
    print(chr(ord('N')^i))
    print(chr(ord('R')^i))
    