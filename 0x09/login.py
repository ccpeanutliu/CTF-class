import urllib2  
import urllib 
import ssl
import cookielib 
def renrenBrower(url,user,password):
    login_page = "https://edu-ctf.csie.org:10190/login.php"  
    try: 

        ssl._create_default_https_context = ssl._create_unverified_context
        cj = cookielib.CookieJar()  
        opener=urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        opener.addheaders = [('User-agent','Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')]
        data = urllib.urlencode({"user":user,"pass":password}) 
        opener.open(login_page,data)
        op=opener.open(url)
        data= op.read()  
        return cj
    except Exception,e:  
        print str(e)  
a = renrenBrower("https://edu-ctf.csie.org:10190/","impeanut","jizz7122")
for i in a:
    print("%s: %s" %(i.name,i.value))