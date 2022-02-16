import requests
import re
import sys

class Klab(object):
	def __init__(self,user,pasw):
		self.user=user
		self.pasw=pasw
		self.s=requests.session()
		self.s.verify=False
		self.token=None
		self.s.headers.update({'sec-ch-ua-platform':'"Windows"','Upgrade-Insecure-Requests':'1','User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'})
		if 'win' in sys.platform:
			self.s.proxies.update({'http': 'http://127.0.0.1:8888','https': 'https://127.0.0.1:8888',})
		res=self.doLogin()
		self.getToken(res)
		
	def giveMeToken(self):
		return self.token
		
	def doLogin(self):
		self.s.get('https://www.id.klabgames.net/auth?redirect_uri=jp%2eklab%2ebbs%3a%2f%2fklab_id%2fcallback&response_type=code&state=gnqgi5jhvxv5a6k2&client_id=bleach-gl&scope=transfer_user_data&lang=en')
		return self.s.post('https://www.id.klabgames.net/login',data={'email':self.user,'password':self.pasw})
	
	def getToken(self,r):
		token=re.search('<input type="hidden" name="token" value="(.*)">',r.content).group(1)
		r=self.s.post('https://www.id.klabgames.net/allow',data={'token':token},allow_redirects=False)
		self.token= re.sub('.*code=','',r.headers['Location'])