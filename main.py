# -*- coding: utf-8 -*-
from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
import base64
import hashlib
import binascii
import hmac
import json
import os
import random
from io import StringIO
import re
import requests
import sys
import time
import urllib
from pkcs7 import PKCS7Encoder
from klab import Klab

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class API(object):
	def __init__(self):
		self.encoder=PKCS7Encoder()
		self.s=requests.session()
		if 'win' in sys.platform:
			self.s.proxies.update({'http': 'http://127.0.0.1:8888','https': 'https://127.0.0.1:8888',})
		self.world='gl'
		self.platform='GOOGLE'
		self.bundle_version='11.1.1'
		self.lang='en'
		self.timezone='Europe/Berlin'
		self.user_agent='/BleachBraveSouls/i:com.klab.bleach/u:11.1.2p2/d:htc Nexus 9/o:Android OS 7.1.1 _ API-25 (N9F27H_4108833)/e:s/'
		self.auth_key='CUANAxRcDUNSURMXAggRFAgPXQEAX0ELVVoFBllCVkVdFwdWQQFSQwVeSEUGDxIXCAtSUQoKFQ9UWFNSVERUEw=='
		self.publicKey='''-----BEGIN PUBLIC KEY-----
						MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCv7iKhOdHvXkCOiq9Ckm98qK12
						hT8vPezkoq8D3AMVaE9wEtZ8qkLRAH19hqNznmD5LFW+TheAxCmb4bzZ3tGFz5Tv
						1r3fpbtulcTVeeKqQtfGw40PmYjIvBR7iI//+k5GxycsDJUwAlwdJzKbRUC+ToH0
						qpIGsIcwq4qeH29ddwIDAQAB
						-----END PUBLIC KEY-----'''
		self.device_id=None
		self.x_authorization_key=None
		self.x_session_key=None
		self.x_vector=None
		self.random_string=None
		self.debug=True
		self.x_auth_count=0
		self.player=None
		self.teams=None
		self.master_data_hash=None
		self.didLogin=False
		self.delete_coin=None
		self.delete_user_id=None
		self.delete_gold=None
		self.check_platform()

	def check_platform(self):
		return self.callAPI('platform/check_platform_version?client_version=%s'%(self.bundle_version),None,0)
		
	def log(self,msg):
		if self.debug:
			print ('{}{}')%(time.strftime('%H:%M:%S'),msg.encode('utf-8'))

	def getRandomString(self,n):
		return ''.join([random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for x in range(n)]).lower()

	def generateMaskData(self,_random=None):
		pubkey = RSA.importKey(self.publicKey)
		cipher = PKCS1_v1_5.new(pubkey)
		self.random_string=_random if _random else self.getRandomString(32)
		return base64.encodestring(cipher.encrypt(self.random_string)).replace('\n','')

	def generateAuthRequestSignature(self,data):
		if type(data)!=str:
			data=urllib.urlencode(data)
		if not self.x_authorization_key:
			self.log('x_authorization_key missing')
			exit(1)
		#if self.player and 'id' in self.player:
		#	tmp='%s-%s-%s'%(self.player['id'],self.x_auth_count,data)
		#else: MILA
		tmp='%s-%s-%s'%(self.device_id,self.x_auth_count,data)
		return base64.b64encode(hmac.new(base64.b64decode(self.x_authorization_key),tmp.encode('utf-8'),hashlib.sha1).hexdigest())

	def generateRequestSignature(self,url,requestBody,requestId):
		if type(requestBody)!=str:
			requestBody=urllib.urlencode(requestBody)
		tmp='%s-%s-%s'%(url,requestId,requestBody)
		return base64.b64encode(hmac.new(base64.b64decode(self.x_session_key),tmp.encode('utf-8'),hashlib.sha1).hexdigest())

	def generateClearHash(self,logid):
		return base64.b64encode(hmac.new(base64.b64encode(str(logid)),'0',hashlib.sha1).hexdigest())

	def setdDevice_id(self,i):
		self.device_id=i

	def getDeviceId(self):
		return str(self.device_id) if self.device_id else ''
	
	def setX_auth_count(self,i):
		self.x_auth_count=i
	
	def setX_session_key(self,i):
		self.x_session_key=i
	
	#def updateHeader(self,data,url,isLink=False):
	def updateHeader(self,data,url,kind):
		_request_id=os.urandom(16).hex()
		head={}
		if self.didLogin:
			if 'X-MASK-DATA' in self.s.headers:
				del self.s.headers['X-MASK-DATA']
			if 'X-AUTHORIZATION' in self.s.headers:
				del self.s.headers['X-AUTHORIZATION']
			if 'X-AUTH-COUNT' in self.s.headers:
				del self.s.headers['X-AUTH-COUNT']
		if kind == 0:
			head={'User-Agent':self.user_agent,'X-LANGUAGE':self.lang,'X-CLIENT-TIMEZONE':self.timezone,'X-PLATFORM':self.platform,'X-BUNDLE-VERSION':self.bundle_version,'X-DEVICE-ID':self.getDeviceId()}
		elif kind ==1:
			head={'User-Agent':self.user_agent,'X-WORLD':self.world,'X-REQUEST-ID':_request_id,'X-LANGUAGE':self.lang,'X-PLATFORM':self.platform,'X-BUNDLE-VERSION':self.bundle_version,'X-CLIENT-LOCALE':'en_US','X-CLIENT-TIMEZONE':self.timezone,'X-MASK-DATA':self.generateMaskData(),'Expect':'100-continue'}
		elif kind ==2:
			head={'User-Agent':self.user_agent,'X-WORLD':self.world,'X-REQUEST-ID':_request_id,'X-LANGUAGE':self.lang,'X-CLIENT-TIMEZONE':'Europe/Berlin','X-PLATFORM':self.platform,'X-BUNDLE-VERSION':self.bundle_version,'X-DEVICE-ID':self.getDeviceId(),'X-AUTH-COUNT':str(self.x_auth_count),'X-AUTHORIZATION':self.generateAuthRequestSignature(data),'X-MASK-DATA':self.generateMaskData(),'Expect':'100-continue'}
		elif kind ==3:
			head={'User-Agent':self.user_agent,'X-WORLD':self.world,'X-MASTER-HASH':self.master_data_hash,'X-LANGUAGE':self.lang,'X-CLIENT-TIMEZONE':self.timezone,'X-PLATFORM':self.platform,'X-BUNDLE-VERSION':self.bundle_version,'X-REQUEST-ID':_request_id,'X-SIGNATURE':self.generateRequestSignature(url,data,_request_id),'X-DEVICE-ID':self.getDeviceId(),'Expect':'100-continue'}
		else:
			head={'User-Agent':self.user_agent,'X-LANGUAGE':self.lang,'X-CLIENT-TIMEZONE':'Europe/Berlin','X-PLATFORM':self.platform,'X-BUNDLE-VERSION':self.bundle_version,'X-DEVICE-ID':self.getDeviceId()}
		self.s.headers.update(head)
		
	def callAPI(self,url,data,kind=3):
		url='http://game-gl.bleach-bravesouls.com/%s'%(url)
		self.updateHeader(data,url,kind)
		if not data:
			r=self.s.get(url)
		else:
			if type(data)==str:
				r=self.s.post(url,data=data)
			else:
				r=self.s.post(url,data=data)
		if 'X-SESSION-KEY' in r.headers:
			self.x_session_key=r.headers['X-SESSION-KEY']
			self.generateSessionKey()
		if 'X-AUTHORIZATION-KEY' in r.headers:
			self.log('found X-AUTHORIZATION-KEY')
			self.x_authorization_key=r.headers['X-AUTHORIZATION-KEY']
			self.device_id=r.headers['X-DEVICE-ID']
			self.log('our device_id:%s'%(self.device_id))
			self.generateCommonKey()
		if b'master_data' in r.content:
			self.master_data_hash=json.loads(r.content)['master_data']['hash']
		if b'custom_message' in r.content:
			return None
		return r.content
		
	def generateCommonKey(self,_xauthkey=None,_random=None):
		authorization_key = _xauthkey if _xauthkey else self.x_authorization_key
		random_string = _random if _random else self.random_string
		inArray = map(ord, authorization_key.decode('base64'))
		bytes = map(ord, random_string.encode('utf-8'))
		for i in range(len(inArray)):
			inArray[i] = inArray[i] ^ bytes[i % len(bytes)]
		res= "".join(map(chr, inArray)).encode('base64')
		self.x_authorization_key=res
		return res

	def generateSessionKey(self,_xauthkey=None,_random=None):
		xSessionKey = _xauthkey if _xauthkey else self.x_session_key
		randomString = _random if _random else self.random_string
		commongKey=self.x_authorization_key
		sessionKeyBytes = map(ord, xSessionKey.decode('base64'))
		randomStringBytes = map(ord, randomString.encode('utf-8'))
		commonKeyBytes = map(ord, commongKey.decode('base64'))
		for i in range(len(sessionKeyBytes)):
			sessionKeyBytes[i] = sessionKeyBytes[i] ^ commonKeyBytes[i % len(commonKeyBytes)]
		for i in range(len(sessionKeyBytes)):
			sessionKeyBytes[i] = sessionKeyBytes[i] ^ randomStringBytes[i % len(randomStringBytes)]
		res= "".join(map(chr, sessionKeyBytes)).encode('base64')
		self.x_session_key=res
		return res
		
	def doRegister(self):
		data={'platform':'GOOGLE','name':'name'}
		tmp= self.callAPI('player_authentication/register',data,1)
		self.x_auth_count+=1
		return tmp
		
	def doLogin(self):
		data={'dummy':'dummy'}
		tmp= self.callAPI('player_authentication/login',data,2)
		if tmp:
			self.player=json.loads(tmp)['player']
			self.log('hello %s'%(self.player['id']))
			self.didLogin=True
		return tmp

	def doUpdatePlayerSetting(self):
		data={'XXX':'XXX','params':'{"message_speed":"1","is_control_position_reverse":"0","is_clear_character_theater":"0","is_stop_sleep_mode":"0","is_high_quality_mode":"1","is_camera_zoom":"0","is_push_all":"1","is_push_action_point_heal":"1","is_push_battle_point_heal":"1","is_push_unei":"1","is_push_event_start":"1","is_push_event_end":"1","bgm_volume":"70","se_volume":"70","voice_volume":"70","is_rec_enable":"0","is_post_rec_movie":"0","is_auto_use_ex_skill_on_team_battle":"1","is_show_my_hit_effect":"1","is_show_other_hit_effect":"1"}'}
		return self.callAPI('playerSetting/update',data)
		
	def setUsername(self,name):
		data={'XXX':'XXX','name':name}
		return self.callAPI('player/update_profile',data)
		
	def checkUsername(self,name):
		data={'XXX':'XXX','name':name}
		return self.callAPI('player/count_name',data)
		
	def doQuestPlayTut(self):
		data={'XXX':'XXX'}
		return self.callAPI('tutorial/quest_play',data)
		
	def doQuestFinishTut(self,data):
		return self.callAPI('tutorial/quest_finish',data)
		
	def doGachaPlayTut(self):
		data={'XXX':'XXX'}
		return self.callAPI('tutorial/gacha_play',data)

	def getTransfer_token(self,data,iv=None):
		if not self.x_vector:
			self.setIV()
		if iv:
			self.x_vector=iv
		encryptor = AES.new(base64.b64decode(self.x_session_key).decode('hex'),AES.MODE_CBC,base64.b64decode(self.x_vector))
		ciphertext = encryptor.encrypt(self.encoder.encode(data))
		return base64.b64encode(ciphertext)
	
	def setIV(self):
		self.x_vector=base64.b64encode(Random.new().read(16))
	
	def genX_vector(self,transferToken,iv=None):
		return self.getTransfer_token(transferToken,iv)
				
	def doTutorialFinish(self):
		data={'XXX':'XXX'}
		return self.callAPI('tutorial/finish',data)
		
	def doLinkWithKlabId(self,authorization_code):
		data={'XXX':'XXX','authorization_code':authorization_code}
		return self.callAPI('data_linking/link_with_klab_id',data,True)
		
	def doTransfer(self,transfer_token):
		data={'XXX':'XXX','transfer_token':self.genX_vector(transfer_token),'delete_user_id':str(self.delete_user_id),'delete_gold':str(self.delete_gold),'delete_coin':str(self.delete_coin)}
		tmp= self.callAPI('data_linking/transfer_with_klab_id',data,True)
		self.x_auth_count+=1
		self.didLogin=False
		return tmp
		
	def doUpdateTeamsTut(self,new):
		self.teams[0]['character_id_2']=new
		data={'XXX':'XXX','json':json.dumps({"teams":self.teams})}
		return self.callAPI('tutorial/update_teams',data)
		
	def doInit(self):
		data={'XXX':'XXX','quest_type':'','quest_log_id':'-1','object_id':'cKECq36vDOM','asset_state':'VVxUUlRQU1FUUFVTUFdVAVECVFFRWlABVFwGVFNSUlMFBQBQAwUCBkgFBlwGBVZaAgFWVVNaVQVXBVwABwFXWgRVAVdaAgAGVQ==','params':'{"message_speed":"1","is_control_position_reverse":"0","is_clear_character_theater":"0","is_stop_sleep_mode":"0","is_high_quality_mode":"1","is_camera_zoom":"0","is_push_all":"1","is_push_action_point_heal":"1","is_push_battle_point_heal":"1","is_push_unei":"1","is_push_event_start":"1","is_push_event_end":"1","bgm_volume":"70","se_volume":"70","voice_volume":"70","is_rec_enable":"0","is_post_rec_movie":"0","is_auto_use_ex_skill_on_team_battle":"1","is_show_my_hit_effect":"1","is_show_other_hit_effect":"1"}','soul_tree':'true','character_link':'true','limit_break':'true','accessory_equip':'true','team_battle_top':'true','team_battle_top_closed':'true','team_battle_prepare':'true','team_battle_ranking':'true','mission_beginner_theater_progress':'0'}
		tmp= self.callAPI('init/index',data,3)
		teams=json.loads(tmp)['teams']
		if len(teams)>=1:
			self.teams=teams
			self.buildTeam()
		u=json.loads(tmp)
		self.delete_user_id=u['player']['id']
		self.delete_coin=u['player']['coin']
		self.delete_gold=u['player']['gold']
		return tmp
		
	def buildTeam(self):
		new_team=[]
		for idx, t in enumerate(self.teams):
			tmp_team={}
			tmp_team['id']=t['id']
			tmp_team['is_main']=int(t['is_main'])
			tmp_team['team_name']=None
			tmp_team['character_id_1']=t['characters'][0]['id'] if len(t['characters'])==1 else "null"
			tmp_team['character_id_2']=t['characters'][0]['id'] if len(t['characters'])==2 else "null"
			tmp_team['character_id_3']=t['characters'][0]['id'] if len(t['characters'])==3 else "null"
			new_team.append(tmp_team)
		self.teams=new_team
		
	def getShopIndex(self):
		data={'XXX':'XXX'}
		return self.callAPI('shop/index',data)
				
	def getAllQuests(self):
		data={'XXX':'XXX','quest_type':'main','section_id':'1','level':'0'}
		return self.callAPI('current_quest_state/get_all_quests',data)
						
	def getDataLinking(self):
		data={'XXX':'XXX'}
		return self.callAPI('data_linking/get_list',data)
								
	def getMyPage(self):
		data={'XXX':'XXX'}
		return self.callAPI('mypage/index',data)
										
	def getWebViewToken(self):
		data={'XXX':'XXX'}
		return self.callAPI('create_web_view_token',data)
									
	def getLoginBonus(self):
		data={'XXX':'XXX'}
		return self.callAPI('login_bonus/receive',data)
									
	def getMissionBeginner(self):
		data={'XXX':'XXX'}
		return self.callAPI('mission_beginner/get_list',data)
								
	def getPresents(self):
		data={'XXX':'XXX','offset':'0','limit':'10000'}
		return self.callAPI('present/get_list',data)

	def doReceiveBulk(self,l):
		l=self.parsePresentIDs(l)
		data={'XXX':'XXX','present_ids':','.join(l)}
		return self.callAPI('present/receive_bulk',data)

	def doMainQuest(self,quest_id,team_id):
		data={'XXX':'XXX','quest_id':quest_id,'team_id':team_id,'level':'0'}
		return self.callAPI('main_quest/play',data)
		
	def doFinishMainQuest(self,finish,client_character_ids):
		data={'XXX':'XXX','result_json':json.dumps(finish),'client_character_ids':client_character_ids,'client_accessory_ids':''}
		return self.callAPI('main_quest/finish',data)
		
	def parseSoulPieces(self,start):
		_res=[]
		soul_pieces=json.loads(start)['pre_dropped_soul_pieces']
		for p in soul_pieces:
			_res.append(p)
		return _res
		
	def parseBoxes(self,start):
		_res={}
		dropped_boxes=json.loads(start)['pre_dropped_boxes']
		for block in dropped_boxes:
			if block not in _res:
				_res[block]={}
			for b in dropped_boxes[block]:
				_res[block][b]=1
		return _res
		
	def completeQuest(self,quest_id,team_id,destroyed_enemies,destroyed_bosses):
		_quest_data=self.doMainQuest(quest_id,self.teams[team_id]['id'])
		_quest_finish_data=self.parseLevel(_quest_data,destroyed_enemies,destroyed_bosses)
		_team=json.loads(_quest_data)['characters']
		client_character_ids=[]
		for c in _team:
			client_character_ids.append(str(c['id']))
		return self.doFinishMainQuest(_quest_finish_data,','.join(client_character_ids))
		
	def parsePresentIDs(self, presents):
		presents = json.loads(presents)
		presentIDs = []
		for cat in presents['presents']:
			for p in presents['presents'][cat]:
				presentIDs.append(str(p['id']))
		return presentIDs

	def parseLevel(self,i,destroyed_enemies,destroyed_bosses):
		data={}
		_boxes=self.parseBoxes(i)
		_soul_pieces=self.parseSoulPieces(i)
		i=json.loads(i)
		data['play_log_id']=i['play_log_id']
		data['clear']=1
		data['play_log']= self.generateClearHash(i['play_log_id'])
		data['destroyed_enemies']=destroyed_enemies
		data['destroyed_bosses']=destroyed_bosses
		data['clear_time']=61092
		data['dropped_boxes']=_boxes
		data['enemy_dropped_ids']=[]
		data['dropped_soul_pieces']=_soul_pieces
		data['change_sub_character']=1
		data['auto_battle']=0
		data['no_bad_status']=1
		data['no_character_defeated']=1
		data['no_following_friend_defeated']=1
		data['received_damage']=0
		data['last_attack_ex']=0
		data['boss_attack_dodge']=1
		data['use_ex_attack']=1
		data['combo_max']=26
		data['damage_max']=146
		data['dropped_watermelon_ids']=[]
		data['is_resumed_game']=0
		data['played_character_theater_last_ids']=[]
		data['special_destroyed_enemies']={}
		data['special_dropped_boxes']={}
		data['special_dropped_soul_pieces']=[]
		data['special_enemy_dropped_ids']=[]
		return data
		
	def completeTut(self):
		self.log('start')
		self.doRegister()
		self.log('register done')
		self.doLogin()
		self.log('login done')
		self.doInit()
		self.log('Init done')
		self.doUpdatePlayerSetting()
		self.log('doUpdatePlayerSetting done')
		self.checkUsername('Rain')
		self.log('checkUsername done')
		self.setUsername('Rain')
		self.log('setUsername done')
		_level=self.doQuestPlayTut()
		self.doQuestFinishTut({'XXX':'XXX','result_json':'{"play_log_id":"%s","clear":1,"play_log":"Default","destroyed_enemies":{"101":{"1":3}},"destroyed_bosses":[1001],"clear_time":32551,"dropped_boxes":{"block1":{"box1":1,"box2":1}},"enemy_dropped_ids":[],"dropped_soul_pieces":[],"change_sub_character":1,"auto_battle":0,"no_bad_status":1,"no_character_defeated":1,"no_following_friend_defeated":1,"received_damage":0,"last_attack_ex":0,"boss_attack_dodge":1,"use_ex_attack":0,"combo_max":11,"damage_max":34,"dropped_watermelon_ids":[],"is_resumed_game":0,"played_character_theater_last_ids":[1101,1201],"special_destroyed_enemies":{},"special_dropped_boxes":{},"special_dropped_soul_pieces":[],"special_enemy_dropped_ids":[]}'%(json.dumps(_level)['play_log_id'])})
		self.log('doQuestFinishTut done')
		self.getShopIndex()
		self.log('getShopIndex done')
		_hero=json.loads(self.doGachaPlayTut())
		self.log('doGachaPlayTut done')
		self.doInit()
		self.doUpdateTeamsTut(_hero['characters'][0]['id'])
		self.getAllQuests()
		_level=self.doQuestPlayTut()
		self.doQuestFinishTut({'XXX':'XXX','result_json':'{"play_log_id":"%s","clear":1,"play_log":"Default","destroyed_enemies":{"101":{"1":5}},"destroyed_bosses":[1002],"clear_time":24364,"dropped_boxes":{"block1":{"box2":1,"box1":1},"block2":{"box1":1,"box2":1}},"enemy_dropped_ids":[],"dropped_soul_pieces":[],"change_sub_character":1,"auto_battle":0,"no_bad_status":1,"no_character_defeated":1,"no_following_friend_defeated":1,"received_damage":0,"last_attack_ex":1,"boss_attack_dodge":1,"use_ex_attack":1,"combo_max":8,"damage_max":124,"dropped_watermelon_ids":[],"is_resumed_game":0,"played_character_theater_last_ids":[2101,2201],"special_destroyed_enemies":{},"special_dropped_boxes":{},"special_dropped_soul_pieces":[],"special_enemy_dropped_ids":[]}'%(json.loads(_level)['play_log_id'])})
		self.getDataLinking()
		self.doTutorialFinish()
		self.getLoginBonus()
		self.getMissionBeginner()
		_gifts=self.getPresents()
		self.doReceiveBulk(_gifts)
		self.doInit()
		if False:
			klab=Klab('mail@gmail.com','password')
			self.setIV()
			_link=self.doLinkWithKlabId(self.genX_vector(klab.giveMeToken()))
			self.setIV()
			self.doTransfer(json.loads(_link)['transfer_token'])
			self.doLogin()
		
if __name__ == "__main__":
	a=API()
	a.completeTut()
	print (a.completeQuest(3,0,{"101":{"1":8}},[3001]))