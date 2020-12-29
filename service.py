# -*- coding: utf-8 -*-
'''
XBMCLocalProxy 0.1
Copyright 2011 Torben Gerkensmeyer

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
'''

import htmlentitydefs
import base64
import uuid
import re
import time
import urllib
import urllib2
import sys
import socket
import gzip
import json
import xbmc,xbmcaddon
import StringIO
from threading import Semaphore
import os
import mimetypes
import cookielib
import shutil
#import ssl
from urlparse import urlparse, parse_qs
from traceback import format_exc
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from Cryptodome import Random
from Cryptodome.Hash import MD5
from Cryptodome.Hash import SHA
from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Cryptodome.PublicKey import RSA


__cwd__=os.path.dirname(__file__)
__lib__  = xbmc.translatePath( os.path.join( __cwd__, 'lib' ) )
sys.path.append (__lib__)

cookiefile = xbmc.translatePath(os.path.join(xbmcaddon.Addon(id='plugin.video.115').getAddonInfo('path'), 'cookie.dat'))
_cookiestr=''
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from pyhtml import *

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
	def http_error_301(self, req, fp, code, msg, headers):  
		result = urllib2.HTTPRedirectHandler.http_error_301(
			self, req, fp, code, msg, headers)
		#result.status = code
		return result
		
	def http_error_302(self, req, fp, code, msg, headers):
		result = urllib2.HTTPRedirectHandler.http_error_302(
			self, req, fp, code, msg, headers)
		#result.status = code
		return result
		
class PassRedirectHandler(urllib2.HTTPRedirectHandler):
	def http_error_301(self, req, fp, code, msg, headers): 
		infourl = urllib.addinfourl(fp, headers, req.get_full_url())
		infourl.status = code
		infourl.code = code
		return infourl
		
	def http_error_302(self, req, fp, code, msg, headers):
		infourl = urllib.addinfourl(fp, headers, req.get_full_url())
		infourl.status = code
		infourl.code = code
		return infourl
		
class api_115(object):
	def __init__(self, cookstr):
		if cookstr=='0':
			cookstr=_cookiestr
		self.headers = {
			#'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.109 Safari/537.36',
			'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)',
			'Accept-encoding': 'gzip,deflate',
			'Cookie': cookstr,
		}
	
	def htmlentitydecode(self,s):
		# First convert alpha entities (such as &eacute;)
		# (Inspired from http://mail.python.org/pipermail/python-list/2007-June/443813.html)
		def entity2char(m):
			entity = m.group(1)
			if entity in htmlentitydefs.name2codepoint:
				return unichr(htmlentitydefs.name2codepoint[entity])
			return u' '  # Unknown entity: We replace with a space.
		t = re.sub(u'&(%s);' % u'|'.join(htmlentitydefs.name2codepoint), entity2char, s)

		# Then convert numerical entities (such as &#233;)
		t = re.sub(u'&#(\d+);', lambda x: unichr(int(x.group(1))), t)

		# Then convert hexa entities (such as &#x00E9;)
		return re.sub(u'&#x(\w+);', lambda x: unichr(int(x.group(1),16)), t)
		
	def gethead(self, url, data=None,h=None,referer=None):
		headers = self.headers
		if h:
			headers.update(h)
		req = urllib2.Request(url, headers = headers)
		if referer:
			req.add_header('Referer', referer)
		req.get_method = lambda : 'HEAD'
		opener = urllib2.build_opener(PassRedirectHandler)
		#opener =urllib.FancyURLopener()
		return opener.open(req,timeout=30)
				
	def get_response(self, url, data=None,h=None,referer=None,charset='auto'):
		''' Return the content of the url page as a string '''
		headers = self.headers
		if h:
			headers.update(h)
		req = urllib2.Request(url, headers = headers)
		if referer:
			req.add_header('Referer', referer)
		try:
			if data:
				response = urllib2.urlopen(req,data=data,timeout=40) 
			else:
				response = urllib2.urlopen(req,timeout=40)
			return response
		except urllib2.URLError as errno:
			errorstr=' '.join(('Connection error:', str(errno)))
			xbmc.log(msg=url+ ' '+errorstr)
			#traceback.print_exc()
			return None
			
	def retrieve_url(self, url, data=None,h=None,referer=None,charset='auto'):
		''' Return the content of the url page as a string '''
		response=self.get_response(url, data,h,referer,charset)
		dat = response.read()
		
		# Check if it is gzipped
		if dat[:2] == '\037\213':
			# Data is gzip encoded, decode it
			compressedstream = StringIO.StringIO(dat)
			gzipper = gzip.GzipFile(fileobj=compressedstream)
			extracted_data = gzipper.read()
			dat = extracted_data
		if 'Set-Cookie' in response.headers:
			#xbmc.log(msg=response.headers['Set-Cookie'],level=xbmc.LOGERROR)
			
			downcookies = re.findall(r'(?:[0-9abcdef]{20,}|acw_tc)\s*\x3D\s*[0-9abcdef]{20,}', response.headers['Set-Cookie'], re.DOTALL | re.MULTILINE)
			self.downcookie=''
			for downcook in downcookies:
				self.downcookie+=downcook+';'
				
				
			#downcook=downcook[downcook.find(',')+2:]
			#self.downcookie=downcook[:downcook.find(';')]
			#xbmc.log(msg='zzzdebug:DownCookie:'+self.downcookie,level=xbmc.LOGERROR)
			#self.downcookie=''
			#for downcook in downcookies:
			#	self.downcookie+=downcook[:downcook.find(';')]+';'
		info = response.info()
		
		if charset=='auto':
			charset = 'utf-8'
			try:
				ignore, charset = info['Content-Type'].split('charset=')
			except Exception as errno:
				xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
				pass
		dat = dat.decode(charset, 'replace')
		dat = self.htmlentitydecode(dat)
		return dat.encode('utf-8', 'replace')

	def urlopen(self, url, data=''): 
		try:
			rs = self.retrieve_url(url,data=data)
			return rs
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return ''
			
	def gettaglist(self):
		data=self.urlopen('https://webapi.115.com/label/list?user_id=&offset=0&limit=11500&sort=create_time&order=desc')
		return json.loads(data[data.index('{'):])
			
	def settag(self,fid,tag):
		data = urllib.urlencode({'fid': fid,'file_label':tag})
		try:
			data=self.urlopen('http://web.api.115.com/files/edit',data=data)
			data= self.fetch(data).replace('\n','').replace('\r','')
			data=json.loads(data[data.index('{'):])
			return data['state']
		except:
			return False
			
	def getfilelist(self,cid,offset,pageitem,star,sorttype,sortasc,typefilter='0',nf='0',search_value=''):
		try:
			if search_value!='' and search_value!='0':
				file_label=''
				match=re.search(r'^tag\s*(?P<tag>[0-9]{10,})$',search_value)
				if match:
					file_label=match.group('tag')
				if file_label:
					data=urllib.urlencode({'file_label': file_label,'cid':cid,'aid':'1','limit':str(pageitem),
								'o':sorttype,'asc':sortasc,'offset':str(offset),'format':'json','date':'','pick_code':'','type':typefilter,'source':''})
				else:
					data=urllib.urlencode({'search_value': search_value,'cid':cid,'aid':'1','limit':str(pageitem),
								'o':sorttype,'asc':sortasc,'offset':str(offset),'format':'json','date':'','pick_code':'','type':typefilter,'source':''})
				data=self.urlopen('http://web.api.115.com/files/search?'+data)
			else:	
				data = urllib.urlencode({'aid': '1','cid':cid,'limit':pageitem,'offset':offset,'type':typefilter,'star':star,'custom_order':'2',
									'o':sorttype,'asc':sortasc,'nf':nf,'show_dir':'1','format':'json','_':str(long(time.time()))})
				if sorttype=='file_name':
					data=self.urlopen('http://aps.115.com/natsort/files.php?'+data)
				else:
					data=self.urlopen('http://web.api.115.com/files?'+data)
			return json.loads(data[data.index('{'):])
		except:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
	
		
	def getpc(self,fid):
		try:
			data=self.urlopen('http://web.api.115.com/category/get?aid=1&cid='+fid)
			data= json.loads(data[data.index('{'):])
			return data['pick_code']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return ''
		
	def getsubtitle(self,pc):
		try:
			data=self.urlopen('http://webapi.115.com/movies/subtitle?pickcode=%s'%(pc))
			data=json.loads(data[data.index('{'):])
			if data['state']:
				return data['data']['list']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
	
	def createdir(self,pid,cname):
		data = urllib.urlencode({'pid': pid,'cname':cname})
		try:
			data=self.urlopen('http://web.api.115.com/files/add',data=data)
			data= json.loads(data[data.index('{'):])
			return data['cid']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return ''
			
	def copy(self,fid,cid):
		data = urllib.urlencode({'fid': fid,'pid':cid})
		try:
			data=self.urlopen('http://web.api.115.com/files/copy',data=data)
			data= json.loads(data[data.index('{'):])
			return data['state']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return False
			
	def rename(self,fid,newname):
		data = urllib.urlencode({'fid': fid,'file_name':newname})
		try:
			data=self.urlopen('http://web.api.115.com/files/edit',data=data)
			data= json.loads(data[data.index('{'):])
			return data['state']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return False
			
	def delete(self,fids):
		data={'pid':0}
		i=0
		for fid in fids:
			data['fid['+str(i)+']']=fid
			i+=1
		data = urllib.urlencode(data)
		try:
			data=self.urlopen('http://web.api.115.com/rb/delete',data=data)
			data= json.loads(data[data.index('{'):])
			return data['state']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return ''

	g_kts = [0xF0, 0xE5, 0x69, 0xAE, 0xBF, 0xDC, 0xBF, 0x5A, 0x1A, 0x45, 0xE8, 0xBE, 0x7D, 0xA6, 0x73, 0x88, 0xDE, 0x8F, 0xE7, 0xC4, 0x45, 0xDA, 0x86, 0x94, 0x9B, 0x69, 0x92, 0x0B, 0x6A, 0xB8, 0xF1, 0x7A, 0x38, 0x06, 0x3C, 0x95, 0x26, 0x6D, 0x2C, 0x56, 0x00, 0x70, 0x56, 0x9C, 0x36, 0x38, 0x62, 0x76, 0x2F, 0x9B, 0x5F, 0x0F, 0xF2, 0xFE, 0xFD, 0x2D, 0x70, 0x9C, 0x86, 0x44, 0x8F, 0x3D, 0x14, 0x27, 0x71, 0x93, 0x8A, 0xE4, 0x0E, 0xC1, 0x48, 0xAE, 0xDC, 0x34, 0x7F, 0xCF, 0xFE, 0xB2, 0x7F, 0xF6, 0x55, 0x9A, 0x46, 0xC8, 0xEB, 0x37, 0x77, 0xA4, 0xE0, 0x6B, 0x72, 0x93, 0x7E, 0x51, 0xCB, 0xF1, 0x37, 0xEF, 0xAD, 0x2A, 0xDE, 0xEE, 0xF9, 0xC9, 0x39, 0x6B, 0x32, 0xA1, 0xBA, 0x35, 0xB1, 0xB8, 0xBE, 0xDA, 0x78, 0x73, 0xF8, 0x20, 0xD5, 0x27, 0x04, 0x5A, 0x6F, 0xFD, 0x5E, 0x72, 0x39, 0xCF, 0x3B, 0x9C, 0x2B, 0x57, 0x5C, 0xF9, 0x7C, 0x4B, 0x7B, 0xD2, 0x12, 0x66, 0xCC, 0x77, 0x09, 0xA6]
	g_key_s = [0x29, 0x23, 0x21, 0x5E]
	g_key_l = [0x42, 0xDA, 0x13, 0xBA, 0x78, 0x76, 0x8D, 0x37, 0xE8, 0xEE, 0x04, 0x91]

	def m115_getkey(self,length,key):
		if key != '':
			results = []
			for i in range(length):
				v1=(key[i] + self.g_kts[length * i])&(0xff)
				v2=self.g_kts[length * (length - 1 - i)]
				results.append(v1^v2)
			return results
		if length == 12:
			return self.g_key_l
		else:
			return self.g_key_s
	
	def xor115_enc(self, src, srclen, key, keylen):
		ret = []
		mod4 = srclen % 4
		for i in range(mod4):
			ret.append(src[i] ^ key[i % keylen])
		for i in range(srclen-mod4):
			ret.append(src[i+mod4] ^ key[i % keylen])
		return ret
	
	def m115_sym_encode(self,src, srclen, key1, key2):
		#plugin.log.error('%d %d %d %d %d %d...%d %d'%(src[0],src[1],src[2],src[3],src[4],src[5],src[30],src[31]))
		k1 = self.m115_getkey(4, key1)
		#plugin.log.error(len(k1))
		#plugin.log.error('%d %d ...%d %d'%(k1[0],k1[1],k1[2],k1[3]))

		k2 = self.m115_getkey(12, key2)
		#plugin.log.error(len(k2))
		#plugin.log.error('%d %d ...%d %d'%(k2[0],k2[1],k2[10],k2[11]))
		ret = self.xor115_enc(src, srclen, k1, 4)


		ret.reverse();
		ret = self.xor115_enc(ret, srclen, k2, 12)
		#plugin.log.error(len(ret))
		#plugin.log.error('%d %d %d %d %d %d...%d %d'%(ret[0],ret[1],ret[2],ret[3],ret[4],ret[5],ret[30],ret[31]))
		return ret;
	
	def m115_sym_decode(self,src, srclen, key1, key2):
		k1 = self.m115_getkey(4, key1)
		#plugin.log.error('k1:%d %d %d %d'%(k1[0],k1[1],k1[2],k1[3]))
		
		k2 = self.m115_getkey(12, key2)
		ssss=0
		# for ss in k2:
			# plugin.log.error('k2:%d:%d'%(ssss,ss))
			# ssss+=1
		ret = self.xor115_enc(src, srclen, k2, 12)
		ssss=0
		# for ss in ret:
			# plugin.log.error('ret1:%d:%d'%(ssss,ss))
			# ssss+=1
		ret.reverse()
		ret = self.xor115_enc(ret, srclen, k1, 4)
		return ret
	
	prsa = RSA.importKey('''-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR3rWmeYnRClwLBB0Rq0dlm8Mr
PmWpL5I23SzCFAoNpJX6Dn74dfb6y02YH15eO6XmeBHdc7ekEFJUIi+swganTokR
IVRRr/z16/3oh7ya22dcAqg191y+d6YDr4IGg/Q5587UKJMj35yQVXaeFXmLlFPo
kFiz4uPxhrB7BGqZbQIDAQAB
-----END RSA PUBLIC KEY-----''')
	pcipher = PKCS1_v1_5.new(prsa)

	srsa = RSA.importKey('''-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC
TVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6
FJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB
AoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/
3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t
viOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy
A9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q
pydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z
DSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft
5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN
4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo
YuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v
wlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=
-----END RSA PRIVATE KEY-----''')
	scipher = PKCS1_v1_5.new(srsa)
	
	def m115_asym_encode(self,src, srclen):
		m = 128 - 11
		ret = ''
		for i in range(int((srclen + m - 1) / m)):
			bsrc=bytes(src[i*m:i*m+m])
			#plugin.log.error(len(bsrc))
			#plugin.log.error('%s %s ...%s %s'%(bsrc[0],bsrc[1],bsrc[30],bsrc[31]))
			rettemp=self.pcipher.encrypt(bsrc)
			#plugin.log.error(len(rettemp))
			ret += rettemp;
			#ret += base64.b64decode(rettemp);
		ret = base64.b64encode(ret)
		return ret

	def m115_asym_decode(self,src, srclen):
		m = 128
		#plugin.log.error(srclen)
		ret = ''
		for i in range(int((srclen + m - 1) / m)):
			rettemp=bytes(src[i*m:i*m+m])
			#dsize = SHA.digest_size
			#sentinel = Random.new().read(16+dsize)
			message=self.scipher.decrypt(rettemp,'')
			#message=self.scipher.decrypt(rettemp,sentinel)
			#digest = SHA.new(message[:-dsize]).digest()
			#if digest==message[-dsize:]:                # Note how we DO NOT look for the sentinel
			#	plugin.log.error("Encryption was correct.")
			#else:
			#	plugin.log.error("Encryption was not correct.")
			ret += message
		#ssss=0
		#for ss in ret:
		#	plugin.log.error('%d:%d'%(ssss,ord(ss)))
		#	ssss+=1
		return ret
		
	def m115_encode(self,src, tm):
		#plugin.log.error(src)
		key = MD5.new()
		#plugin.log.error(b'tm=%s'%tm)
		key.update(b'!@###@#%sDFDR@#@#'%tm)
		bkey = bytearray()
		bkey.extend( key.hexdigest())
		#plugin.log.error(len(bkey))
		#plugin.log.error(key.hexdigest())
		#plugin.log.error('%d %d ...%d %d'%(bkey[0],bkey[1],bkey[30],bkey[31]))
		bsrc = bytearray()
		bsrc.extend(src)
		#plugin.log.error(bsrc)
		tmp = self.m115_sym_encode(bsrc, len(bsrc),bkey, '')
		tmp2 = bkey[0:16]
		tmp2.extend(tmp)
		#plugin.log.error(len(tmp2))
		#plugin.log.error('%d %d %d %d %d %d...%d %d...%d %d'%(tmp2[0],tmp2[1],tmp2[2],tmp2[3],tmp2[4],tmp2[5],tmp2[30],tmp2[31],tmp2[46],tmp2[47]))
		return {
		'data': self.m115_asym_encode(tmp2, len(tmp2)),'key':key.hexdigest()
		}

	def m115_decode(self,src, key):
		bkey1 = bytearray()
		bkey1.extend(key)
		#plugin.log.error('%d %d ...%d %d'%(bkey1[0],bkey1[1],bkey1[30],bkey1[31]))
		tmp = base64.b64decode(src)
		bsrc = bytearray()
		bsrc.extend(tmp)
		tmp = self.m115_asym_decode(bsrc, len(bsrc))
		#plugin.log.error('ch=%s'%len(tmp))
		bkey2 = bytearray()
		bkey2.extend(tmp[0:16])
		#plugin.log.error('key2=%s'%tmp[0:16])
		bsrc2 = bytearray()
		bsrc2.extend(tmp[16:])
		return self.m115_sym_decode(bsrc2, len(tmp) - 16, bkey1,bkey2)

	def getfiledownloadurl(self,pc):
		tm = str((int(long(time.time()))))
		pcencode = self.m115_encode((json.dumps({'pickcode': pc})).replace(' ',''),tm)
		data=self.urlopen('http://proapi.115.com/app/chrome/downurl?t='+tm,data=urllib.urlencode({'data':pcencode['data']}))
		jsondata = json.loads(data[data.index('{'):])
		if jsondata['state'] != True:
			return ''
		decodetmp=self.m115_decode(jsondata['data'], pcencode['key'])
		bdecode = bytearray()
		bdecode.extend(decodetmp)
		jsondata = json.loads(bdecode.decode('utf-8'))
		jsondata=jsondata[jsondata.keys()[0]]
		#plugin.log.error(type(jsondata))
	
		result = ''
		if jsondata.has_key(u'url'):
			result = jsondata[u'url'][u'url']
		#plugin.log.error(result)
		
		return result+'|'+self.downcookie

	def oldgetfiledownloadurl(self,pc):
		bad_server = ''
		result = ''
		try:
			data=self.urlopen('https://webapi.115.com/files/download?pickcode='+pc+'&_='+str(long(time.time())))
			data= json.loads(data[data.index('{'):])
			if data['state']:
				result=data['file_url']
			else:
				data=self.urlopen('http://proapi.115.com/app/chrome/down?method=get_file_url&pickcode='+pc)
				data= json.loads(data[data.index('{'):])
				if data['state']:
					for value in data['data'].values():
						if value.has_key('url'):
							result = value['url']['url']
							break
				else:
					return ''

			#xbmc.executebuiltin('XBMC.Notification('%s', '%s', '%s', '%s')' %(result, '', 5000, ''))
			return result+'|'+self.downcookie
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return ''
	
	def coversrttovtt(self,srturl):
		try:
			srtcontent=self.urlopen(srturl)
			dictsrt={
					'sourceFormat': 'AutoDetect',
					'targetFormat': 'Vtt',
					'timeShiftBy': '+0.0',
					'timeShiftAfter': '0.0',
					'writeHours': True,
					'vttStartCounter': '',
					'maxCharactersPerLine': '',
					'input': srtcontent,
				}
			jsonsrt=json.dumps(dictsrt)
			data=urllib.urlencode({'tool':'subtitle-subtitle-converter','parameters':jsonsrt})
			data=self.urlopen('https://toolslick.com/api/process',data=data)
			data= json.loads(data[data.index('{'):])
			return data['subtitle']
		except Exception as errno:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return ''

class MyHandler(BaseHTTPRequestHandler):
	#文件块读取大小
	blockSize=1024*1024*16
	#每文件最大访问线程数
	accessThreadNum=2
	#文件下载地址
	fidDownloadurl={}
	#文件下载线程计数器
	fidSemaphores={}
	#文件大小
	fileSize={}
	def handle(self):
		try:
			BaseHTTPRequestHandler.handle(self)
		except socket.error:
			pass
			
	def handle_one_request(self):
		try:
			self.raw_requestline = self.rfile.readline(65537)
			if len(self.raw_requestline) > 65536:
				self.requestline = ''
				self.request_version = ''
				self.command = ''
				self.send_error(414)
				return
			if not self.raw_requestline:
				self.close_connection = 1
				return
			if not self.parse_request():
				# An error code has been sent, just exit
				return
			mname = 'do_' + self.command
			if not hasattr(self, mname):
				self.send_error(501, 'Unsupported method (%r)' % self.command)
				return
			method = getattr(self, mname)
			#xbmc.log('before call do_Get')
			method()
			#add debug info  close
			#xbmc.log('after call do_Get')
			if not self.wfile.closed:
				self.wfile.flush() #actually send the response if not already done.
			print 'after wfile.flush()'
		except socket.timeout, e:
			#a read or a write timed out.  Discard this connection
			self.log_error('Request timed out: %r', e)
			self.close_connection = 1
			return
	'''
	Serves a HEAD request
	'''
	def do_HEAD(s):
		print 'XBMCLocalProxy: Serving HEAD request...'
		s.answer_request(0)

	'''
	Serves a GET request.
	'''
	def do_GET(s):
		print 'XBMCLocalProxy: Serving GET request...'
		s.answer_request(1)

	def answer_request(s, sendData):
		try:
			urlsp=urlparse(s.path)
			scheme=urlsp.scheme
			netloc=urlsp.netloc
			request_path=urlsp.path
			requestedWith=''
			for key in s.headers:
				if key.lower()=='x-requested-with':
					requestedWith= s.headers[key]
			if request_path=='/stop':
				sys.exit()
			elif request_path=='/version':
				s.send_response(200)
				s.end_headers()
				t = html(
					head(
						title('WEB115 VERSION'),
						link(rel='stylesheet',href='/css/styles.css')
					),
					body(
							xbmcaddon.Addon().getAddonInfo('name')+' is Running',
							br(),
							'Version: '+xbmcaddon.Addon().getAddonInfo('version')
					)
				)

				s.wfile.write( t.render())
				
			elif request_path[0:4]=='/djs':
				try:
					(url,name)=request_path[5:].split('/')
					name=name[:name.index('.json')]
					dictvideo={
							'encodings':[
							{
								'name':'h264',
								'videoSources':[
								{
									'resolution':'scode',
									'url':urllib.unquote_plus(url)
								}
								]
							}
							],
							'title':name,
							'id': 999
						}
					jsonvideo = json.dumps(dictvideo)
					debugstr='''{
	'id': 100,
	'title': '%s',
	'encodings': [{
			'name': 'h264',
			'videoSources': [{
					'resolution': 1080,
					'height': 1920,
					'width': 3840,
					'url': '%s'
				}, ]
		}
	]
}
					'''%(name,urllib.unquote_plus(url))
					s.send_response(200)
					#s.send_header('Content-Length', len(jsonvideo))
					s.send_header('Content-Length', len(debugstr))
					s.send_header('Keep-Alive', 'timeout=5, max=100')
					s.send_header('Connection', 'Keep-Alive')
					s.send_header('Content-Type', 'application/json')
					s.end_headers()
					#s.wfile.write(jsonvideo)
					s.wfile.write(debugstr)
				except Exception as errno:
					xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
					
			elif request_path[0:4]=='/deo':
				try:
					qs=parse_qs(urlsp.query, keep_blank_values=True)
					url=qs.get('url',['0'])[0]
					name=qs.get('title',['0'])[0]
					mimetype=qs.get('mimetype',['0'])[0]
					s.send_response(200)
					
					playhtml='''
<!DOCTYPE html>
<html lang='en'>
<head>
	<meta charset='UTF-8'>
	<link rel='stylesheet' type='text/css' href='https://s3.deovr.com/version/1/css/styles.css' />
	<title>DEOVR</title>
</head>
<body>
<div>
<deo-video format='LR' angle='180' title='%s' >
<source src='%s' quality='1920p'/>
</deo-video>
</div>
<!-- Scripts -->
<script async src='https://s3.deovr.com/version/1/js/bundle.js'></script>
</body>
</html>
					'''%(name,url)
					s.send_header('Content-Length', len(playhtml))
					s.end_headers()
					s.wfile.write(playhtml)
				except Exception as errno:
					xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			
			elif request_path[0:4]=='/gjs':
				try:
					(url,name)=request_path[5:].split('/')
					name=name[:name.index('.json')]
					dictvideo={
							'encodings':[
							{
								'name':'h264',
								'videoSources':[
								{
									'resolution':'scode',
									'url':urllib.unquote_plus(url)
								}
								]
							}
							],
							'title':name,
							'id': 999
						}
					jsonvideo = json.dumps(dictvideo)
					debugstr='''{
	'id': 100,
	'title': '%s',
	'encodings': [{
			'name': 'h264',
			'videoSources': [{
					'resolution': 1080,
					'height': 1920,
					'width': 3840,
					'url': '%s'
				}, ]
		}
	]
}
					'''%(name,urllib.unquote_plus(url))
					s.send_response(200)
					#s.send_header('Content-Length', len(jsonvideo))
					s.send_header('Content-Length', len(debugstr))
					s.send_header('Keep-Alive', 'timeout=5, max=100')
					s.send_header('Connection', 'Keep-Alive')
					s.send_header('Content-Type', 'application/json')
					s.end_headers()
					#s.wfile.write(jsonvideo)
					s.wfile.write(debugstr)
				except Exception as errno:
					xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
					
			elif request_path[0:4]=='/115':
				(fid,cookiestr,changeserver,name)=request_path[5:].split('/')
				cookiestr=urllib.unquote_plus(cookiestr)
				if fid=='cleartempplay':
					s.send_response(200)
					t = html(
						head(
							meta(charset='utf-8'),
							title('WEB115 CLEARTEMPLAY'),
							link(rel='stylesheet',href='/css/styles.css')
						),
						body(
							res
						)
					)
					htmlrender=t.render()
					s.send_header('Content-Length', len(htmlrender))
					s.end_headers()
					s.wfile.write(htmlrender)
				else:
					res=s.serveFile(fid, cookiestr, changeserver, sendData,name)
				
			elif request_path[0:4]=='/m3u':
				try:
					(pc,sha,name)=request_path[5:].split('/')
					xl = api_115('0')
					datam=xl.urlopen('http://115.com/api/video/m3u8/'+ pc+'.m3u8')
					#s.wfile.write(datam)
					m3u8urls=[]
					for match in re.finditer('BANDWIDTH=(?P<bandwidth>.*?)\x2C.*?(?P<url>http.*?)\r', datam, re.IGNORECASE | re.DOTALL):
						m3u8urls.append((int(match.group('bandwidth')),match.group('url')))
					if len(m3u8urls)>0:
						m3u8urls.sort(key=lambda x:x[0],reverse=True)
						url= m3u8urls[0][1]
						extm3u='''#EXTM3U
#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=15000000,RESOLUTION=640x426,NAME='YH'
%s'''%(url)
						# urlsp=urlparse(url)
						# scheme=urlsp.scheme
						# netloc=urlsp.netloc
						# datam=xl.urlopen(url)
						# matchkeyurl=re.search(r'(?P<keyurl>\x2Fapi\x2Fvideo\x2Fm3u8\x2Fvideo\x2ekey.*?)[\x22\x27]', datam, re.DOTALL | re.IGNORECASE)
						# if matchkeyurl:
							# keyurl=matchkeyurl.group('keyurl')
							# keyurl2=urlparse.urljoin(url, keyurl)
							# datam=datam.replace(keyurl,keyurl2)
						# datam=datam.replace('\n/','\n%s://%s/'%(scheme,netloc))
						#s.wfile.write(datam)
						s.send_response(200)
						s.send_header('Content-type', 'application/x-mpegURL')
						s.send_header('Content-Length', len(extm3u))
						s.end_headers()
						s.wfile.write(extm3u)
					else:
						xl = api_115('0')
						data = urllib.urlencode({'op': 'vip_push','pickcode':pc,'sha1':sha})
						data=xl.urlopen('http://115.com/?ct=play&ac=push',data=data)
						s.send_response(200)
						s.send_header('Content-Type', 'text/html; charset=UTF-8')
						t = html(
							head(
								title('未转码'),
								link(rel='stylesheet',href='/css/styles.css')
							),
							body('当前文件未转码，请尝试原码播放')
							)
						htmlrender=t.render()
						s.send_header('Content-Length', len(htmlrender))
						s.end_headers()
						s.wfile.write(htmlrender)
				except Exception as errno:
					xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
					
			elif request_path=='/play':
				try:
					qs=parse_qs(urlsp.query, keep_blank_values=True)
					url=qs.get('url',['0'])[0]
					name=qs.get('title',['0'])[0]
					mimetype=qs.get('mimetype',['0'])[0]
					cid=qs.get('cid',['0'])[0]
					pc=qs.get('pc',['0'])[0]
					xl = api_115('0')
					subtitlelist=xl.getsubtitle(pc)
					subtrack=''
					defaultsub='default'
					for sub in subtitlelist:
						
						suburl=('%s://%s/sub/%s/%s.vtt' % (s.request_version.split('/')[0],
															s.headers.get('Host'),
															urllib.quote_plus(sub['url']),
															urllib.quote_plus(sub['title'].encode('utf-8')))).encode('latin-1')
						subtrack+='''<track src='%s' kind='Subtitles' srclang='%s' label='%s' %s>
'''%(suburl,sub['language'],urllib.quote_plus(sub['title'].encode('UTF-8')),defaultsub)
						defaultsub=''
					s.send_response(200)
					s.send_header('Content-Type', 'text/html; charset=UTF-8')
					playhtml='''
<head>
  <link href="https://vjs.zencdn.net/7.6.5/video-js.css" rel="stylesheet">
  <link href="/css/styles.css" rel="stylesheet">
  <!-- If you'd like to support IE8 (for Video.js versions prior to v7) -->
  <script src="https://vjs.zencdn.net/ie8/1.1.2/videojs-ie8.min.js"></script>
</head>

<body>
<div class="video-container">
  <video id='my-video' class='video-js' controls preload='auto' autoplay=true width='800' height='450'
  poster='MY_VIDEO_POSTER.jpg' data-setup='{}'>
    <source src='%s' type='%s'>
	%s
    <p class='vjs-no-js'>
      To view this video please enable JavaScript, and consider upgrading to a web browser that
      <a href='https://videojs.com/html5-video-support/' target='_blank'>supports HTML5 video</a>
    </p>
  </video>
</div>
  <script src='https://vjs.zencdn.net/7.6.5/video.js'></script>
</body>
'''%(url,mimetype,subtrack)
					# t = html(
						# head(
							# meta(charset='utf-8'),
							# title('web115 files'),
							# link(rel='stylesheet',href='https://vjs.zencdn.net/7.6.0/video-js.css'),
							# script(src='https://vjs.zencdn.net/ie8/1.1.2/videojs-ie8.min.js')
						# ),
						# body(
							# video(id='my-video' class_='video-js vjs-default-skin' width='800' data-setup={'controls': True, 'autoplay': True, 'preload': 'auto'}
							# )()
							# script(src='https://vjs.zencdn.net/7.6.0/video.js')
						# )
					# )
					# s.wfile.write(t.render())
					s.send_header('Content-Length', len(playhtml))
					s.end_headers()
					s.wfile.write(playhtml)
				except Exception as errno:
					xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
				
			elif request_path=='/files':
				qs=parse_qs(urlsp.query, keep_blank_values=True)
				cid=qs.get('cid',[0])[0]
				cid=int(cid)
				offset=int(qs.get('offset',[0])[0])
				star=qs.get('star',[0])[0]
				typefilter=qs.get('typefilter',[0])[0]
				cursorttype=qs.get('cursorttype',['0'])[0]
				sorttype ='user_ptime'
				if cursorttype=='2' or cursorttype=='3':
					sorttype ='file_size'
				if cursorttype=='4' or cursorttype=='5':
					sorttype ='file_name'
				sortasc='0'
				if cursorttype=='1' or cursorttype=='2' or cursorttype=='4':
					sortasc='1'
				xl = api_115('0')
				taglist=[]
				data=xl.gettaglist()
				if data['state']:
					fllist=sorted( data['data']['list'],key=lambda k:k['sort'],reverse=True)
					for tag in fllist:
						tagname=tag['name'].encode('UTF-8')
						taglist.append([tagname,tag['id']])
				tagnamelist=[q[0] for q in taglist]
				tagidlist=[q[1] for q in taglist]
				
				searchvalue=qs.get('searchvalue',[''])[0]
				if len(searchvalue)<3:searchvalue=''
				searchstr=searchvalue
				if searchvalue[0:2]=='t:':
					searchstr=searchvalue[2:]
					try:
						searchstr=('tag'+tagidlist[tagnamelist.index(searchstr)]).encode('UTF-8')
					except:
						pass
				pageitem= int(xbmcaddon.Addon().getSetting('pageitem'))
				if pageitem<10: pageitem=10
				if pageitem>200: pageitem=200
				data=xl.getfilelist(cid=cid,offset=offset,pageitem=pageitem,star=star,sorttype=sorttype,sortasc=sortasc,typefilter=typefilter,nf='0',search_value=searchstr)
				if data['state']:
					def sort(ctx):
						for title, url in [
										('从新到旧','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':typefilter,'cursorttype':0,'searchvalue':searchvalue,'star': star})),
										('从旧到新','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':typefilter,'cursorttype':1,'searchvalue':searchvalue,'star': star})),
										('从小到大','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':typefilter,'cursorttype':2,'searchvalue':searchvalue,'star': star})),
										('从大到小','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':typefilter,'cursorttype':3,'searchvalue':searchvalue,'star': star})),
										('从A到Z','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':typefilter,'cursorttype':4,'searchvalue':searchvalue,'star': star})),
										('从Z到A','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':typefilter,'cursorttype':5,'searchvalue':searchvalue,'star': star}))]:
							yield  td(a(href=url,class_='sort')(title))
					def filters(ctx):
						for title, url in [
										('全部','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':0,'cursorttype':cursorttype,'searchvalue':searchvalue})),
										('视频','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':4,'cursorttype':cursorttype,'searchvalue':searchvalue})),
										('图片','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':2,'cursorttype':cursorttype,'searchvalue':searchvalue})),
										('音乐','/files?'+urllib.urlencode({'cid': cid,'offset':0,'typefilter':3,'cursorttype':cursorttype,'searchvalue':searchvalue}))]:
							yield td(a(href=url,class_='typefilter')(title))
					def paths(ctx):
						if data.has_key('path'):
							for item in data['path']:
								title=''
								url=''
								if str(item['cid'])!=str(cid):
									title='返回到【%s】'%(item['name']).encode('UTF-8')
									url='/files?'+urllib.urlencode({'cid': item['cid'],'offset':0,'cursorttype':cursorttype})
									yield td(a(href=url,class_='path',title=title)(title))
					def searchcur(ctx):
						cidname=''
						if data.has_key('path'):
							if len(data['path'])>0:
								cidname=data['path'][-1]['name']
						if data.has_key('folder'):
							cidname=data['folder']['name']
						if cidname!='':
							def tagnameoptions(ctx):
								for tagname in tagnamelist:
									yield option(value='t:'+tagname)
							url='/files?'+urllib.urlencode({'cid': cid,'offset':0,'cursorttype':cursorttype})
							title='当前【%s】'%(cidname).encode('UTF-8')
							yield form(action='/files',method='GET')(
								input_( type='hidden', name="cid",value=cid),
								input_( type='hidden', name="cursorttype",value=cursorttype),
								table(tr(
								td(a(href=url,class_='curpath',title=title)(title)),
								td(input_(class_='bigfont', type='text', name="searchvalue", list='tagnames',value=searchvalue),datalist(id='tagnames')(tagnameoptions)),
								td(input_(class_='bigfont', type='submit', name="submit",value='搜索')),
								)
								))
					def navpage(ctx):
						count=int(data['count'])
						pages=int(count/pageitem)
						if count%pageitem>0:
							pages=pages+1
						curpage=int(offset/pageitem)+1
						offlast=offset+pageitem
						if offlast>count:
							offlast=count
						yield td('翻页：')
						if curpage>1:
							url='/files?'+urllib.urlencode({'cid': cid,'offset':0,'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
							yield td(a(href=url,title='第一页',class_='pagesel')('|<'),class_='pagesel')
							
							url='/files?'+urllib.urlencode({'cid': cid,'offset':pageitem*(curpage-2),
							'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
							yield td(a(href=url,title='上一页',class_='pagesel')('<'),class_='pagesel')
						else:
							yield td(a(href='#',title='第一页',class_='pagesel')('|<'),class_='pagesel')
							yield td(a(href='#',title='上一页',class_='pagesel')('<'),class_='pagesel')
						def options(ctx):
							for page in range(1,pages+1):
								offset=pageitem*(page-1)
								url='/files?'+urllib.urlencode({'cid': cid,'offset':offset,
								'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
								#offlast=offset+pageitem
								#if offlast>count:
								#	offlast=count
								strpage='第%03d页'%(page)
								if curpage==page:
									yield option(value=url,selected='selected',class_='pagesel')(strpage)
								else:
									yield option(value=url)(strpage)
						yield td(select(onchange='if (this.value) window.location.href=this.value',class_='pagesel')(options),class_='pagesel')
						yield td('共%03d页'%(pages),class_='pagesel')
						
						if curpage<pages:
							url='/files?'+urllib.urlencode({'cid': cid,'offset':pageitem*(curpage),'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
							yield td(a(href=url,title='下一页',class_='pagesel')('>'),class_='pagesel'),
							
							url='/files?'+urllib.urlencode({'cid': cid,'offset':pageitem*(pages-1),'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
							yield td(a(href=url,title='最后一页',class_='pagesel')('>|'),class_='pagesel')
						else:
							yield td(a(href='#',title='下一页',class_='pagesel')('>'),class_='pagesel')
							yield td(a(href='#',title='最后一页',class_='pagesel')('>|'),class_='pagesel')
						yield td('（当前：%s至%s|共%s个文件）'%(offset+1,offlast,count),class_='curpath')
					def items(ctx):
						for item in data['data']:
							#data['data']有时不是list,而是dict, foreach后返回的是key文本。20180425
							if not isinstance(item, dict):
								item=data['data'][item]
							title=''
							url=''
							locurl=''
							isvideo=False
							ism3u8=False
							mimetype=''
							if item.has_key('sha'):
								if cid!=int(item['cid']):
									locurl='/files?'+urllib.urlencode({'cid':item['cid'],'offset':0,'typefilter':typefilter,'cursorttype':0,'searchvalue':''})
								title=item['n'].encode('UTF-8')
								mimetype, _ =mimetypes.guess_type('a.'+item['ico'].lower())
								url='%s://%s/115/%s/%s/%s/%s' % (s.request_version.split('/')[0],s.headers.get('Host'),item['fid'],'0','0',urllib.quote_plus(title))
								#if item['ico'].lower() in ['mp4', 'wmv', 'avi', 'mkv', 'mpg','ts','vob','m4v','mov','flv','rmvb']:
								if item.has_key('iv'):
									isvideo=True
									'''
									sourceurl=urllib.quote_plus('%s://%s/deo/%s/%s/%s/%s' % (s.request_version.split('/')[0],s.headers.get('Host'),item['fid'],'0','0','a.mp4'))
									sourceurl='%s://%s/115/%s/%s/%s/%s' % (s.request_version.split('/')[0],s.headers.get('Host'),item['fid'],'0','0',urllib.quote_plus(title))
									url='deovr://%s' % (sourceurl)
									#url='/giz/%s/%s/%s/%s' % (item['fid'],'0','0',urllib.quote_plus(title+'.json'))
									#url='/deo/%s/%s/%s/%s' % (item['fid'],'0','0',urllib.quote_plus(title)+'.json')
									
									video_code =  int(xbmcaddon.Addon().getSetting('video_code'))
									if video_code==2 or (video_code==1 and item['ico'].lower()!='mp4'):
										datam=xl.urlopen('http://115.com/api/video/m3u8/'+ xl.getpc(item['fid'])+'.m3u8')
										m3u8urls=[]
										for match in re.finditer('BANDWIDTH=(?P<bandwidth>.*?)\x2C.*?(?P<url>http.*?)\r', datam, re.IGNORECASE | re.DOTALL):
											m3u8urls.append((int(match.group('bandwidth')),match.group('url')))
										if len(m3u8urls)>0:
											url='/m3u/%s/%s.m3u8' % (item['fid'],urllib.quote_plus(title))
											#m3u8urls.sort(key=lambda x:x[0],reverse=True)
											#url= m3u8urls[0][1]
											ism3u8=True
											mimetype='application/x-mpegURL'
									'''
								url=url.encode('latin-1')
							else:
								if item['n'][0:8]=='tempplay':
									continue;
								title='【%s】'%(item['n']).encode('UTF-8')
								url='/files?'+urllib.urlencode({'cid': item['cid'],'offset':0,'cursorttype':cursorttype})
							if title:
								tds=[]
								if locurl:
									tds.append(td(a(href=locurl,type=mimetype,class_='loc')('定位'),class_='loctd'))
								if isvideo:
									# url='/play?'+urllib.urlencode({'url': url,'title':title+'.m3u8','mimetype':mimetype})
									# yield li(a(href=url,title=title)(title))
									#yield li(a(href=url,type=mimetype)(title),class_='video')
									playurl='/play?'+urllib.urlencode({'url': url,'title':title+'.m3u8','mimetype':mimetype,'cid':item['cid'],'pc':item['pc']})
									m3url=('/m3u/%s/%s/%s.m3u8' % (item['pc'],item['sha'],urllib.quote_plus(title))).encode('latin-1')
									m3url=('%s://%s/m3u/%s/%s/%s.m3u8' % (s.request_version.split('/')[0],
															s.headers.get('Host'),
															item['pc'],item['sha'],urllib.quote_plus(title))).encode('latin-1')
									m3uplayurl='/play?'+urllib.urlencode({'url': m3url,'title':title+'.m3u8','mimetype':'application/x-mpegURL','cid':item['cid'],'pc':item['pc']})
									deourl=('deovr://%s://%s/djs/%s/%s.json' % (s.request_version.split('/')[0],
															s.headers.get('Host'),
															urllib.quote_plus(url),
															urllib.quote_plus(title),
															)).encode('latin-1')
									m3udeourl=('deovr://%s://%s/djs/%s/%s.json' % (s.request_version.split('/')[0],
															s.headers.get('Host'),
															urllib.quote_plus(m3url),
															urllib.quote_plus(title),
															)).encode('latin-1')
									#gizurl=('gizmovr://type=video&url=%s' % (url)).encode('latin-1')
									#m3ugizurl=('gizmovr://type=video&url=%s' % (m3url)).encode('latin-1')
									#xbmc.log(msg='requestedWith:'+requestedWith,level=xbmc.LOGERROR)
									tds.append( td(a(href=url,type=mimetype,class_='video')(title),class_='videotd'))
									tds.append( td(a(href=playurl,class_='vid2')('原码HTML5播放')))
									tds.append( td(a(href=m3uplayurl,class_='vid2')('转码HTML5播放')))
									#if requestedWith.lower().find('deovr')>=0:
									#tds.append( td(a(href=m3udeourl,class_='vid2')('DEO转码播放')))
									#else:
									tds.append( td(a(href=m3url,type='application/x-mpegURL',class_='vid2')('转码直连播放')))
								else:
									tds.append(td(a(href=url,type=mimetype)(title),colspan='4'))
								yield tr(tds)
					s.send_response(200)
					s.send_header('Content-Type', 'text/html; charset=UTF-8')
					
					t = html(
						head(
							title('web115 files'),
							link(rel='stylesheet',href='/css/styles.css')
						),
						body(
							# nav(
								# select(onchange='if (this.value) window.location.href=this.value')(sort),
								# ),
							# nav(
								# select(onchange='if (this.value) window.location.href=this.value')(filters),
								# ),
							
							#ul(paths),
							table(tr(paths)),
							searchcur,
							table(tr(sort)),
							table(tr(filters,navpage)),
							table(items),
						)
					)
					htmlrender=t.render()
					s.send_header('Content-Length', len(htmlrender))
					s.end_headers()
					s.wfile.write(htmlrender)
				else:
					s.send_response(200)
					t = html(
						head(
							meta(charset='utf-8'),
							title('WEB115 error'),
							link(rel='stylesheet',href='/css/styles.css')
						),
						body(
								'获取文件列表失败',
								br(),
								'请重新扫码登录115网盘插件',
								br(),
								'并重新启动KODI',
						)
					)
					htmlrender=t.render()
					s.send_header('Content-Length', len(htmlrender))
					s.end_headers()
					s.wfile.write(htmlrender)
					
			elif request_path[0:4]=='/sub':
				try:
					(suburl,name)=request_path[5:].split('/')
					suburl=urllib.unquote_plus(suburl)
					name=name[:name.index('.vtt')]
					xl = api_115('0')
					vttstr=xl.coversrttovtt(srturl=suburl)
					s.send_response(200)
					s.send_header('Content-Length', len(vttstr))
					s.send_header('Keep-Alive', 'timeout=5, max=100')
					s.send_header('Connection', 'Keep-Alive')
					s.send_header('Content-Type', 'text/vtt; charset=UTF-8')
					s.end_headers()
					s.wfile.write(vttstr.encode('UTF-8'))
				except Exception as errno:
					xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			else:
				try:
					if request_path=='/' or request_path=='':
						request_path='/index.html'
					filepath = xbmc.translatePath( os.path.join( __cwd__,  'www', request_path[1:]))
					#filesize=os.path.getsize(filepath)
					#xbmc.log(msg=filepath,level=xbmc.LOGERROR)
					f = open(filepath)

				except IOError:
					s.send_error(404,'File Not Found: %s ' % request_path)
				else:
					s.send_response(200)
					mimetype, _ = mimetypes.guess_type(filepath)
					s.send_header('Content-type', mimetype)
					#s.send_header('Content-Length', filesize)
					s.end_headers()
					shutil.copyfileobj(f,s.wfile)
		except:
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			s.wfile.close()
			return
		try:
			s.wfile.close()
		except Exception as errno:
			#xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			pass

	def getfidUrl(s, fid, cookiestr):
		xl = api_115(cookiestr)
		filecopypc=''
		cid=''
		try:
			fidUrl=''
			if s.fidDownloadurl.has_key(fid):
				(strtime,fidUrl)=s.fidDownloadurl[fid].split(' ')
				timespan=long(time.time())-long(strtime)
				if timespan>=18000:
					fidUrl=''
			if fidUrl=='':
				fpc=xl.getpc(fid)
				fidUrl=xl.getfiledownloadurl(fpc)
				s.fidDownloadurl[fid]=str(long(time.time()))+' '+fidUrl
			return fidUrl
		except Exception as errno:
			errorstr=' '.join(('error:', str(errno)))
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			return errorstr


	def urlopenwithRetry(s,request):
		for _ in range(10):
			try:
				opener2 = urllib2.build_opener(SmartRedirectHandler)
				response= opener2.open(request,timeout=40)
				return response
				break
			except:
				time.sleep(1)
				pass
	'''
	Sends the requested file and add additional headers.
	'''
	def serveFile(s, fid, cookiestr, changeserver, sendData,name):
		fidUrl = s.getfidUrl( fid, cookiestr)
		if not fidUrl:
			s.send_response(403)
			return
		filedownloadurl,downcookie=fidUrl.split('|')
		if not s.fileSize.has_key(fid):
			s.fileSize[fid]=-1
		if not s.fidSemaphores.has_key(fid):
			s.fidSemaphores[fid]=Semaphore(s.accessThreadNum)

		rangeBegin=0
		#处理转发请求headers---begin
		reqheaders={}
		for key in s.headers:
			#xbmc.log(msg='zzzdebug:XBMCLocalProxy: reqheaders %s:%s'%(key, s.headers[key]))
			if key.lower()!='host' and key.lower()!='user-agent':
				#opener.addheader(key,s.headers[key])
				#request.add_header(key, s.headers[key])
				reqheaders[key]=s.headers[key]
			if key.lower()=='range':
				strRange=s.headers[key]
				rangeBegin=int(strRange[strRange.index('=')+1:strRange.index('-')])
		#request.add_header('User-Agent','Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)')
		#request.add_header('Referer', 'https://115.com/?cid=0&offset=0&mode=wangpan')
		#request.add_header('Cookie',cookiestr+downcookie+';')
		reqheaders['User-Agent']='Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)'
		reqheaders['Referer']='https://115.com/?cid=0&offset=0&mode=wangpan'
		reqheaders['Cookie']=cookiestr+downcookie+';'
		#处理转发请求headers---end
		#转发请求
		request = urllib2.Request(filedownloadurl, headers=reqheaders)
		if sendData==0:
			request.get_method = lambda : 'HEAD'
		response=None
		#线程加塞
		s.fidSemaphores[fid].acquire()
		xbmc.log('lockcount+1 sendData=%d bytes=%d-'%(sendData,rangeBegin),level=xbmc.LOGERROR)
		err=False
		
		wcode=200
		wheaders={}
		#wheaders={'Connection':'Keep-Alive','Keep-Alive':'timeout=20, max=100'}
		try:
			
			response = s.urlopenwithRetry(request)
			
			#s.protocal_version ='HTTP/1.1'
			wcode=response.code
			headers=response.info()
			#xbmc.log(msg=str(headers),level=xbmc.LOGERROR)
			keys=['content-length','content-range','accept-ranges','date']
			for key in headers:
				try:
					if key=='content-length' and s.fileSize[fid]==-1:
						#文件大小
						s.fileSize[fid]= int(headers[key])
					if key.lower() in keys:
						#xbmc.log(msg='zzzdebug:'+key+':'+headers[key],level=xbmc.LOGERROR)
						wheaders[key]=headers[key]
				except Exception as errno:
					xbmc.log(msg='zzzdebug:sendheaderERR:%s'%(errno),level=xbmc.LOGERROR)
					pass
			
			mimetype, _ =mimetypes.guess_type(name.lower())
			if not mimetype:
				mimetype='application/octet-stream'
			xbmc.log(msg='zzzdebug:mimetype:%s'%(mimetype),level=xbmc.LOGERROR)
			wheaders['content-type']=mimetype
			
			
		except:
			xbmc.log('lockcount-1 HEAD error',level=xbmc.LOGERROR)
			xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
			s.send_response(404)
			err=True
		finally:
			response.close()
			#time.sleep(1)
			s.fidSemaphores[fid].release()
			xbmc.log('lockcount-1 HEAD over err=%s'%str(err),level=xbmc.LOGERROR)
			if sendData==0:
				s.send_response(wcode)
				for key in wheaders:
					s.send_header(key,wheaders[key])
				s.end_headers()
			if err or sendData==0:
				return

		xbmc.log('rangeBegin=%d,s.fileSize[fid]=%d'%(rangeBegin,s.fileSize[fid]),level=xbmc.LOGERROR)
		sendheadover=False
		while rangeBegin<s.fileSize[fid]:
			#改变获取范围的结束位置
			rangeEnd=rangeBegin+s.blockSize-1
			if rangeEnd>=s.fileSize[fid]:
				rangeEnd=s.fileSize[fid]-1
			reqheaders['Range']='bytes=%d-%d'%(rangeBegin,rangeEnd)
			request = urllib2.Request(filedownloadurl, headers=reqheaders)
			#线程加塞
			s.fidSemaphores[fid].acquire()
			xbmc.log('lockcount+1 bytes=%d-%d'%(rangeBegin,rangeEnd),level=xbmc.LOGERROR)
			err=False
			try:
				response = s.urlopenwithRetry(request)
				if not sendheadover:
					s.send_response(wcode)
					for key in wheaders:
						s.send_header(key,wheaders[key])
					s.end_headers()
					sendheadover=True
				fileout=s.wfile
				shutil.copyfileobj(response,fileout)
				'''
				readcount1=16384
				readcount2=2048

				st=0

				buf="INIT"
				while (buf!=None and len(buf)>0):
					buf=response.read(readcount1)
					st=0
					#xbmc.log(msg='zzzdebug:XBMCLocalProxy: write..%s'%(len(buf)),level=xbmc.LOGERROR)
					while (st<(len(buf)-readcount2)):
						fileout.write(buf[st:st+readcount2])
						st+=readcount2
					fileout.write(buf[st:len(buf)])
				'''
				rangeBegin+=s.blockSize
			except:
				xbmc.log('lockcount-1 getandsendData error bytes=%d-%d'%(rangeBegin,rangeEnd),level=xbmc.LOGERROR)
				xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
				
				err=True
				#s.send_response(404)
			
			finally:
				response.close()
				#time.sleep(1)
				response=None
				s.fidSemaphores[fid].release()
				xbmc.log('lockcount-1 copyfileobj finally err=%s'%str(err),level=xbmc.LOGERROR)
				if err:
					break
				#time.sleep(1)
				#xbmc.log(msg='zzzdebug:XBMCLocalProxy:'+time.asctime()+' Closing connection')
		try:
			s.wfile.close()
		except:
			pass


class Server(HTTPServer):
	'''HTTPServer class with timeout.'''
	def get_request(self):
		'''Get the request and client address from the socket.'''
		self.socket.settimeout(20.0)
		result = None
		while result is None:
			try:
				result = self.socket.accept()
				#self.socket.getpeername()
				#self.socket = ssl.wrap_socket (self.socket,keyfile = xbmc.translatePath(os.path.join( __cwd__,'key.pem')),certfile=xbmc.translatePath(os.path.join( __cwd__,'server.pem')),server_side=True),
				#xbmc.log(msg='ssl.wrap_socket',level=xbmc.LOGERROR)
			except socket.timeout:
				pass
			except:
				xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
		result[0].settimeout(4000)
		return result

class ThreadedHTTPServer(ThreadingMixIn, Server):
	'''Handle requests in a separate thread.'''
HOST_NAME = '0.0.0.0'
PORT_NUMBER =  int(xbmcaddon.Addon().getSetting('listen_port'))

if __name__ == '__main__':
	#fid_pclist=plugin.get_storage('fid_pclist')
	cookiejar = cookielib.LWPCookieJar()
	try:
		if os.path.exists(cookiefile):
			cookiejar.load(
				cookiefile, ignore_discard=True, ignore_expires=True)
			_cookiestr=''
			for k,v in cookiejar._cookies['.115.com']['/'].items():
				_cookiestr+=str(k)+'='+str(v.value)+';'
	except:
		xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
		exit()
	fid_pclist={}
	fid_downloadurls={}
	socket.setdefaulttimeout(40)
	server_class = ThreadedHTTPServer
	#MyHandler.protocol_version='HTTP/1.1'
	MyHandler.protocol_version='HTTP/1.0'
	httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
	xbmc.log(msg='XBMCLocalProxy Starts - %s:%s' % (HOST_NAME, PORT_NUMBER),level=xbmc.LOGERROR)
	while(not xbmc.abortRequested):
		httpd.handle_request()
	httpd.server_close()
	#fid_pclist.sync()
	xbmc.log(msg='XBMCLocalProxy Stop - %s:%s' % (HOST_NAME, PORT_NUMBER),level=xbmc.LOGERROR)