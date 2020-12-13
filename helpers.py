#VERSION: 1.40

# Author:
#  Christophe DUMEZ (chris@qbittorrent.org)

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the author nor the names of its contributors may be
#      used to endorse or promote products derived from this software without
#      specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# -*- coding: utf-8 -*-
import re, htmlentitydefs
import tempfile
import os
import StringIO, gzip, urllib,urllib2
import socket
import socks
import re
import xbmc

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
	def http_error_301(self, req, fp, code, msg, headers):  
		result = urllib2.HTTPRedirectHandler.http_error_301(
			self, req, fp, code, msg, headers)
		result.status = code
		return result
		
	def http_error_302(self, req, fp, code, msg, headers):
		result = urllib2.HTTPRedirectHandler.http_error_302(
			self, req, fp, code, msg, headers)
		result.status = code
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


# Some sites blocks default python User-agent
user_agent = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
#user_agent = 'User-Agent: Mozilla/5.0 (Linux; U; Android 6.0.1;)'
headers    = {'User-Agent': user_agent,'Accept-encoding': 'gzip,deflate','Accept-Language':'zh-cn','X-Requested-With': 'XMLHttpRequest'}
# SOCKS5 Proxy support
if os.environ.has_key("sock_proxy") and len(os.environ["sock_proxy"].strip()) > 0:
	proxy_str = os.environ["sock_proxy"].strip()
	m=re.match(r"^(?:(?P<username>[^:]+):(?P<password>[^@]+)@)?(?P<host>[^:]+):(?P<port>\w+)$", proxy_str)
	if m is not None:
		socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, m.group('host'), int(m.group('port')), True, m.group('username'), m.group('password'))
		socket.socket = socks.socksocket

def htmlentitydecode(s):
	# First convert alpha entities (such as &eacute;)
	# (Inspired from http://mail.python.org/pipermail/python-list/2007-June/443813.html)
	def entity2char(m):
		entity = m.group(1)
		if entity in htmlentitydefs.name2codepoint:
			return unichr(htmlentitydefs.name2codepoint[entity])
		return u" "  # Unknown entity: We replace with a space.
	t = re.sub(u'&(%s);' % u'|'.join(htmlentitydefs.name2codepoint), entity2char, s)

	# Then convert numerical entities (such as &#233;)
	t = re.sub(u'&#(\d+);', lambda x: unichr(int(x.group(1))), t)

	# Then convert hexa entities (such as &#x00E9;)
	return re.sub(u'&#x(\w+);', lambda x: unichr(int(x.group(1),16)), t)
	
def gethead(url, data=None,referer=None,h=None):
	if h:
		headers.update(h)
	req = urllib2.Request(url, headers = headers)
	if referer:
		req.add_header('Referer', referer)
	req.get_method = lambda : 'HEAD'
	opener = urllib2.build_opener(PassRedirectHandler)
	return opener.open(req,timeout=30)
		
def retrieve_url(url, data=None,referer=None,h=None,redirect=True,charset='auto',savecookie=False):
	""" Return the content of the url page as a string """
	if h:
		headers.update(h)
	req = urllib2.Request(url, headers = headers)
	if referer:
		req.add_header('Referer', referer)
	if redirect:
		opener = urllib2.build_opener(SmartRedirectHandler)
	else:
		opener = urllib2.build_opener(PassRedirectHandler)
	try:
		if data:
			response = opener.open(req, data=data,timeout=30)
		else:
			response = opener.open(req,timeout=30)
		if response.code==302:
			return response.info()['Location']
	except urllib2.URLError as errno:
		print(" ".join(("Connection error:", str(errno.reason))))
		return ""
	dat = response.read()
	
	# Check if it is gzipped
	if dat[:2] == '\037\213':
		# Data is gzip encoded, decode it
		compressedstream = StringIO.StringIO(dat)
		gzipper = gzip.GzipFile(fileobj=compressedstream)
		extracted_data = gzipper.read()
		dat = extracted_data
	info = response.info()
	if savecookie:
		cookie=info.getheader('Set-Cookie')
		if cookie:
			dat='feelfarcookie:'+cookie+dat
	if charset=='auto':
		charset = 'utf-8'
		try:
			ignore, charset = info['Content-Type'].split('charset=')
		except:
			pass
	dat = dat.decode(charset, 'replace')
	dat = htmlentitydecode(dat)
	return dat.encode('utf-8', 'replace')

def download_file(url, referer=None):
	""" Download file at url and write it to a file, return the path to the file and the url """
	file, path = tempfile.mkstemp()
	file = os.fdopen(file, "w")
	# Download url
	req = urllib2.Request(url, headers = headers)
	if referer is not None:
		req.add_header('referer', referer)
	response = urllib2.urlopen(req)
	dat = response.read()
	# Check if it is gzipped
	if dat[:2] == '\037\213':
		# Data is gzip encoded, decode it
		compressedstream = StringIO.StringIO(dat)
		gzipper = gzip.GzipFile(fileobj=compressedstream)
		extracted_data = gzipper.read()
		dat = extracted_data

	# Write it to a file
	file.write(dat)
	file.close()
	# return file path
	return path+" "+url
