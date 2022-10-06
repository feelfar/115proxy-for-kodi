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
from  __future__  import unicode_literals
import sys
import lib.six as six
from lib.six.moves.urllib import parse
from lib.six.moves.urllib import request
from lib.six.moves.urllib import response 
from lib.six.moves import http_cookiejar as cookielib
from lib.six.moves import html_entities as htmlentitydefs
from datetime import datetime
import base64
import uuid
import re
import time
import socket
import gzip
import json
import xbmc,xbmcaddon,xbmcvfs
try:
    xbmc.translatePath = xbmcvfs.translatePath
except AttributeError:
    pass
from threading import Semaphore
import os
import mimetypes
import shutil
#import ssl
from traceback import format_exc
from lib.six.moves.socketserver import ThreadingMixIn
from lib.six.moves.BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from cgi import parse_header, parse_multipart
from Cryptodome import Random
from Cryptodome.Hash import MD5
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Cryptodome.PublicKey import RSA

__cwd__=os.path.dirname(__file__)
__lib__  = xbmc.translatePath( os.path.join( __cwd__, 'lib' ) )
sys.path.append (__lib__)

from pyhtml import *
defaultUserAgent='Mozilla/5.0;  Mac  OS  X/10.15.7;  115Desktop/2.0.1.7'

_cookiestr=''

def encode_obj(in_obj):
    def encode_list(in_list):
        out_list = []
        for el in in_list:
            out_list.append(encode_obj(el))
        return out_list

    def encode_dict(in_dict):
        out_dict = {}
        for k, v in in_dict.items():
            out_dict[k] = encode_obj(v)
        return out_dict

    if isinstance(in_obj, six.text_type):
        return six.ensure_binary(in_obj)
    elif isinstance(in_obj, list):
        return encode_list(in_obj)
    elif isinstance(in_obj, tuple):
        return tuple(encode_list(in_obj))
    elif isinstance(in_obj, dict):
        return encode_dict(in_obj)
    return in_obj
    
class SmartRedirectHandler(request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):  
        result = request.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers)
        #result.status = code
        return result
        
    def http_error_302(self, req, fp, code, msg, headers):
        result = request.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)
        #result.status = code
        return result
        
class PassRedirectHandler(request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers): 
        infourl = response.addinfourl(fp, headers, req.get_full_url())
        infourl.status = code
        infourl.code = code
        return infourl
        
    def http_error_302(self, req, fp, code, msg, headers):
        infourl = response.addinfourl(fp, headers, req.get_full_url())
        infourl.status = code
        infourl.code = code
        return infourl
        
class api_115(object):
    downcookie=''
    def __init__(self, cookstr):
        if cookstr=='0':
            cookstr=_cookiestr
            #xbmc.log(cookstr,level=xbmc.LOGERROR)
        self.headers = {
            
            'User-Agent': defaultUserAgent,
            'Accept-encoding': 'gzip,deflate',
            'Cookie': cookstr,
        }
        self.user_id=None
        self.user_key=None
        if self.get_userkey() is False:
            xbmc.log(msg='Get userkey info failed!',level=xbmc.LOGERROR)
            
    def urlopen(self,url, data=None,referer=None,binary=False):
        #url=url
        reponse=''
        for i in range(1,5):
            try:
                req = request.Request(url,headers = self.headers)
                if referer:
                    req.add_header('Referer', referer)
                opener = request.build_opener(SmartRedirectHandler)
                if data:
                    if type(data) == str:
                        data=data.encode()
                    rsp = opener.open(req, data=data, timeout=15)
                else:
                    rsp = opener.open(req, timeout=15)
                
                if rsp.info().get('Content-Encoding') == 'gzip':
                    reponse = gzip.GzipFile(fileobj=six.BytesIO(rsp.read())).read()
                else:
                    reponse = rsp.read()
                if not binary:
                    reponse=six.ensure_text(reponse)
                #xbmc.log(msg=str(rsp.headers),level=xbmc.LOGERROR)
                self.downcookie=''
                for key,value in rsp.headers.items():
                    if key.lower()=='set-cookie':
                        downcookies = re.findall(r'(?:[0-9abcdef]{20,}|acw_tc)\s*\x3D\s*[0-9abcdef]{20,}', value, re.DOTALL | re.MULTILINE)
                        for downcook in downcookies:
                            self.downcookie+=downcook+';'
                rsp.close()
                break
            except Exception as e:
                xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
        
        return reponse
        
    def jsonload(self,data):
        try:
            data= data.replace('\n','').replace('\r','')
            data=json.loads(data[data.index('{'):])
            return data
        except:
            return {'state':False,'error':'jsonload error'}
            
    def gettaglist(self):
        data=self.urlopen('https://webapi.115.com/label/list?user_id=&offset=0&limit=11500&sort=create_time&order=desc')
        return json.loads(data[data.index('{'):])
            
    def settag(self,fid,tag):
        data = parse.urlencode({'fid': fid,'file_label':tag})
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
                    data=parse.urlencode({'file_label': file_label,'cid':cid,'aid':'1','limit':str(pageitem),
                                'o':sorttype,'asc':sortasc,'offset':str(offset),'format':'json','date':'','pick_code':'','type':typefilter,'source':''})
                else:
                    data=parse.urlencode({'search_value': search_value,'cid':cid,'aid':'1','limit':str(pageitem),
                                'o':sorttype,'asc':sortasc,'offset':str(offset),'format':'json','date':'','pick_code':'','type':typefilter,'source':''})
                data=self.urlopen('http://web.api.115.com/files/search?'+data)
            else:
                data = parse.urlencode({'aid': '1','cid':cid,'limit':pageitem,'offset':offset,'type':typefilter,'star':star,'custom_order':'2',
                                    'o':sorttype,'asc':sortasc,'nf':nf,'show_dir':'1','format':'json','_':str(int(time.time()))})
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
        data = parse.urlencode({'pid': pid,'cname':cname})
        try:
            data=self.urlopen('http://web.api.115.com/files/add',data=data)
            data= json.loads(data[data.index('{'):])
            return data['cid']
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return ''
            
    def copy(self,fid,cid):
        data = parse.urlencode({'fid': fid,'pid':cid})
        try:
            data=self.urlopen('http://web.api.115.com/files/copy',data=data)
            data= json.loads(data[data.index('{'):])
            return data['state']
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return False
            
    def rename(self,fid,newname):
        data = parse.urlencode({'fid': fid,'file_name':newname})
        try:
            data=self.urlopen('http://web.api.115.com/files/edit',data=data)
            data= json.loads(data[data.index('{'):])
            return data['state']
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return False
    
    def batchrename(self,namedict):
        newnames={}
        for key,value in namedict.items():
            newnames['files_new_name[%s]'%key]=value
        data = parse.urlencode(newnames)
        try:
            data=self.urlopen('https://webapi.115.com/files/batch_rename',data=data)
            data= json.loads(data[data.index('{'):])
            return data['state']
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return False
            
    def batchcidrename(self,cid,oldnewnames):
        namedict={}
        files=[]
        self.getallfiles(cid,files)
        for f in files:
            if f['n'] in oldnewnames:
                namedict[f['fid']]=oldnewnames[f['n']]
        self.batchrename(namedict)
        
    def getallfiles(self,cid,files):
        data=self.getfilelist(cid=cid,offset=0,pageitem=1150,star='0',sorttype='user_ptime',sortasc='0')
        if 'data' in data:
            resp = data['data']
            for d in resp:
                if 'fid' in d:
                    files.append(d)
                elif 'pid' in d:
                    cid=d['cid']
                    self.getallfiles(cid,files)
                    
    def countfiles(self,cid):
        try:
            data=self.urlopen('https://webapi.115.com/category/get?cid=%s'%(cid))
            data= json.loads(data[data.index('{'):])
            return int(data['count'])
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            
    def pathdeep(self,cid):
        try:
            data=self.urlopen('https://webapi.115.com/category/get?cid=%s'%(cid))
            data= json.loads(data[data.index('{'):])
            return int(len(data['paths']))
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            
    def delete(self,fids):
        data={'pid':0}
        i=0
        for fid in fids:
            data['fid['+str(i)+']']=fid
            i+=1
        data = parse.urlencode(data)
        try:
            data=self.urlopen('http://web.api.115.com/rb/delete',data=data)
            data= json.loads(data[data.index('{'):])
            return data['state']
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return ''
    
    def get_userkey(self):
        try:
            data=self.urlopen('http://proapi.115.com/app/uploadinfo')
            data= json.loads(data[data.index('{'):])
            self.user_id=str(data['user_id'])
            self.user_key=str(data['userkey']).upper()
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return False
            
    def get_preid(self,pc):
        try:
            file_url=self.getfiledownloadurl(pc)
            filedownloadurl,downcookie=file_url.split('|')

            reqheaders={}
            reqheaders['User-Agent']=defaultUserAgent
            reqheaders['Referer']='https://115.com/?cid=0&offset=0&mode=wangpan'
            reqheaders['Cookie']=self.headers['Cookie']+downcookie+';'
            reqheaders['Range']='bytes=0-131071';
            req = request.Request(filedownloadurl, headers=reqheaders)
            response=None
            preid=''
            opener = request.build_opener(SmartRedirectHandler)
            rsp = opener.open(req, timeout=15)
            if rsp.info().get('Content-Encoding') == 'gzip':
                reponse = gzip.GzipFile(fileobj=six.BytesIO(rsp.read())).read()
            else:
                reponse = rsp.read()
            sha = SHA1.new()
            sha.update(bytes(reponse))
            preid = sha.hexdigest()
            return preid.upper()
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return ''
        
    def import_file_with_sha1(self,preid,fileid,filesize,filename,cid,tm):
        target='U_1_'+str(cid)
        #tm=str(int(time.time()))+'000'
        #tm='16649927390000'
        xbmc.log(msg="tm:"+tm,level=xbmc.LOGERROR)
        
        sha=SHA1.new()
        sha.update( str.encode(self.user_id+fileid+ fileid +target+'0'))
        s1 = sha.hexdigest()
        xbmc.log(msg="s1:"+s1,level=xbmc.LOGERROR)
        s2=self.user_key+s1+"000000"
        
        sha=SHA1.new()
        sha.update(str.encode(s2))
        sig=sha.hexdigest().upper()
        xbmc.log(msg="sig:"+sig,level=xbmc.LOGERROR)
        
        useridmd5 = MD5.new()
        useridmd5.update(self.user_id.encode())
        struidmd5=useridmd5.hexdigest()
        xbmc.log(msg="useridmd5:"+struidmd5,level=xbmc.LOGERROR)
        
        tokenmd5 = MD5.new()
        appVersion = "2.0.1.7"
        tokenstr = "Qclm8MGWUv59TnrR0XPg" +fileid +str(filesize)+ preid + self.user_id + tm + struidmd5 +appVersion;
        tokenmd5.update(tokenstr.encode())
        token=tokenmd5.hexdigest()
        xbmc.log(msg="token:"+token,level=xbmc.LOGERROR)
        
        url=("http://uplb.115.com/3.0/initupload.php?rt=0&topupload=0&isp=0&appid=0&appversion=%s&format=json&sig=%s&token=%s&t=%s")%(appVersion,sig,token,tm)
        postData=('preid=%s&fileid=%s&quickid=%s&app_ver=%s&filename=%s&filesize=%s&exif=&target=%s&userid=%s')%(preid,fileid,fileid,appVersion,filename,filesize,target,self.user_id)
        try:
            data=self.urlopen(url,data=postData)
            data= json.loads(data[data.index('{'):])
            
            if data['status']==2 and data['statuscode']==0:
                return True
            else:
                xbmc.log(msg=filename+' upload failed.',level=xbmc.LOGERROR)
                return False
        except Exception as errno:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return False
            
    def exportfid(self,name,length,sha1,pc):
        fidsha1=''
        try:
            preid=self.get_preid(pc)
            fidsha1='115://'+name+'|'+length+'|'+sha1+'|'+preid;
        except Exception as e:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
        return fidsha1
    
    def exportcid(self,outlist,cid,pathdeep=0):
        data=self.getfilelist(cid=cid,offset=0,pageitem=1150,star='0',sorttype='user_ptime',sortasc='0')
        paths=''
        pathlist=[]
        if 'path' in data:
            for item in data['path']:
                pathlist.append(item['name'])
            if len(pathlist)>=pathdeep:
                pathlist=pathlist[pathdeep:]
            paths='|'.join(pathlist)
        if 'data' in data:
            resp = data['data']
        for d in resp:
            if 'fid' in d:
                fidsha1=self.exportfid(d['n'],str(d['s']),d['sha'],d['pc'])
                if paths!='':
                    fidsha1=fidsha1+'|'+paths
                outlist.append(fidsha1)
            elif 'pid' in d:
                cid=d['cid']
                self.exportcid(outlist,cid,pathdeep)
        
    def url_is_alive(self,url):
        try:
            rspcode=0
            req = request.Request(url,headers = self.headers)
            req.get_method = lambda : 'HEAD'
            req.add_header('keep_alive','false')
            opener = request.build_opener(SmartRedirectHandler)
            rsp = opener.open(req, timeout=15)
            rspcode=str(rsp.code)
            rsp.close()
            return rspcode=='200'
        except:
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return False
    def notecatelist(self):
        data=self.urlopen('https://note.115.com/?ct=note&ac=cate&has_picknews=1')
        return self.jsonload(data)
        
    def noteaddcate(self,cname):
        data = parse.urlencode(encode_obj({'cname': cname,'up_key':'tn__%d_0'%(int(time.time()))}))
        data=self.urlopen('https://note.115.com/?ct=note&ac=addcate',data=data)
        return self.jsonload(data)

    def notegetcateid(self,cname):
        cid=0
        data=self.notecatelist()
        if data['state'] and data['data']:
            for cate in data['data']:
                if cate['cname']==cname:
                    cid=int(cate['cid'])
                    break
        if cid==0:
            data = self.noteaddcate(cname)
            if data['state']:
                cid=int(data['data']['cid'])
        return cid
    
    def notesave(self,cid,nid,title,content):
        data = parse.urlencode(encode_obj({'cid': cid,'nid':nid,'subject':title,'content':content,'is_html':0,'toc_ids':''}))
        data = self.urlopen('https://note.115.com/?ct=note&ac=save',data=data)
        return self.jsonload(data)
        
    def notelist(self,cid,start):
        data = parse.urlencode(encode_obj({'ct':'note','page_size':90,'has_picknews':1,'cid': cid,'keyword':'','start':start,'_':int(time.time())}))
        data = self.urlopen('https://note.115.com/?'+data)
        return self.jsonload(data)
    
    def notedelete(self,nid):
        data = parse.urlencode(encode_obj({'nid': nid}))
        data = self.urlopen('https://note.115.com/?ct=note&ac=delete',data=data)
        return self.jsonload(data)
        
    def notedetail(self,nid):
        data = parse.urlencode(encode_obj({'ct': 'note','nid':nid,'ac':'detail'}))
        data = self.urlopen('https://note.115.com/?'+data)
        return self.jsonload(data)
            
    def notegetcontent(self,cname,notetitle):
        content=''
        cid=self.notegetcateid(cname)
        data=self.notelist(cid=cid,start=0)
        nid=0
        if data['state'] and data['data']:
            for note in data['data']:
                if note['title']==notetitle:
                    nid=int(note['nid'])
                    break
        if nid:
            data = self.notedetail(nid)
            if data['state']:
                content=data['data']['content']
        return content

    def notegetpcurl(self,pc):
        content=''
        cid=self.notegetcateid('pickcodeurl')
        data=self.notelist(cid=cid,start=0)
        nid=0
        nidolds=''
        if data['state'] and data['data']:
            for note in data['data']:
                #xbmc.log(msg='zzzzz: %s %s %d %d'%(pc,note['title'],int(time.time()) , int(note['update_time'])),level=xbmc.LOGERROR)
                if (int(time.time()) - int(note['update_time']))>60*3600:
                    nidolds+=note['nid']+','
                else:
                    if note['title']==pc:
                        nid=int(note['nid'])
                        break
        if nidolds:
             self.notedelete(nidolds)
        if nid:
            data = self.notedetail(nid)
            if data['state']:
                content=data['data']['content']
        return content
            
            
    def notesavecontent(self,cname,notetitle,content):
        state=False
        cid=self.notegetcateid(cname)
        data=self.notelist(cid=cid,start=0)
        nid=0
        if data['state'] and data['data']:
            for note in data['data']:
                if note['title']==notetitle:
                    nid=int(note['nid'])
                    break
        data = self.notesave(cid=cid,nid=nid,title=notetitle,content=content)
        state = data['state']
        return state
                    
    def notedeleteolds(self,cname):
        state=False
        cid=self.notegetcateid(cname)
        data=self.notelist(cid=cid,start=90)
        nids=''
        if data['state'] and data['data']:
            for note in data['data']:
                nids=nids+note['nid']+','
        if nids:
            data = self.notedelete(nid=nids)
            state = data['state']
        return state

    g_kts = [240, 229, 105, 174, 191, 220, 191, 138, 26, 69, 232, 190, 125, 166, 115, 184, 222, 143, 231, 196, 69, 218, 134, 196, 155, 100, 139, 20, 106, 180, 241, 170, 56, 1, 53, 158, 38, 105, 44, 134, 0, 107, 79, 165, 54, 52, 98, 166, 42, 150, 104, 24, 242, 74, 253, 189, 107, 151, 143, 77, 143, 137, 19, 183, 108, 142, 147, 237, 14, 13, 72, 62, 215, 47, 136, 216, 254, 254, 126, 134, 80, 149, 79, 209, 235, 131, 38, 52, 219, 102, 123, 156, 126, 157, 122, 129, 50, 234, 182, 51, 222, 58, 169, 89, 52, 102, 59, 170, 186, 129, 96, 72, 185, 213, 129, 156, 248, 108, 132, 119, 255, 84, 120, 38, 95, 190, 232, 30, 54, 159, 52, 128, 92, 69, 44, 155, 118, 213, 27, 143, 204, 195, 184, 245]

    g_key_s = [0x29, 0x23, 0x21, 0x5E]

    g_key_l = [120, 6, 173, 76, 51, 134, 93, 24, 76, 1, 63, 70]
    
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

    n=0x8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683
    e=0x10001
    def rsa_encrypt(self, bsrc):
        pretemp=bytearray(128-len(bsrc))
        for i in range(len(pretemp)):
            pretemp[i]=0xff
        pretemp[0]=0x00
        pretemp[1]=0x02
        pretemp[len(pretemp)-1]=0x00
        pretemp.extend(bsrc)
        isrc=int.from_bytes(pretemp,'big')
        ienc=pow(isrc,self.e,self.n)
        return ienc.to_bytes(128, 'big')
        
    def rsa_decrypt(self,bsrc):
        isrc=int.from_bytes(bsrc,'big')
        idec=pow(isrc,self.e,self.n)
        bdec=idec.to_bytes(128, 'big')
        index00=bdec[1:].index(0x00)
        return bdec[index00+2:]
        
    def m115_asym_encode(self,src, srclen):
        m = 128 - 11
        ret = bytearray()
        for i in range(int((srclen + m - 1) / m)):
            bsrc=bytes(src[i*m:i*m+m])
            #plugin.log.error(len(bsrc))
            #plugin.log.error('%s %s ...%s %s'%(bsrc[0],bsrc[1],bsrc[30],bsrc[31]))
            #rettemp=self.pcipher.encrypt(bsrc)
            #rettemp=self.cipher.encrypt(bsrc)
            rettemp=self.rsa_encrypt(bsrc)
            #plugin.log.error(len(rettemp))
            ret.extend(rettemp);
            #ret += base64.b64decode(rettemp);
        ret = base64.b64encode(ret)
        return ret

    def m115_asym_decode(self,src, srclen):
        m = 128
        #plugin.log.error(srclen)
        ret = bytearray()
        for i in range(int((srclen + m - 1) / m)):
            rettemp=bytes(src[i*m:i*m+m])
            #dsize = SHA.digest_size
            #sentinel = Random.new().read(16+dsize)
            #message=self.scipher.decrypt(rettemp,'')
            #message=self.cipher.decrypt(rettemp,'')
            message=self.rsa_decrypt(rettemp)
            #message=self.scipher.decrypt(rettemp,sentinel)
            #digest = SHA.new(message[:-dsize]).digest()
            #if digest==message[-dsize:]:                # Note how we DO NOT look for the sentinel
            #    plugin.log.error("Encryption was correct.")
            #else:
            #    plugin.log.error("Encryption was not correct.")
            ret.extend(message)
        #ssss=0
        #for ss in ret:
        #    plugin.log.error('%d:%d'%(ssss,ord(ss)))
        #    ssss+=1
        return ret
        
    def m115_encode(self,src, tm):
        #plugin.log.error(src)
        key = MD5.new()
        #plugin.log.error(b'tm=%s'%tm)
        key.update(('!@###@#%sDFDR@#@#'%tm).encode())
        bkey = bytearray()
        bkey.extend( key.hexdigest().encode())
        #plugin.log.error(len(bkey))
        #plugin.log.error(key.hexdigest())
        #plugin.log.error('%d %d ...%d %d'%(bkey[0],bkey[1],bkey[30],bkey[31]))
        bsrc = bytearray()
        bsrc.extend(src.encode())
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
        bkey1.extend(key.encode())
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
        result = ''
        tm = str((int(int(time.time()))))
        data=self.urlopen("https://webapi.115.com/files/download?pickcode="+pc+"&_="+tm)
        data= self.jsonload(data)
        if data['state']:
            result=data['file_url']
        if not result:
            content=self.notegetpcurl(pc=pc)
            if content:
                if self.url_is_alive(content):
                    #xbmc.log('url_is_alive '+content,level=xbmc.LOGERROR)
                    result=content
        if not result:
            pcencode = self.m115_encode((json.dumps({'pickcode': pc})).replace(' ',''),tm)
            data=self.urlopen('http://proapi.115.com/app/chrome/downurl?t='+tm,data=parse.urlencode({'data':pcencode['data']}))
            jsondata = json.loads(data[data.index('{'):])
            if jsondata['state'] != True:
                return ''
            decodetmp=self.m115_decode(jsondata['data'], pcencode['key'])
            bdecode = bytearray()
            bdecode.extend(decodetmp)
            jsondata = json.loads(bdecode.decode())
            jsondata=jsondata[list(jsondata.keys())[0]]
            if 'url' in jsondata:
                result = jsondata['url']['url']
                self.notesavecontent(cname='pickcodeurl',notetitle=pc,content=result)
        #xbmc.log('url_return '+result,level=xbmc.LOGERROR)
        return result+'|'+self.downcookie

    def oldgetfiledownloadurl(self,pc):
        bad_server = ''
        result = ''
        try:
            data=self.urlopen('https://webapi.115.com/files/download?pickcode='+pc+'&_='+str(int(time.time())))
            data= json.loads(data[data.index('{'):])
            if data['state']:
                result=data['file_url']
            else:
                data=self.urlopen('http://proapi.115.com/app/chrome/down?method=get_file_url&pickcode='+pc)
                data= json.loads(data[data.index('{'):])
                if data['state']:
                    for value in data['data'].values():
                        if 'url' in value:
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
            data=parse.urlencode({'tool':'subtitle-subtitle-converter','parameters':jsonsrt})
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
            self.raw_requestline = self.rfile.readline(65536*1024+1)
            if len(self.raw_requestline) > 65536*1024:
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
        except socket.timeout as errno:
            #a read or a write timed out.  Discard this connection
            self.log_error('Request timed out: %r', errno)
            self.close_connection = 1
            return
    '''
    Serves a HEAD request
    '''
    def do_HEAD(s):
        xbmc.log( 'XBMCLocalProxy: Serving HEAD request...')
        s.answer_request(0)

    '''
    Serves a GET request.
    '''
    def do_GET(s):
        xbmc.log( 'XBMCLocalProxy: Serving GET request...')
        s.answer_request(1)
        
    def parse_POST(s):
        ctype, pdict = parse_header(s.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = parse_multipart(s.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(s.headers['content-length'])
            postvars = parse.parse_qs(
                    s.rfile.read(length).decode ('utf-8'), 
                    keep_blank_values=True)
        else:
            postvars = {}
        return postvars

    def do_POST(s):
        postvars = s.parse_POST()
        s.answer_request(1,postvars)
        
    def answer_request(s, sendData,postvars={}):
        try:
            urlsp=parse.urlparse(s.path)
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

                s.wfile.write( six.ensure_binary(t.render()))
                
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
                                    'url':parse.unquote_plus(url)
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
                    '''%(name,parse.unquote_plus(url))
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
                    qs=parse.parse_qs(urlsp.query, keep_blank_values=True)
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
                                    'url':parse.unquote_plus(url)
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
                    '''%(name,parse.unquote_plus(url))
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
                cookiestr=parse.unquote_plus(cookiestr)
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
                        s.wfile.write(six.ensure_binary(extm3u))
                    else:
                        xl = api_115('0')
                        data = parse.urlencode({'op': 'vip_push','pickcode':pc,'sha1':sha})
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
                        htmlrender=six.ensure_binary(t.render())
                        s.send_header('Content-Length', len(htmlrender))
                        s.end_headers()
                        s.wfile.write(htmlrender)
                except Exception as errno:
                    xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
                    
            elif request_path=='/play':
                try:
                    qs=parse.parse_qs(urlsp.query, keep_blank_values=True)
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
                                                            parse.quote_plus(sub['url']),
                                                            parse.quote_plus(sub['title'])))
                        subtrack+='''<track src='%s' kind='Subtitles' srclang='%s' label='%s' %s>
'''%(suburl,sub['language'],parse.quote_plus(sub['title']),defaultsub)
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
                    playhtml=six.ensure_binary(playhtml)
                    s.send_header('Content-Length', len(playhtml))
                    s.end_headers()
                    s.wfile.write(playhtml)
                except Exception as errno:
                    xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
                
            elif request_path=='/files':
                qs=parse.parse_qs(urlsp.query, keep_blank_values=True)
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
                        tagname=tag['name']
                        taglist.append([tagname,tag['id']])
                tagnamelist=[q[0] for q in taglist]
                tagidlist=[q[1] for q in taglist]
                
                searchvalue=qs.get('searchvalue',[''])[0]
                if len(searchvalue)<3:searchvalue=''
                searchstr=searchvalue
                if searchvalue[0:2]=='t:':
                    searchstr=searchvalue[2:]
                    try:
                        searchstr=('tag'+tagidlist[tagnamelist.index(searchstr)])
                    except:
                        pass
                #pageitem= int(xbmcaddon.Addon().getSetting('pageitem'))
                pageitem= int(qs.get('pageitem',[0])[0])
                if pageitem==0: pageitem=80
                if pageitem<8: pageitem=8
                if pageitem>200: pageitem=200
                data=xl.getfilelist(cid=cid,offset=offset,pageitem=pageitem,star=star,sorttype=sorttype,sortasc=sortasc,typefilter=typefilter,nf='0',search_value=searchstr)
                #xbmc.log(str(data),level=xbmc.LOGERROR)
                if data['state']:
                    def sha1inout(ctx):
                        for title, url in [('导入SHA1','/sha1?'+parse.urlencode({'mode':'beginimport','cid': cid}))]:
                            yield td(a(href=url,class_='sha1import')(title))
                    def sort(ctx):
                        for title, url in [
                                        ('从新到旧','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':0,'searchvalue':searchvalue,'star': star})),
                                        ('从旧到新','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':1,'searchvalue':searchvalue,'star': star})),
                                        ('从小到大','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':2,'searchvalue':searchvalue,'star': star})),
                                        ('从大到小','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':3,'searchvalue':searchvalue,'star': star})),
                                        ('从A到Z','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':4,'searchvalue':searchvalue,'star': star})),
                                        ('从Z到A','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':5,'searchvalue':searchvalue,'star': star}))]:
                            yield  td(a(href=url,class_='sort')(title))
                    def filters(ctx):
                        for title, url in [
                                        ('全部','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':0,'cursorttype':cursorttype,'searchvalue':searchvalue})),
                                        ('视频','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':4,'cursorttype':cursorttype,'searchvalue':searchvalue})),
                                        ('图片','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':2,'cursorttype':cursorttype,'searchvalue':searchvalue})),
                                        ('音乐','/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'typefilter':3,'cursorttype':cursorttype,'searchvalue':searchvalue}))]:
                            yield td(a(href=url,class_='typefilter')(title))
                    def paths(ctx):
                        if 'path' in data:
                            for item in data['path']:
                                title=''
                                url=''
                                if str(item['cid'])!=str(cid):
                                    title='返回到【%s】'%(item['name'])
                                    url='/files?'+parse.urlencode({'cid': item['cid'],'offset':0,'pageitem':pageitem,'cursorttype':cursorttype})
                                    yield td(a(href=url,class_='path',title=title)(title))
                    def searchcur(ctx):
                        cidname=''
                        if 'path' in data:
                            if len(data['path'])>0:
                                cidname=data['path'][-1]['name']
                        if 'folder' in data:
                            cidname=data['folder']['name']
                        if cidname!='':
                            def tagnameoptions(ctx):
                                for tagname in tagnamelist:
                                    yield option(value='t:'+tagname)
                            url='/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,'cursorttype':cursorttype})
                            title='当前【%s】'%(cidname)
                            yield form(action='/files',method='GET')(
                                input_( type='hidden', name="cid",value=cid),
                                input_( type='hidden', name="cursorttype",value=cursorttype),
                                input_( type='hidden', name="pageitem",value=pageitem),
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
                        yield td('每页')
                        pageitems=[8,16,40,80,120,200]
                        def optionspageitem(ctx):
                            for pi in pageitems:
                                url='/files?'+parse.urlencode({'cid': cid,'offset':offset,'pageitem':pi,
                                'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
                                if pi==pageitem:
                                    yield option(value=url,selected='selected',class_='pagesel')(str(pi))
                                else:
                                    yield option(value=url)(str(pi))
                        yield td(select(onchange='if (this.value) window.location.href=this.value',class_='pagesel')(optionspageitem))
                        yield td('项')
                        if curpage>1:
                            url='/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':pageitem,
                            'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
                            yield td(a(href=url,title='第一页',class_='pagesel')('|<'),class_='pagesel')
                            
                            url='/files?'+parse.urlencode({'cid': cid,'offset':pageitem*(curpage-2),'pageitem':pageitem,
                            'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
                            yield td(a(href=url,title='上一页',class_='pagesel')('<'),class_='pagesel')
                        else:
                            yield td(a(href='#',title='第一页',class_='pagesel')('|<'),class_='pagesel')
                            yield td(a(href='#',title='上一页',class_='pagesel')('<'),class_='pagesel')
                        def optionspage(ctx):
                            for page in range(1,pages+1):
                                url='/files?'+parse.urlencode({'cid': cid,'offset':pageitem*(page-1),'pageitem':pageitem,
                                'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
                                #offlast=offset+pageitem
                                #if offlast>count:
                                #    offlast=count
                                strpage='第%03d页'%(page)
                                if curpage==page:
                                    yield option(value=url,selected='selected',class_='pagesel')(strpage)
                                else:
                                    yield option(value=url)(strpage)
                        yield td(select(onchange='if (this.value) window.location.href=this.value',class_='pagesel')(optionspage),class_='pagesel')
                        yield td('共%03d页'%(pages),class_='pagesel')
                        
                        if curpage<pages:
                            url='/files?'+parse.urlencode({'cid': cid,'offset':pageitem*(curpage),'pageitem':pageitem,
                            'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
                            yield td(a(href=url,title='下一页',class_='pagesel')('>'),class_='pagesel'),
                            
                            url='/files?'+parse.urlencode({'cid': cid,'offset':pageitem*(pages-1),'pageitem':pageitem,
                            'cursorttype':cursorttype,'typefilter':typefilter,'searchvalue':searchvalue,'star': star})
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
                            sha1url=''
                            locurl=''
                            ifFolder=False
                            isvideo=False
                            ism3u8=False
                            mimetype=''
                            if 'sha' in item:
                                ifFolder=False
                                if cid!=int(item['cid']):
                                    locurl='/files?'+parse.urlencode({'cid':item['cid'],'offset':0,'pageitem':pageitem,'typefilter':typefilter,'cursorttype':0,'searchvalue':''})
                                title=item['n']
                                mimetype, _ =mimetypes.guess_type('a.'+item['ico'].lower())
                                url='%s://%s/115/%s/%s/%s/%s' % (s.request_version.split('/')[0],s.headers.get('Host'),item['fid'],'0','0',parse.quote_plus(six.ensure_binary(title)))
                                sha1url='/sha1?'+parse.urlencode({'mode':'exportfid','name': item['n'],'length': item['s'],'sha1': item['sha'],'pc': item['pc']})
                                #if item['ico'].lower() in ['mp4', 'wmv', 'avi', 'mkv', 'mpg','ts','vob','m4v','mov','flv','rmvb']:
                                if 'iv' in item:
                                    isvideo=True
                                    '''
                                    sourceurl=parse.quote_plus('%s://%s/deo/%s/%s/%s/%s' % (s.request_version.split('/')[0],s.headers.get('Host'),item['fid'],'0','0','a.mp4'))
                                    sourceurl='%s://%s/115/%s/%s/%s/%s' % (s.request_version.split('/')[0],s.headers.get('Host'),item['fid'],'0','0',parse.quote_plus(title))
                                    url='deovr://%s' % (sourceurl)
                                    #url='/giz/%s/%s/%s/%s' % (item['fid'],'0','0',parse.quote_plus(title+'.json'))
                                    #url='/deo/%s/%s/%s/%s' % (item['fid'],'0','0',parse.quote_plus(title)+'.json')
                                    
                                    video_code =  int(xbmcaddon.Addon().getSetting('video_code'))
                                    if video_code==2 or (video_code==1 and item['ico'].lower()!='mp4'):
                                        datam=xl.urlopen('http://115.com/api/video/m3u8/'+ xl.getpc(item['fid'])+'.m3u8')
                                        m3u8urls=[]
                                        for match in re.finditer('BANDWIDTH=(?P<bandwidth>.*?)\x2C.*?(?P<url>http.*?)\r', datam, re.IGNORECASE | re.DOTALL):
                                            m3u8urls.append((int(match.group('bandwidth')),match.group('url')))
                                        if len(m3u8urls)>0:
                                            url='/m3u/%s/%s.m3u8' % (item['fid'],parse.quote_plus(title))
                                            #m3u8urls.sort(key=lambda x:x[0],reverse=True)
                                            #url= m3u8urls[0][1]
                                            ism3u8=True
                                            mimetype='application/x-mpegURL'
                                    '''
                            else:
                                if item['n'][0:8]=='tempplay':
                                    continue;
                                ifFolder=True
                                title='【%s】'%(item['n'])
                                url='/files?'+parse.urlencode({'cid': item['cid'],'offset':0,'pageitem':pageitem,'cursorttype':cursorttype})
                                sha1url='/sha1?'+parse.urlencode({'mode':'beginexportcid','cid': item['cid']})
                            if title:
                                tds=[]
                                tds.append(td(a(href=sha1url, target="_blank" ,class_='sha1')('导出SHA1'),class_='sha1td'))
                                if locurl:
                                    tds.append(td(a(href=locurl,type=mimetype,class_='loc')('定位'),class_='loctd'))
                                if isvideo:
                                    # url='/play?'+parse.urlencode({'url': url,'title':title+'.m3u8','mimetype':mimetype}))
                                    # yield li(a(href=url,title=title)(title))
                                    #yield li(a(href=url,type=mimetype)(title),class_='video')
                                    playurl='/play?'+parse.urlencode(encode_obj({'url': url,'title':item['n']+'.m3u8','mimetype':mimetype,'cid':item['cid'],'pc':item['pc']}))
                                    m3url=('/m3u/%s/%s/%s.m3u8' % (item['pc'],item['sha'],parse.quote_plus(six.ensure_binary(title))))
                                    m3url=('%s://%s/m3u/%s/%s/%s.m3u8' % (s.request_version.split('/')[0],
                                                            s.headers.get('Host'),
                                                            item['pc'],item['sha'],parse.quote_plus(six.ensure_binary(title))))
                                    m3uplayurl='/play?'+parse.urlencode(encode_obj({'url': m3url,'title':title+'.m3u8','mimetype':'application/x-mpegURL','cid':item['cid'],'pc':item['pc']}))
                                    deourl=('deovr://%s://%s/djs/%s/%s.json' % (s.request_version.split('/')[0],
                                                            s.headers.get('Host'),
                                                            parse.quote_plus(url),
                                                            parse.quote_plus(six.ensure_binary(title)),
                                                            ))
                                    m3udeourl=('deovr://%s://%s/djs/%s/%s.json' % (s.request_version.split('/')[0],
                                                            s.headers.get('Host'),
                                                            parse.quote_plus(m3url),
                                                            parse.quote_plus(six.ensure_binary(title)),
                                                            ))
                                    #gizurl=('gizmovr://type=video&url=%s' % (url))
                                    #m3ugizurl=('gizmovr://type=video&url=%s' % (m3url)).encode('latin-1')
                                    #xbmc.log(msg='requestedWith:'+requestedWith,level=xbmc.LOGERROR)
                                    tds.append( td(a(href=url,type=mimetype,class_='video')(title),class_='videotd'))
                                    tds.append( td(a(href=playurl,class_='vid2')('原码HTML5')))
                                    tds.append( td(a(href=m3uplayurl,class_='vid2')('转码HTML5')))
                                    #if requestedWith.lower().find('deovr')>=0:
                                    #tds.append( td(a(href=m3udeourl,class_='vid2')('DEO转码播放')))
                                    #else:
                                    tds.append( td(a(href=m3url,type='application/x-mpegURL',class_='vid2')('转码直连')))
                                elif ifFolder:
                                    tds.append(td(a(href=url,type=mimetype,class_='folder')(title),colspan='4'))
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
                            table(tr(sha1inout,sort)),
                            table(tr(sort)),
                            table(tr(filters,navpage)),
                            table(items),
                        )
                    )
                    htmlrender=six.ensure_binary(t.render())
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
                    htmlrender=six.ensure_binary(t.render())
                    s.send_header('Content-Length', len(htmlrender))
                    s.end_headers()
                    s.wfile.write(htmlrender)
            elif request_path=='/sha1':
                qs=parse.parse_qs(urlsp.query, keep_blank_values=True)
                mode=str(qs.get('mode',[0])[0])
                xl = api_115('0')
                if mode=='beginimport':
                    cid=str(qs.get('cid',[0])[0])
                    data=xl.getfilelist(cid=cid,offset=0,pageitem=10,star='0',sorttype='user_ptime',sortasc='0')
                    #xbmc.log(str(data),level=xbmc.LOGERROR)
                    if data['state']:
                        cidname=''
                        if 'path' in data:
                            if len(data['path'])>0:
                                cidname=data['path'][-1]['name']
                        if 'folder' in data:
                            cidname=data['folder']['name']
                        s.send_response(200)
                        t = html(
                                    head(
                                        meta(charset='utf-8'),
                                        title('115 SHA1'),
                                        link(rel='stylesheet',href='/css/styles.css')
                                    ),
                                    body(
                                            script(type='text/javascript')(r'''
function filtershastr() {
var content = document.getElementsByName("sha1str")[0].value.split('\n');
result="";
content.forEach(filter);
function filter(value) {
if(value.split('|').length>=4){
if(value.text.substring(0, 5)!="ed2k:"){
result=result+value+'\n';}
}
};
document.getElementsByName("sha1str")[0].value=result;
}
'''),
                                            form(name='myform',action='/sha1?mode=import',method='POST', onsubmit='filtershastr()')(
                                                input_( type='hidden', name="cid",value=cid),
                                                label('当前【%s】'%(cidname)),
                                                textarea(rows='40', cols="60", name='sha1str')(''),
                                                input_(class_='bigfont', type='submit', name="submit",value='导入SHA1'),
                                                )
                                    )
                                )
                        htmlrender=six.ensure_binary(t.render())
                        s.send_header('Content-Length', len(htmlrender))
                        s.end_headers()
                        s.wfile.write(htmlrender)
                if mode=='import':
                    #cid=str(qs.get('cid',[0])[0])
                    cid=postvars['cid'][0]
                    xbmc.log("rootcid"+cid,level=xbmc.LOGERROR)
                    cid=xl.createdir(cid,'sha-%s'%(datetime.now().strftime('%Y%m%d-%H%M%S')))
                    #sha1str=str(qs.get('sha1str',[0])[0])
                    #sha1str=str(postvars['sha1str'])
                    sha1str=postvars['sha1str']
                    sha1str='\n'.join(sha1str)
                    
                    sha1str=parse.unquote_plus(sha1str)
                    #xbmc.log(sha1str,level=xbmc.LOGERROR)
                    succ=fail=0
                    subfolders={}
                    def getsubfoldercid(cid,foldername):
                        if not type(foldername)==str:
                            return cid
                        foldername = foldername.strip()
                        if foldername == '':
                            return cid
                        if foldername in subfolders:
                            return subfolders[foldername]
                        else:
                            foldernamelast=foldername
                            folders=foldername.split('|')
                            if len(folders)>1:
                                cid=getsubfoldercid(cid,'|'.join(folders[:-1]))
                                foldernamelast=folders[-1]
                            subfolders[foldername]=xl.createdir(cid,foldernamelast)
                            xbmc.log(msg='subfolders %s,%s,%s'%(foldername,foldernamelast,subfolders[foldername]),level=xbmc.LOGERROR)
                            return subfolders[foldername]
                    
                    link115s=[]
                    for match in re.finditer(r'(?:115\x3A\x2f\x2f|^)(?P<shalink>[^\r\n\x3A\x7C]+?[\x7C][0-9]+[\x7C][0-9a-fA-F]{40}[\x7C][0-9a-fA-F]{40})(?:\x7C(?P<folder>.+?$)|\s+.*?|)', sha1str, re.IGNORECASE | re.MULTILINE):
                        link115s.append({'shalink':match.group('shalink'),'folder':match.group('folder')})
                    maxcount=300
                    if len(link115s)>maxcount:
                        s.send_response(200)
                        t = html(
                                head(
                                    meta(charset='utf-8'),
                                    title('Import '),
                                    link(rel='stylesheet',href='/css/styles.css')
                                ),
                                body(
                                    label('链接数为%i,最高支持%i,可尝试分批导入'%(len(link115s),maxcount)),
                                    br(),
                                    br(),
                                    label('如有大批量导入导出需求，建议使用'),
                                    a(href='http://www.tampermonkey.net/',target="_blank",)('油猴'),
                                    label('配合'),
                                    a(href='https://gist.github.com/Nerver4Ever/953447c9ecd330ffc0861d4cbb839369/raw/29b609ce37cb58a9e568069cb569e442941ea99c/115%25E8%25BD%25AC%25E5%25AD%2598%25E5%258A%25A9%25E6%2589%258Bui%25E4%25BC%2598%25E5%258C%2596%25E7%2589%2588.user.js',target="_blank",)('115转存助手ui优化版'),
                                    br(),
                                    a(href='#',onClick='javascript:history.go(-1)',class_='return')('返回上一页'),
                                )
                            )
                        htmlrender=six.ensure_binary(t.render())
                        s.send_header('Content-Length', len(htmlrender))
                        s.end_headers()
                        s.wfile.write(htmlrender)
                        return
                    #for match in re.finditer(r'^\s*(?:115\x3A\x2f\x2f)?(?P<shalink>[^\r\n\x2F\x7C]+?[\x7C][0-9]+[\x7C][0-9a-fA-F]{40}[\x7C][0-9a-fA-F]{40})\x7C?(?P<folder>.*?)\s*$', sha1str, re.IGNORECASE | re.MULTILINE):
                    failedlist = []
                    oldnewnames={}
                    tempnameindex=0
                    for link115 in link115s:
                        shalink=link115['shalink']
                        linkpart=shalink.split('|')
                        
                        filename=linkpart[0]
                        filesize=linkpart[1]
                        fileid=linkpart[2]
                        preid=linkpart[3].strip()
                        tempnameindex=tempnameindex+1
                        tempname="{0}{1}".format(tempnameindex,filename[filename.rfind('.'):].lower())
                        subcid=getsubfoldercid(cid,link115['folder'])
                        #xbmc.log(msg="{0}||||{1}".format(filename,tempname),level=xbmc.LOGERROR)
                        tm=str(int(time.time()))+'000'
                        if xl.import_file_with_sha1(preid,fileid,filesize,tempname,subcid,tm):
                            succ+=1
                            oldnewnames[tempname]=filename
                        else:
                            fail+=1
                            failedlist.append(shalink)
                    xl.batchcidrename(cid,oldnewnames)
                    url='/files?'+parse.urlencode({'cid': cid,'offset':0,'pageitem':10,'cursorttype':0})
                    
                    s.send_response(200)
                    t = html(
                                head(
                                    meta(charset='utf-8'),
                                    title('115 SHA1'),
                                    link(rel='stylesheet',href='/css/styles.css')
                                ),
                                body(
                                    label('成功：%i  失败：%i'%(succ,fail)),
                                    br(),
                                    textarea()('\r\n'.join(failedlist)),
                                    a(href=url,title='打开保存目录',class_='path')('打开保存目录'),
                                )
                            )
                    htmlrender=six.ensure_binary(t.render())
                    s.send_header('Content-Length', len(htmlrender))
                    s.end_headers()
                    s.wfile.write(htmlrender)
                if mode=='exportfid':
                    name=str(qs.get('name',[0])[0])
                    length=str(qs.get('length',[0])[0])
                    sha1=str(qs.get('sha1',[0])[0])
                    pc=str(qs.get('pc',[0])[0])
                    exportsha=xl.exportfid(name,length,sha1,pc)
                    s.send_response(200)
                    s.send_header('Content-Length', len(exportsha))
                    s.send_header('Keep-Alive', 'timeout=5, max=100')
                    s.send_header('Connection', 'Keep-Alive')
                    s.send_header('Content-Type', 'text/plain; charset=UTF-8')
                    s.end_headers()
                    s.wfile.write(str.encode(exportsha))
                if mode=='beginexportcid':
                    maxcount=200
                    warningcount=20
                    cid=str(qs.get('cid',[0])[0])
                    filescount=xl.countfiles(cid)
                    if filescount>maxcount:
                        s.send_response(200)
                        t = html(
                                head(
                                    meta(charset='utf-8'),
                                    title('Export '),
                                    link(rel='stylesheet',href='/css/styles.css')
                                ),
                                body(
                                    label('目录下文件数为%i,最高支持%i'%(filescount,maxcount)),
                                    br(),
                                    br(),
                                    label('如有大批量导入导出需求，建议使用'),
                                    a(href='http://www.tampermonkey.net/',target="_blank",)('油猴'),
                                    label('配合'),
                                    a(href='https://gist.github.com/Nerver4Ever/953447c9ecd330ffc0861d4cbb839369/raw/29b609ce37cb58a9e568069cb569e442941ea99c/115%25E8%25BD%25AC%25E5%25AD%2598%25E5%258A%25A9%25E6%2589%258Bui%25E4%25BC%2598%25E5%258C%2596%25E7%2589%2588.user.js',target="_blank",)('115转存助手ui优化版'),
                                    br(),
                                    a(href='#',onClick='window.close();',class_='return')('关闭页面'),
                                )
                            )
                        htmlrender=six.ensure_binary(t.render())
                        s.send_header('Content-Length', len(htmlrender))
                        s.end_headers()
                        s.wfile.write(htmlrender)
                    elif filescount>warningcount:
                        url='/sha1?'+parse.urlencode({'mode':'exportcid','cid': cid})
                        s.send_response(200)
                        t = html(
                                head(
                                    meta(charset='utf-8'),
                                    title('Export '),
                                    link(rel='stylesheet',href='/css/styles.css')
                                ),
                                body(
                                    label('目录下文件数为%i，将会耗费较长时间，是否继续？'%(filescount)),
                                    br(),
                                    a(href=url,title='继续导出',class_='path')('继续导出'),
                                    br(),
                                    br(),
                                    a(href='#',onClick='window.close();',class_='return')('关闭页面'),
                                )
                            )
                        htmlrender=six.ensure_binary(t.render())
                        s.send_header('Content-Length', len(htmlrender))
                        s.end_headers()
                        s.wfile.write(htmlrender)
                    else:
                        url='/sha1?'+parse.urlencode({'mode':'exportcid','cid': cid})
                        s.send_response(200)
                        t = html(
                                head(
                                    meta(charset='utf-8'),
                                    title('Export '),
                                    link(rel='stylesheet',href='/css/styles.css')
                                ),
                                body(
                                    label('目录下文件数为%i，是否继续？'%(filescount)),
                                    br(),
                                    a(href=url,title='继续导出',class_='path')('继续导出'),
                                    br(),
                                    br(),
                                    a(href='#',onClick='window.close();',class_='return')('关闭页面'),
                                )
                            )
                        htmlrender=six.ensure_binary(t.render())
                        s.send_header('Content-Length', len(htmlrender))
                        s.end_headers()
                        s.wfile.write(htmlrender)
                if mode=='exportcid':
                    cid=str(qs.get('cid',[0])[0])
                    pathdeep=xl.pathdeep(cid)
                    outlist=[]
                    xl.exportcid(outlist,cid,pathdeep)
                    exportsha=str.encode('\r\n'.join(outlist))
                    s.send_response(200)
                    s.send_header('Content-Length', len(exportsha))
                    s.send_header('Keep-Alive', 'timeout=5, max=100')
                    s.send_header('Connection', 'Keep-Alive')
                    s.send_header('Content-Type', 'text/plain; charset=UTF-8')
                    s.end_headers()
                    s.wfile.write(exportsha)
                    
            elif request_path=='/cookie':
                qs=parse.parse_qs(urlsp.query, keep_blank_values=True)
                curformat=str(qs.get('cformat',[0])[0])
                ac=str(qs.get('ac',[0])[0])
                if ac=='save':
                    cookiestr=str(qs.get('cookiestr',[0])[0])
                    savecookiefile(cookiestr)
                    _cookiestr=loadcookiefile()
                #xbmc.log(msg='zzzzzzz:'+curformat,level=xbmc.LOGERROR)
                cookiestr=loadcookiefile(cformat=curformat)
                #xbmc.log(msg='zzzzzzz:'+cookiestr,level=xbmc.LOGERROR)
                def tdcformat(ctx):
                    yield label(for_='cformat')('cookie格式：')
                    def optionscformat(ctx):
                        for cformat in ['simple','json','LWP']:
                            url='/cookie?'+parse.urlencode({'cformat': cformat})
                            if curformat==cformat:
                                yield option(value=url,selected='selected',class_='pagesel')(cformat)
                            else:
                                yield option(value=url)(cformat)
                    yield select(id='cformat',onchange='if (this.value) window.location.href=this.value',class_='pagesel')(optionscformat)
                    
                def savecookie(ctx):
                    yield form(action='/cookie',method='GET')(
                        input_( type='hidden', name='ac',value='save'),
                        textarea(rows='40', cols="60", name='cookiestr')(cookiestr),
                        input_(class_='bigfont', type='submit', name="submit",value='保存',onclick="return confirm('错误的值将造成登录失败，是否继续?')" ),
                        )
                s.send_response(200)
                t = html(
                    head(
                        meta(charset='utf-8'),
                        title('WEB115 COOKIE'),
                        link(rel='stylesheet',href='/css/styles.css')
                    ),
                    body(
                        tdcformat,
                        savecookie,
                    )
                )
                htmlrender=six.ensure_binary(t.render())
                s.send_header('Content-Length', len(htmlrender))
                s.end_headers()
                s.wfile.write(htmlrender)
            elif request_path[0:4]=='/sub':
                try:
                    (suburl,name)=request_path[5:].split('/')
                    suburl=parse.unquote_plus(suburl)
                    name=name[:name.index('.vtt')]
                    xl = api_115('0')
                    vttstr=xl.coversrttovtt(srturl=suburl)
                    s.send_response(200)
                    s.send_header('Content-Length', len(vttstr))
                    s.send_header('Keep-Alive', 'timeout=5, max=100')
                    s.send_header('Connection', 'Keep-Alive')
                    s.send_header('Content-Type', 'text/vtt; charset=UTF-8')
                    s.end_headers()
                    s.wfile.write(six.ensure_binary(vttstr))
                except Exception as errno:
                    xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            else:
                try:
                    if request_path=='/' or request_path=='':
                        request_path='/index.html'
                    filepath = xbmc.translatePath( os.path.join( __cwd__,  'www', request_path[1:]))

                    f = open(filepath,'rb')

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
            if fid in s.fidDownloadurl:
                (strtime,fidUrl)=s.fidDownloadurl[fid].split(' ')
                timespan=int(time.time())-int(strtime)
                if timespan>=7200:
                    fidUrl=''
            if fidUrl=='':
                fpc=xl.getpc(fid)
                fidUrl=xl.getfiledownloadurl(fpc)
                s.fidDownloadurl[fid]=str(int(time.time()))+' '+fidUrl
            return fidUrl
        except Exception as errno:
            errorstr=' '.join(('error:', str(errno)))
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            return errorstr


    def urlopenwithRetry(s,req):
        for icount in range(10):
            try:
                opener2 = request.build_opener(SmartRedirectHandler)
                response= opener2.open(req,timeout=40)
                return response
                break
            except:
                time.sleep(icount+1)
                continue
    '''
    Sends the requested file and add additional headers.
    '''
    def serveFile(s, fid, cookiestr, changeserver, sendData,name):
        fidUrl = s.getfidUrl( fid, cookiestr)
        if not fidUrl:
            s.send_response(403)
            return
        filedownloadurl,downcookie=fidUrl.split('|')
        #xbmc.log('filedownloadurl=%s downcookie=%s'%(filedownloadurl,downcookie),level=xbmc.LOGERROR)
        if not fid in s.fileSize:
            s.fileSize[fid]=-1
        if not fid in  s.fidSemaphores:
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

        reqheaders['User-Agent']=defaultUserAgent
        reqheaders['Referer']='https://115.com/?cid=0&offset=0&mode=wangpan'
        if cookiestr=='0': cookiestr=''
        reqheaders['Cookie']=cookiestr+downcookie+';'
        #处理转发请求headers---end
        #转发请求
        req = request.Request(filedownloadurl, headers=reqheaders)
        if sendData==0:
            req.get_method = lambda : 'HEAD'
        response=None
        #线程加塞
        s.fidSemaphores[fid].acquire()
        #xbmc.log('lockcount+1 sendData=%d bytes=%d-'%(sendData,rangeBegin),level=xbmc.LOGERROR)
        err=False
        
        wcode=200
        wheaders={}
        #wheaders={'Connection':'Keep-Alive','Keep-Alive':'timeout=20, max=100'}
        try:
            response = s.urlopenwithRetry(req)
            #s.protocal_version ='HTTP/1.1'
            wcode=response.code
            headers=response.info()
            #xbmc.log(msg=str(headers),level=xbmc.LOGERROR)
            keys=['content-length','content-range','accept-ranges','date']
            headerkeys = set(k.lower() for k in headers)
            for key in headerkeys:
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
            #xbmc.log(msg='zzzdebug:mimetype:%s'%(mimetype),level=xbmc.LOGERROR)
            wheaders['content-type']=mimetype
            
            
        except:
            #xbmc.log('lockcount-1 HEAD error',level=xbmc.LOGERROR)
            xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
            s.send_response(404)
            err=True
        finally:
            response.close()
            #time.sleep(1)
            s.fidSemaphores[fid].release()
            #xbmc.log('lockcount-1 HEAD over err=%s'%str(err),level=xbmc.LOGERROR)
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
            req = request.Request(filedownloadurl, headers=reqheaders)
            #线程加塞
            s.fidSemaphores[fid].acquire()
            xbmc.log('lockcount+1 bytes=%d-%d'%(rangeBegin,rangeEnd),level=xbmc.LOGERROR)
            err=False
            try:
                response = s.urlopenwithRetry(req)
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

def loadcookiefile(cformat='simple'):
    cstr=''
    cookiejar = cookielib.LWPCookieJar()
    cid=seid=uid=''
    try:
        cookiefile = xbmc.translatePath(os.path.join(xbmcaddon.Addon(id='plugin.video.115').getAddonInfo('path'), 'cookie.dat'))
        if os.path.exists(cookiefile):
            cookiejar.load(
                cookiefile, ignore_discard=True, ignore_expires=True)
            for cookie in cookiejar:
                if cookie.name.upper()=='CID': cid=cookie.value
                if cookie.name.upper()=='SEID': seid=cookie.value
                if cookie.name.upper()=='UID': uid=cookie.value
        if cformat.lower()=='json':
            cookiejson=[{
                            "domain": "115.com",
                            "hostOnly": False,
                            "httpOnly": True,
                            "path": "/",
                            "sameSite": "lax",
                            "firstPartyDomain": "",
                            "partitionKey": None,
                            "secure": False,
                            "session": True,
                            "name": "CID",
                            "value": cid,
                            "id": 1
                        },
                        {
                            "domain": "115.com",
                            "hostOnly": False,
                            "httpOnly": True,
                            "path": "/",
                            "sameSite": "lax",
                            "firstPartyDomain": "",
                            "partitionKey": None,
                            "secure": False,
                            "session": True,
                            "name": "SEID",
                            "value": seid,
                            "id": 2
                        },
                        {
                            "domain": "115.com",
                            "hostOnly": False,
                            "httpOnly": True,
                            "path": "/",
                            "sameSite": "lax",
                            "firstPartyDomain": "",
                            "partitionKey": None,
                            "secure": False,
                            "session": True,
                            "name": "UID",
                            "value": uid,
                            "id": 3
                        }]
            cstr=json.dumps(cookiejson,indent=4)

        elif cformat.lower()=='lwp':
            cstr='''#LWP-Cookies-2.0
Set-Cookie3: CID=%s; path="/"; domain="115.com"; path_spec; domain_dot; discard; HttpOnly=None; version=0
Set-Cookie3: SEID=%s; path="/"; domain="115.com"; path_spec; domain_dot; discard; HttpOnly=None; version=0
Set-Cookie3: UID=%s; path="/"; domain="115.com"; path_spec; domain_dot; discard; HttpOnly=None; version=0'''%(cid,seid,uid)
        else:
            cstr='CID=%s;SEID=%s;UID=%s'%(cid,seid,uid)
        return cstr
    except:
        xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)

def savecookiefile(cstr):
    cid=seid=uid=''
    try:
        cookies=json.loads(cstr)
        for cookie in cookies:
            if 'name' in cookie and 'value' in cookie:
                if cookie['name'] == 'CID': cid = cookie['value']
                if cookie['name'] == 'SEID': seid = cookie['value']
                if cookie['name'] == 'UID': uid = cookie['value']
    except:
        cid=''
    if cid=='':
        match = re.search(r'CID\s*\x3D\s*(?P<value>[A-Za-z0-9\x5F]+)', cstr, re.IGNORECASE | re.MULTILINE)
        if match:
            cid = match.group('value')
        match = re.search(r'SEID\s*\x3D\s*(?P<value>[A-Za-z0-9\x5F]+)', cstr, re.IGNORECASE | re.MULTILINE)
        if match:
            seid = match.group('value')
        match = re.search(r'UID\s*\x3D\s*(?P<value>[A-Za-z0-9\x5F]+)', cstr, re.IGNORECASE | re.MULTILINE)
        if match:
            uid = match.group('value')
    if cid=='': return False
    cookiedat='''#LWP-Cookies-2.0
Set-Cookie3: CID=%s; path="/"; domain="115.com"; path_spec; domain_dot; discard; HttpOnly=None; version=0
Set-Cookie3: SEID=%s; path="/"; domain="115.com"; path_spec; domain_dot; discard; HttpOnly=None; version=0
Set-Cookie3: UID=%s; path="/"; domain="115.com"; path_spec; domain_dot; discard; HttpOnly=None; version=0'''%(cid,seid,uid)
    
    try:
        cookiefilename = xbmc.translatePath(os.path.join(xbmcaddon.Addon(id='plugin.video.115').getAddonInfo('path'), 'cookie.dat'))
        with open(cookiefilename, "wb") as cookieFile:
            cookieFile.write(six.ensure_binary(cookiedat))
            cookieFile.close()
        return True
    except:
        xbmc.log(msg=format_exc(),level=xbmc.LOGERROR)
        return False

if __name__ == '__main__':
    #fid_pclist=plugin.get_storage('fid_pclist')
    _cookiestr=loadcookiefile()
    fid_pclist={}
    fid_downloadurls={}
    socket.setdefaulttimeout(40)
    server_class = ThreadedHTTPServer
    #MyHandler.protocol_version='HTTP/1.1'
    MyHandler.protocol_version='HTTP/1.0'
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    xbmc.log(msg='XBMCLocalProxy Starts - %s:%s' % (HOST_NAME, PORT_NUMBER),level=xbmc.LOGERROR)
    monitor = xbmc.Monitor()
    while not monitor.abortRequested():
        httpd.handle_request()
    httpd.server_close()
    #fid_pclist.sync()
    xbmc.log(msg='XBMCLocalProxy Stop - %s:%s' % (HOST_NAME, PORT_NUMBER),level=xbmc.LOGERROR)