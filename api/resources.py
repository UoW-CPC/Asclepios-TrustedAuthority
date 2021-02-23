from tastypie.resources import ModelResource, Resource, fields
from api.models import FileNo,SearchNo,Key,EnclaveId
from tastypie.authorization import Authorization
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from tastypie.bundle import Bundle 
from parameters import SALT, IV, hash_length, MODE, ITER, KS # KeyG
from django.db.models import Q
#from django.db import transaction # test
#from django.shortcuts import get_object_or_404 #test
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from threading import Thread, Lock
from teepclient import simple
#from django.core import serializers
#from django.http import HttpResponse


#from collections import Counter

import json
import hashlib
import requests
import sys
sys.path.append('sjcl-0.2.1/sjcl') #we modified python sjcl a bit to allow define iv, salt of encryption
from sjcl import SJCL
import logging

import os
from base64 import b64encode,b64decode
#===============================================================================
# Common functions, constants
#===============================================================================  

# Get an instance of a logger
logger = logging.getLogger(__name__)
NO_ATTRIBUTES = 400 # allow to get maximum of NO_ATTRIBUTES items at once
update_lock = sem = threading.Semaphore()
#URL_TEEP = "http://127.0.0.1:5683"
URL_TEEP = os.environ['TEEP_SERVER']
SGX_ENABLE=os.environ['SGX'] # True if sgx is enabled, False otherwise
#===============================================================================
# "File Number" resource
#===============================================================================
class FileNoResource(ModelResource):
    class Meta:
        queryset = FileNo.objects.all()
        resource_name = 'fileno'
        authorization = Authorization()
        fields = ['w', 'fileno','keyId']
        filtering = {
            "w": ['exact','in'],
        }
        limit=NO_ATTRIBUTES  # allow to get maximum of NO_ATTRIBUTES items at once
    def apply_filters(self, request, applicable_filters): # customized filter, which accept to get value with OR, for i.e. w = w_1 or w = w_2
        query = request.GET.get('w', None)
 
        if query: # build filter with OR
            args = query.split(",") # split parameters by comma
            l = len(args)
            qset = Q(w=args[0])
            for i in range(1,l):
                qset = qset | Q(w=args[i])
            ret = self.get_object_list(request).filter(qset) # filter values which satisfy qset
            return ret
        else:
            base_object_list = super(FileNoResource, self).apply_filters(request, applicable_filters)
            return base_object_list
      
#===============================================================================
# "Search Number" resource
#===============================================================================
class SearchNoResource(ModelResource):
    class Meta:
        queryset = SearchNo.objects.all()
        resource_name = 'searchno'
        authorization = Authorization()
        fields = ['w', 'searchno','keyId']
        filtering = {
            "w": ['exact','in'],
        }
        limit=NO_ATTRIBUTES
        
    def apply_filters(self, request, applicable_filters): # customized filter, which accept to get value with OR, for i.e. w = w_1 or w = w_2
        query = request.GET.get('w', None)
 
        if query: # build filter with OR
            args = query.split(",") # split parameters by comma
            l = len(args)
            qset = Q(w=args[0])
            for i in range(1,l):
                qset = qset | Q(w=args[i])
            ret = self.get_object_list(request).filter(qset) # filter values which satisfy qset
            return ret
        else:
            base_object_list = super(SearchNoResource, self).apply_filters(request, applicable_filters)
            return base_object_list

#===============================================================================
# Common functions
#===============================================================================  
def hash(input):
    h = hashlib.sha256(input).hexdigest()
    return h

#===============================================================================
# "Search" object
#===============================================================================  
class Search(object):
    KeyW = ''
    keyId = ''
    
#===============================================================================
# "Search Query" resource
#===============================================================================       
class SearchResource(Resource):
    KeyW = fields.CharField(attribute = 'KeyW')
    Lta = fields.ListField(attribute='Lta',default=[]) # List of addresses, computed by TA
    keyId = fields.CharField(attribute = 'keyId')
    
    class Meta:
        resource_name = 'search'
        object_class = Search
        authorization = Authorization()
        always_return_data=True # This is enabled, permitting return results for post request
        fields = ['Lta']

    # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }

        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.KeyW # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.KeyW
          
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
          
        return self._build_reverse_url('api_dispatch_detail', kwargs = kwargs)
 
    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0
 
    def obj_get_list(self, request = None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)
 
    def obj_get(self, bundle, request = None, **kwargs):
#         get one object from data source
        KeyW = kwargs['pk']
            
        bundle_obj = Search()
        bundle_obj.KeyW = KeyW

        try:
            return bundle_obj
        except KeyError:
            raise NotFound("Object not found") 

    
    def obj_create(self, bundle, request = None, **kwargs):
        logger.info("Search in TA Server")
        
        # create a new object
        bundle.obj = Search()
          
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
        
        #KeyW = b64decode(bundle.obj.KeyW) # base64 -> bytes
        KeyW = bundle.obj.KeyW
        logger.debug("Type of ciphertext: %s",type(KeyW))
        logger.debug("keyW:%s",KeyW)
        logger.debug("bundle object:%s",bundle)
        # Recover hash(w) and searchNo[w] from KeyW
        # Retrieve KeyG from database
        keyid = bundle.obj.keyId;
        logger.debug("Id of key:%s",keyid);

        KeyG=Key.objects.get(keyId=keyid).key; # type of KeyG: string
        #KeyG=b64decode(KeyG) # string -> bytes
        logger.debug("KeyG: {}, type:{},size:{}".format(KeyG,type(KeyG),len(KeyG)))
        logger.debug("SGX_ENABLE:{}".format(SGX_ENABLE)) 
        try:
            if SGX_ENABLE==True :
                KeyW_bytes = b64decode(bundle.obj.KeyW) # base64 -> bytes
                sealed_key=b64decode(KeyG) # string -> bytes
                q = EnclaveId.objects.first() # get existed enclave id
        
                # invoke API of TA
                enclaveId = q.encId

        # encryption - for testing only
        #message = b'hello'
        
        #hex_string = "d8 cc aa 75 3e 29 83 f0 36 57 ab 3c 8a 68 a8 5a"
        #key=bytes.fromhex(hex_string)
        
        #key=bytes.fromhex(b'd8ccaa753e2983f03657ab3c8a68a85a'.decode("utf-8"))
        
        #key=b64decode(b'2MyqdT4pg/A2V6s8imioWg==')
        #logger.debug("Encrypt data in enclave %d, plaintext:%s",enclaveId,message)
        #ct,size_ct = simple.encrypt_w_sealkey(enclaveId,True,KeyG,message,URL_TEEP);
        #ct,size_ct = simple.encrypt(enclaveId,True,key,message,URL_TEEP);
        #logger.debug("ciphertext 1:%s,size:%d,ciphertext 2:%s",ct,size_ct,KeyW);
        
        # unseal key - for testing only
        #unseal_key = simple.unsealkey(enclaveId,KeyG,URL_TEEP);
        #logger.debug("unseal key:%s",unseal_key);
        
                # decryption
                #sealed_key = KeyG
        #sealed_key=b'Gk\xb5\xe7RP}\x93\x8dsv\xb7\x11\xf7\xbd\xd5\xc9\xc0\x99\xd9s\x0e\x90\xba[^\xafR/;:\x19<4`N\x9b\x1f\x05?\x94g\xbd8\xa5\xfe\xde\xbd\xfc\xfe\xfa\xe1\xd6\xe3\xd8\xc4U\xc9\xb1\xfc\xac<|\xf8'
                logger.debug("sealed_key: %s, type:{},size:{}",sealed_key,type(sealed_key),len(sealed_key))
                plaintext,size_pt=simple.encrypt_w_sealkey(enclaveId,False,sealed_key,KeyW,URL_TEEP)
        #pt,size_pt=simple.encrypt(enclaveId,False,key,KeyW,URL_TEEP)
                logger.debug("plaintext:%s,size:%d",plaintext,size_pt)
            else: # SGX is not enabled
                logger.debug("decrypting without sgx")
                logger.debug("KeyW:{},KeyG:{}".format(KeyW,KeyG))
                plaintext = SJCL().decrypt(KeyW, KeyG)
                logger.debug("plaintext:%s",plaintext)
        except: # cannot decrypt
            logger.debug("wrong token")
            bundle.obj.Lta = ''
            bundle.obj.KeyW = 'error' # hide KeyW in the response
            return bundle

        hashChars = int(hash_length/4) # hash_length/4 = number of characters in hash value = 64

        plaintext_str = str(plaintext,'utf-8') # convert type from byte (plaintext) to string (plaintext_str)
        hashW = plaintext_str[0:hashChars]
        logger.debug("hashW: %s",hashW)
        try:
            searchNo = SearchNo.objects.get(w=hashW,keyId=keyid).searchno # check
        except: # if searchno does not exist
            searchNo = 0

        # increase search number
        searchNo = str(searchNo + 1)
        logger.debug("hashW: %s, searchNo: %s", hashW, searchNo)

        if SGX_ENABLE==True:
            newKeyW_ciphertext,size_ct = simple.encrypt_w_sealkey(enclaveId,True,KeyG,hashW+searchNo,URL_TEEP);
            logger.debug("newKeyW_ciphertext: %s", newKeyW_ciphertext)
        else:
            plaintext_byte =  str.encode(hashW + searchNo) # string -> bytes
            logger.debug("new plaintext: %s", plaintext_byte)
        
            newKeyW = SJCL().encrypt(plaintext_byte,KeyG,SALT,IV,MODE,ITER,int(KS/8)) # Compute new KeyW    
            logger.debug("new ciphertext: {}".format(newKeyW))

            newKeyW_ciphertext = newKeyW['ct'] # convert type from dict (newKeyW) to byte (newKeyW_byte)
            logger.debug("newKeyW_ciphertext: %s", newKeyW_ciphertext)

        logger.debug("Retrieve fileno")
        Lta = []
        try:
            fileno = FileNo.objects.get(w=hashW,keyId=keyid).fileno
            logger.debug("fileno from the internal request: %s",fileno)
            # Compute all addresses with the new key
            for i in range(1,int(fileno)+1): # file number is counted from 1
                logger.debug("i: %s",i)
                logger.debug("newKeyW_ciphertext: %s",str(newKeyW_ciphertext,'utf-8'))
                input = (str(newKeyW_ciphertext,'utf-8') + str(i) + "0").encode('utf-8')
                addr = hash(input)
                logger.debug("hash input: %s",input)
                logger.debug("hash output (computed from newKeyW): %s", addr)
                Lta.append(addr)
        except: # not found
            logger.debug("Not found fileno")
        finally:
            bundle.obj.Lta = Lta
            bundle.obj.KeyW = '' # hide KeyW in the response
            bundle.obj.keyId = ''
            return bundle # return the list of computed addresses to CSP, which sends the request
#===============================================================================
# "Long line request" object
#===============================================================================  
class LongLineReq(object):
    requestType  = '' # requestType can be "searchno" or "fileno"
    Lw = []
    keyId = ''
     
#===============================================================================
# "Long line request" resource
#===============================================================================       
class LongLineReqResource(Resource):
    requestType = fields.CharField(attribute = 'requestType')
    Lw = fields.ListField(attribute='Lw',default=[])  
    keyId = fields.CharField(attribute = 'keyId')   
     
    class Meta:
        resource_name = 'longrequest'
        object_class = LongLineReq
        authorization = Authorization()
        always_return_data=True # This is enabled, permitting return results for post request
        fields = ['requestType','Lw']
     
     # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }
 
        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.requestType # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.requestType
           
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
           
        return self._build_reverse_url('api_dispatch_detail', kwargs = kwargs)
  
    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0
  
    def obj_get_list(self, request = None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)
  
    def obj_get(self, bundle, request = None, **kwargs):
#         get one object from data source
        requestType = kwargs['pk']
             
        bundle_obj = LongLineReq()
        bundle_obj.requestType = requestType
 
        try:
            return bundle_obj
        except KeyError:
            raise NotFound("Object not found") 
    
    def obj_create(self, bundle, request = None, **kwargs):
        logger.info("Long line request in TA Server")
         
        # create a new object
        bundle.obj = LongLineReq()
           
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
         
        requestType = bundle.obj.requestType
        Lw = bundle.obj.Lw
        logger.debug("Type of request:{}".format(requestType))
        logger.debug("Request content:{}".format(Lw))
        
        keyid = bundle.obj.keyId
         
        if requestType=="fileno":
            ret = FileNo.objects.filter(w__in=Lw,keyId=keyid).values("fileno","id","w")
            logger.debug(ret)
        else:   
            ret = SearchNo.objects.filter(w__in=Lw,keyId=keyid).values("searchno","id","w")
            logger.debug(ret)
            
        bundle.obj.Lw = []#ret.values("w") # hide requestType in the response
        bundle.data["objects"]=list(ret)
        return bundle

#===============================================================================
# "Key" resource
#===============================================================================
class KeyResource(ModelResource):
    class Meta:
        queryset = Key.objects.all()
        resource_name = 'key'
        authorization = Authorization()
        fields = ['key','keyId']
        allowed_methods = ['get','post','delete'] # only allow GET, POST method
        filtering = {
            "key": ['exact'],
        }
        
#===============================================================================
# "Upload" object
#===============================================================================  
class Upload(object):
    Lw = ''
    keyId = ''
    
#===============================================================================
# "Search Query" resource
#===============================================================================       
class UploadResource(Resource):
    Lw = fields.CharField(attribute = 'Lw')
    Lfileno = fields.ListField(attribute='Lfileno',default=[]) # List of fileno
    Lsearchno = fields.ListField(attribute='Lsearchno',default=[]) # List of searchno
    keyId = fields.CharField(attribute = 'keyId')
    
    class Meta:
        resource_name = 'upload'
        object_class = Upload
        authorization = Authorization()
        always_return_data=True # This is enabled, permitting return results for post request
        fields = ['Lw']
    # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }

        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.Lw # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.Lw
          
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
          
        return self._build_reverse_url('api_dispatch_detail', kwargs = kwargs)
 
    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0
 
    def obj_get_list(self, request = None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)
 
    def obj_get(self, bundle, request = None, **kwargs):
#         get one object from data source
        Lw = kwargs['pk']
            
        bundle_obj = Upload()
        bundle_obj.Lw = Lw

        try:
            return bundle_obj
        except KeyError:
            raise NotFound("Object not found") 

    def obj_create(self, bundle, request = None, **kwargs):
        global update_lock
        # Processing POST requests
        cur_thread = threading.current_thread()
        logger.debug("Thread arrived =>  {0} ".format(cur_thread.name))
        update_lock.acquire()
        cur_thread = threading.current_thread()
        logger.debug("Thread entered into critical region  =>  {0}".format(cur_thread.name))
        
        logger.info("Upload data - TA Server")
        
        # create a new object
        bundle.obj = Upload()
          
        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)
        
        listW = bundle.obj.Lw
        logger.debug("Type of listW: %s",type(listW))
        
        keyid = bundle.obj.keyId
        
        logger.debug("Query for returned fileno")
        
        listFileNo = FileNo.objects.filter(w__in=listW,keyId=keyid) #values_list('fileno',flat=True) #FileNo.objects.get(w=listW)
        bundle.obj.Lfileno = listFileNo.values("w","fileno")
                 
        #logger.debug("List of fileno: ()",listFileNo)
        logger.debug(bundle.obj.Lfileno)
                
        count = 0
        for x in listFileNo:
            x.fileno = x.fileno+1
                        
        Ly = []
        for x in listW:
            y = listFileNo.filter(w=x,keyId=keyid).first() 
            if y==None: # if not found
                y = FileNo(w=x,fileno=1,keyId=keyid)
                Ly.append(y)
            else: # if found
                y.fileno = y.fileno+1
                            
                            
        logger.debug("List of words and file no")
        logger.debug(Ly)
        logger.debug("update file no:")
        FileNo.objects.bulk_update(listFileNo,['fileno'])
        logger.debug("create file no:")
        if Ly!=[]:
            FileNo.objects.bulk_create(Ly)
            
        logger.debug("Query for searchno")
        listSearchNo = SearchNo.objects.filter(w__in=listW,keyId=keyid).values('w','searchno') #values_list('fileno',flat=True) #FileNo.objects.get(w=listW)
        
        bundle.obj.Lsearchno = listSearchNo.values('w','searchno')
        bundle.obj.Lw = ''
        
        cur_thread = threading.current_thread()
        logger.debug("Thread left critical region =>  {0} ".format(cur_thread.name))
        update_lock.release()
        return bundle # return the list of computed addresses to CSP, which sends the request

#===============================================================================
# "PubKey" resource
#===============================================================================
class PubKey(object):
    pubkey = ''
    report = ''
    #enclaveId = ''
    keyId = ''

class PubKeyResource(Resource):
    pubkey = fields.CharField(attribute = 'pubkey')
    report = fields.CharField(attribute = 'report')
    #enclaveId = fields.CharField(attribute = 'enclaveId')
    keyId = fields.CharField(attribute = 'keyId')

    class Meta:
        resource_name = 'pubkey'
        object_class = PubKey
        authorization = Authorization()
        allowed_methods = ['get','post'] # only allow GET, POST method
        field = ['report','pubkey','keyId']
        always_return_data= False
    # adapted this from ModelResource
    def get_resource_uri(self, bundle_or_obj):
        kwargs = {
            'resource_name': self._meta.resource_name,
        }
 
        if isinstance(bundle_or_obj, Bundle):
            kwargs['pk'] = bundle_or_obj.obj.keyId # pk is referenced in ModelResource
        else:
            kwargs['pk'] = bundle_or_obj.keyId
           
        if self._meta.api_name is not None:
            kwargs['api_name'] = self._meta.api_name
           
        return self._build_reverse_url('api_dispatch_detail', kwargs = kwargs)
    
    def get_object_list(self, request):
        # inner get of object list... this is where you'll need to
        # fetch the data from what ever data source
        return 0

    def obj_get_list(self, request=None, **kwargs):
        # outer get of object list... this calls get_object_list and
        # could be a point at which additional filtering may be applied
        return self.get_object_list(request)
    
    def obj_get(self, bundle, request = None, **kwargs):
        logger.debug("invoke request to teep-server")
        keyId = kwargs['pk']

        num_enc = EnclaveId.objects.all().count()
        if (num_enc==0): #if enclave is not initialized
            ENCLAVE=simple.initenclave(URL_TEEP)
            pk, report,enclave_id,h = simple.getpubkey(ENCLAVE) #simple.getpubkey(URL_TEEP)
            EnclaveId.objects.create(encId=enclave_id,pubkey=pk,report=report,sha=h)
        else:
            q = EnclaveId.objects.first()
            pk = q.pubkey
            report = q.report
            enclave_id = q.encId

        bundle_obj = PubKey()
        bundle_obj.pubkey = pk
        bundle_obj.report = report
        #bundle_obj.enclaveId = enclave_id
        bundle_obj.keyId=enclave_id
        try:
            return bundle_obj
        except KeyError:
            raise NotFound("Object not found") 

    def obj_create(self, bundle, request=None, **kwargs):
        logger.info("Store encrypted key to TA")

        # create a new object
        bundle.obj = PubKey()

        # full_hydrate does the heavy lifting mapping the
        # POST-ed payload key/values to object attribute/values
        bundle = self.full_hydrate(bundle)

        q = EnclaveId.objects.first()
        # invoke API of TA
        enclaveId = q.encId#ENCLAVE['id']#bundle.obj.enclaveId
        pubkey = b64decode(bytes(bundle.obj.pubkey,"utf-8")) # convert string into bytes, then decode 
        logger.debug("api/resource.py - public key:%s",pubkey)
        keyId = bundle.obj.keyId
        sealed_pk=simple.sealkey(enclaveId,pubkey,URL_TEEP)
        sealed_pk=b64encode(sealed_pk).decode() # encode sealed_pk into base64, then convert it into string
        logger.debug("api/resource.py - sealed key:%s,type:%s",sealed_pk,type(sealed_pk))
        Key.objects.create(key=sealed_pk, keyId=keyId)
       
        bundle.obj.pubkey = ''
        bundle.obj.report = ''
        #bundle.obj.enclaveId = '' # hide KeyW in the response
        bundle.obj.keyId = ''
        return bundle

#===============================================================================
# "EnclaveId" resource
#===============================================================================
class EnclaveIdResource(ModelResource):
    class Meta:
        queryset = Key.objects.all()
        resource_name = 'enclaveid'
        authorization = Authorization()
        fields = ['encId']
        allowed_methods = ['get','post','delete'] # only allow GET, POST method
        filtering = {
            "encId": ['exact'],
        }


