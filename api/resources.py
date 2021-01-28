from tastypie.resources import ModelResource, Resource, fields
from api.models import FileNo,SearchNo,Key
from tastypie.authorization import Authorization
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from tastypie.bundle import Bundle 
from parameters import SALT, IV, hash_length # KeyG
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
#===============================================================================
# Common functions, constants
#===============================================================================  

# Get an instance of a logger
logger = logging.getLogger(__name__)
NO_ATTRIBUTES = 400 # allow to get maximum of NO_ATTRIBUTES items at once
update_lock = sem = threading.Semaphore()
URL_TEEP = os.environ['TEEP_SERVER']

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
        
        KeyW = bundle.obj.KeyW
        logger.debug("Type of ciphertext: %s",type(KeyW))
        logger.debug("keyW:%s",KeyW)
        logger.debug("bundle object:{}",bundle)
        # Recover hash(w) and searchNo[w] from KeyW
        # Retrieve KeyG from database
        keyid = bundle.obj.keyId;
        logger.debug("Id of key:%s",bundle.obj.keyId);

        KeyG=Key.objects.get(keyId=keyid).key;
        
        logger.debug("key: %s",KeyG)
        logger.debug("KeyW: %s",KeyW)
        
        
        try:
            plaintext = SJCL().decrypt(KeyW, KeyG)
        except: # cannot decrypt
            logger.debug("wrong token")
            bundle.obj.Lta = ''
            bundle.obj.KeyW = 'error' # hide KeyW in the response
            return bundle
            
        logger.debug("plaintext: %s",plaintext)
        
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
        
        plaintext_byte =  str.encode(hashW + searchNo)
        logger.debug("new plaintext: %s", plaintext_byte)
        newKeyW = SJCL().encrypt(plaintext_byte,KeyG,SALT,IV) # Compute new KeyW
        logger.debug("new ciphertext: {}", newKeyW)
        
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
        logger.debug("Type of request:",requestType)
        logger.debug("Request content:",Lw)
        
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
    enclaveId = ''
    keyId = ''

class PubKeyResource(Resource):
    pubkey = fields.CharField(attribute = 'pubkey')
    report = fields.CharField(attribute = 'report')
    enclaveId = fields.CharField(attribute = 'enclaveId')
    keyId = fields.CharField(attribute = 'keyId')

    class Meta:
        resource_name = 'pubkey'
        object_class = PubKey
        authorization = Authorization()
        allowed_methods = ['get','post'] # only allow GET, POST method
        field = ['report','pubkey','enclaveId','keyId']
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
        pk, report,enclave_id = simple.getpubkey(URL_TEEP)
        bundle_obj = PubKey()
        bundle_obj.pubkey = pk
        bundle_obj.report = report
        bundle_obj.enclaveId = enclave_id
        bundle_obj.keyId=keyId
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

        # invoke API of TA
        enclaveId = bundle.obj.enclaveId
        pubkey = bundle.obj.pubkey
        keyId = bundle.obj.keyId
        sealed_pk=simple.sealkey(enclaveId,pubkey,URL_TEEP)
        Key.objects.create(key=sealed_pk, keyId=keyId)

        bundle.obj.pubkey = ''
        bundle.obj.report = ''
        bundle.obj.enclaveId = '' # hide KeyW in the response
        bundle.obj.keyId = ''
        return bundle
