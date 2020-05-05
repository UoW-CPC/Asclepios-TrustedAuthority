from tastypie.resources import ModelResource, Resource, fields
from api.models import FileNo,SearchNo,Key
from tastypie.authorization import Authorization
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from tastypie.bundle import Bundle 
from parameters import SALT, IV, hash_length # KeyG
from django.db.models import Q

import json
import hashlib
import requests

import sys
sys.path.append('sjcl-0.2.1/sjcl') #we modified python sjcl a bit to allow define iv, salt of encryption
from sjcl import SJCL
import logging

#===============================================================================
# Common functions, constants
#===============================================================================  

# Get an instance of a logger
logger = logging.getLogger(__name__)
NO_ATTRIBUTES = 400 # allow to get maximum of NO_ATTRIBUTES items at once

#===============================================================================
# "File Number" resource
#===============================================================================
class FileNoResource(ModelResource):
    class Meta:
        queryset = FileNo.objects.all()
        resource_name = 'fileno'
        authorization = Authorization()
        fields = ['w', 'fileno']
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
        fields = ['w', 'searchno']
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
    
#===============================================================================
# "Search Query" resource
#===============================================================================       
class SearchResource(Resource):
    KeyW = fields.CharField(attribute = 'KeyW')
    Lta = fields.ListField(attribute='Lta',default=[]) # List of addresses, computed by TA
    
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
        
        # Recover hash(w) and searchNo[w] from KeyW
        # Retrieve KeyG from database
        KeyG = Key.objects.first().key;
        #logger.debug("retrieved key:%s",key1);
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
        #logger.debug("search no: %s", plaintext_str[hashChars:])
        #searchNo = plaintext_str[hashChars:] # NEED to correct: it should read locally instead of parsing
        try:
            searchNo = SearchNo.objects.get(w=hashW).searchno # check
        except: # if searchno does not exist
            searchNo = 0
        
        # increase search number
        #searchNo = str(int(searchNo) + 1)
        searchNo = str(searchNo + 1)
        
        logger.debug("hashW: %s, searchNo: %s", hashW, searchNo)
        
        plaintext_byte =  str.encode(hashW + searchNo)
        logger.debug("new plaintext: %s", plaintext_byte)
        newKeyW = SJCL().encrypt(plaintext_byte,KeyG,SALT,IV) # Compute new KeyW
        logger.debug("new ciphertext: {}", newKeyW)
        #logger.debug("decrypted value: %s", SJCL().decrypt(newKeyW, KeyG))
        newKeyW_ciphertext = newKeyW['ct'] # convert type from dict (newKeyW) to byte (newKeyW_byte)
        logger.debug("newKeyW_ciphertext: %s", newKeyW_ciphertext) 
        
        logger.debug("Retrieve fileno")
        Lta = []
        try:
            fileno = FileNo.objects.get(w=hashW).fileno
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
            return bundle # return the list of computed addresses to CSP, which sends the request

# #===============================================================================
# # "Long line request" object
# #===============================================================================  
# class LongLineReq(object):
#     requestType  = '' # requestType can be "searchno" or "fileno"
#     requestLine = ''
#     
# #===============================================================================
# # "Long line request" resource
# #===============================================================================       
# class LongLineReqResource(Resource):
#     requestType = fields.CharField(attribute = 'requestType')
#     requestLine = fields.CharField(attribute='requestLine')
#     #Lno = fields.ListField(attribute='Lno',default=[]) # List of addresses, computed by TA
#       
#     class Meta:
#         resource_name = 'longrequest'
#         object_class = LongLineReq
#         authorization = Authorization()
#         always_return_data=True # This is enabled, permitting return results for post request
#         #fields = ['Lno']
#     
#      # adapted this from ModelResource
#     def get_resource_uri(self, bundle_or_obj):
#         kwargs = {
#             'resource_name': self._meta.resource_name,
#         }
# 
#         if isinstance(bundle_or_obj, Bundle):
#             kwargs['pk'] = bundle_or_obj.obj.requestType # pk is referenced in ModelResource
#         else:
#             kwargs['pk'] = bundle_or_obj.requestType
#           
#         if self._meta.api_name is not None:
#             kwargs['api_name'] = self._meta.api_name
#           
#         return self._build_reverse_url('api_dispatch_detail', kwargs = kwargs)
#  
#     def get_object_list(self, request):
#         # inner get of object list... this is where you'll need to
#         # fetch the data from what ever data source
#         return 0
#  
#     def obj_get_list(self, request = None, **kwargs):
#         # outer get of object list... this calls get_object_list and
#         # could be a point at which additional filtering may be applied
#         return self.get_object_list(request)
#  
#     def obj_get(self, bundle, request = None, **kwargs):
# #         get one object from data source
#         requestType = kwargs['pk']
#             
#         bundle_obj = LongLineReq()
#         bundle_obj.requestType = requestType
# 
#         try:
#             return bundle_obj
#         except KeyError:
#             raise NotFound("Object not found") 
#    
#     def obj_create(self, bundle, request = None, **kwargs):
#         logger.info("Long line request in TA Server")
#         
#         # create a new object
#         bundle.obj = LongLineReq()
#           
#         # full_hydrate does the heavy lifting mapping the
#         # POST-ed payload key/values to object attribute/values
#         bundle = self.full_hydrate(bundle)
#         
#         requestType = bundle.obj.requestType
#         requestLine = bundle.obj.requestLine
#         logger.debug("Type of request:",requestType)
#         logger.debug("Request content:",requestLine)
#         
#         if requestType=="fileno":
#             #response = FileNo.objects.filter(Q(w="patient[age]20") | Q(w="patient[age]23"))
#             logger.debug("Send internal request")
#             response = requests.get("http://127.0.0.1:8080/api/v1/fileno/?w="+requestLine)  
#             logger.debug("List of file no:",response)
#         else:   
#             #response = SearchNo.objects.get(w=requestLine)
#             response = requests.get("http://127.0.0.1:8080/api/v1/search/?w="+requestLine)  
#             logger.debug("List of search no:",response)
#         bundle.obj.requestLine = '' # hide requestLine in the response
#         bundle.obj.requestType = '' # hide requestType in the response
#         #bundle.data["result"]=response.text
#         bundle.data["result"]=response
#         return bundle


#===============================================================================
# "Key" resource
#===============================================================================
class KeyResource(ModelResource):
    class Meta:
        queryset = Key.objects.all()
        resource_name = 'key'
        authorization = Authorization()
        fields = ['key']
        allowed_methods = ['get','post','delete'] # only allow GET, POST method
        filtering = {
            "key": ['exact'],
        }
