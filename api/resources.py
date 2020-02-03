from tastypie.resources import ModelResource, Resource, fields
from api.models import FileNo,SearchNo
from tastypie.authorization import Authorization
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from tastypie.bundle import Bundle 
from parameters import KeyG, SALT, IV, hash_length

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
            "w": ['exact'],
        }

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
            "w": ['exact'],
        }

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
    fileno = 0
    
#===============================================================================
# "Search Query" resource
#===============================================================================       
class SearchResource(Resource):
    KeyW = fields.CharField(attribute = 'KeyW')
    fileno = fields.IntegerField(attribute='fileno')
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
        logger.debug("Type of ciphertext:",type(KeyW))
        
        
        # Recover hash(w) and searchNo[w] from KeyW
        logger.debug("key:",KeyG)
        logger.debug("KeyW",KeyW)
        plaintext = SJCL().decrypt(KeyW, KeyG)
        logger.debug("plaintext:",plaintext)
        
        hashChars = int(hash_length/4) # hash_length/4 = number of characters in hash value = 64
        
        plaintext_str = str(plaintext,'utf-8') # convert type from byte (plaintext) to string (plaintext_str)
        hashW = plaintext_str[0:hashChars]
        logger.debug("hashW:",hashW)
        logger.debug("search no:", plaintext_str[hashChars:])
        searchNo = plaintext_str[hashChars:]
        
        # increase search number
        searchNo = str(int(searchNo) + 1)
        
        logger.debug("hashW:", hashW, "searchNo:", searchNo)
        
        plaintext_byte =  str.encode(hashW + searchNo)
        logger.debug("new plaintext:", plaintext_byte)
        newKeyW = SJCL().encrypt(plaintext_byte,KeyG,SALT,IV)#b"abc123!?",b"abcdefg") # Compute new KeyW ,,
        logger.debug("new ciphertext:", newKeyW)
        logger.debug("decrypted value:", SJCL().decrypt(newKeyW, KeyG))
        newKeyW_ciphertext = newKeyW['ct'] # convert type from dict (newKeyW) to byte (newKeyW_byte)
        #newKeyW_str = str(newKeyW_byte,'utf-8') # convert type from byte (newKeyW_byte) to byte (newKeyW_str)
        logger.debug("newKeyW_ciphertext:", newKeyW_ciphertext) 
        
        fileno = bundle.obj.fileno
        Lta = []
        
        # Compute all addresses with the new key
        for i in range(1,int(fileno)+1):
            logger.debug("i:",i)
            logger.debug("newKeyW_ciphertext:",str(newKeyW_ciphertext,'utf-8'))
            input = (str(newKeyW_ciphertext,'utf-8') + str(i) + "0").encode('utf-8')
            addr = hash(input)
            logger.debug("hash input:",input)
            logger.debug("hash output (computed from newKeyW):", addr)
            Lta.append(addr)

        bundle.obj.Lta = Lta
        bundle.obj.KeyW = '' # hide KeyW in the response
        bundle.obj.fileno = 0 # hide fileNo in the response

        return bundle # return the list of computed addresses to CSP, which sends the request