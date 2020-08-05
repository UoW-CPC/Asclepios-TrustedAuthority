from django.db import models

# Create your models here.
class FileNo(models.Model):
    w = models.CharField(max_length=500,unique=True)
    fileno = models.IntegerField()
    transaction_id = models.CharField(max_length=256,unique=False)
    def __str__(self):
        return '%s %d' % (self.w, self.fileno,self.transaction_id)
   
class SearchNo(models.Model):
    w = models.CharField(max_length=500,unique=True)
    searchno = models.IntegerField()
    transaction_id = models.CharField(max_length=256,unique=False)
    def __str__(self):
        return '%s %d' % (self.w, self.searchno,self.transaction_id)
    
class Key(models.Model):
    key = models.CharField(max_length=256,unique=True)
    def __str__(self):
        return '%s %d' % (self.key)