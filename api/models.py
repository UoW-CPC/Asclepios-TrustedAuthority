from django.db import models

# Create your models here.
class FileNo(models.Model):
    w = models.CharField(max_length=255)
    fileno = models.IntegerField()
    keyId = models.CharField(max_length=20)
    def __str__(self):
        return '%s %d' % (self.w, self.fileno)
    class Meta:
        unique_together = ('w', 'keyId',)
   
class SearchNo(models.Model):
    w = models.CharField(max_length=255)
    searchno = models.IntegerField()
    keyId = models.CharField(max_length=20)
    def __str__(self):
        return '%s %d' % (self.w, self.searchno)
    class Meta:
        unique_together = ('w', 'keyId',)
    
class Key(models.Model):
    key = models.CharField(max_length=255)
    keyId = models.CharField(max_length=20,unique=True)
    def __str__(self):
        return '%s %d' % (self.key,self.keyId)