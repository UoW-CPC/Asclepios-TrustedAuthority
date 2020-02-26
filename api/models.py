from django.db import models

# Create your models here.
class FileNo(models.Model):
    w = models.CharField(max_length=500,unique=True)
    fileno = models.IntegerField()
    def __str__(self):
        return '%s %d' % (self.w, self.fileno)

    
class SearchNo(models.Model):
    w = models.CharField(max_length=500,unique=True)
    searchno = models.IntegerField()
    def __str__(self):
        return '%s %d' % (self.w, self.searchno)