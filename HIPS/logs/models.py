from django.db import models

# Create your models here.
class CheckSuma(models.Model):
    directorio = models.CharField(max_length=80)
    hashsuma   = models.CharField(max_length=80)
