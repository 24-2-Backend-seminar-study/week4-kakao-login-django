from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class UserProfile(models.Model):
  user = models.OneToOneField(User, on_delete=models.CASCADE)
  is_social_login = models.BooleanField(default=False)
  social_provider = models.CharField(max_length=20, blank=True, null=True)
  nickname = models.CharField(max_length=30, blank=True, null=True)