from django.contrib import admin

# Register your models here.
from .models import UserContactInfo, User, Token

# Register your models here.

admin.site.register(UserContactInfo)
admin.site.register(User)
admin.site.register(Token)