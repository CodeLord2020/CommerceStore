from django.contrib import admin

# Register your models here.
from .models import Vendor, User, Token, UserRating

# Register your models here.

admin.site.register(Vendor)
admin.site.register(User)
admin.site.register(Token)
admin.site.register(UserRating)