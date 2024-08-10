from django.db import models
import uuid
# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils.crypto import get_random_string
from .managers import UserManager
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models import Avg


TOKEN_TYPE = (
    ('ACCOUNT_VERIFICATION', 'ACCOUNT_VERIFICATION'),
    ('PASSWORD_RESET', 'PASSWORD_RESET'),
)

class StarRatingField(models.IntegerField):
    def __init__(self, *args, **kwargs):
        kwargs['validators'] = [
            MinValueValidator(1),
            MaxValueValidator(5)
        ]
        super().__init__(*args, **kwargs)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=500)
    first_name = models.CharField(max_length=250, null=False, blank=False)
    last_name = models.CharField(max_length=250, null=False, blank=False)
    vendor_star = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    is_vendor = models.BooleanField(default=False)
    media_url = models.CharField(max_length=255, blank=True, null=True)
    cloud_id = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    objects = UserManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def update_vendor_star(self):
        if self.is_vendor:
            self.vendor_star = self.ratings_received.aggregate(Avg('rating'))['rating__avg'] or 0.00
            self.save()

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.first_name +' '+ self.last_name

    def get_short_name(self):
        return self.first_name



class Vendor(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=50)
    address_line_1 = models.TextField()
    address_line_2 = models.TextField(blank=True, null=True)
    media_url = models.CharField(max_length=255, blank=True, null=True)
    cloud_id = models.CharField(max_length=255, blank=True, null=True)
    town_city = models.TextField(help_text='Enter residing city or town')
    state = models.CharField(max_length=50)
    country = models.CharField(max_length=50)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.user.is_vendor = True
        self.user.save()

    def __str__(self):
        return self.user.first_name



class UserRating(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='ratings_received', on_delete=models.CASCADE)
    rater = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='ratings_given', on_delete=models.CASCADE)
    rating = StarRatingField()  # 1-5 rating
    review = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.user.update_vendor_star()
        self.user.save()




class Token(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, null=True)
    token_type = models.CharField(
        max_length=100, choices=TOKEN_TYPE, default='ACCOUNT_VERIFICATION'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{str(self.user)} {self.token}"

    def generate_random_token(self):
        if not self.token:
            self.token = get_random_string(30)
            self.save()

    def reset_user_password(self, password):
        self.user.set_password(password)
        self.user.save()
