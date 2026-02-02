from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from uuid import uuid4
class UserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    userid = models.CharField(max_length=50, unique=True, primary_key=True)  # Set userid as the primary key
    email = models.EmailField(unique=True)  # Email is unique but not the primary key
    name = models.CharField(max_length=100)
    role = models.CharField(max_length=50)
    address = models.TextField(blank=True, null=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'userid']

    def __str__(self):
        return self.email
class Message(models.Model):
    from_user = models.CharField(max_length=50)  # Changed to CharField
    to_user = models.CharField(max_length=50)  # Changed to CharField
    message = models.TextField()
    session_id = models.UUIDField(default=uuid4, editable=False)
    created_date = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.from_user} to {self.to_user}"