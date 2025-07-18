from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.db import models
from django.utils import timezone
import random
from django.db import models
from django.conf import settings

class UserManager(BaseUserManager):
    def create_user(self,email,password=None,**extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save()
        return user
    
class CustomUser(AbstractBaseUser,PermissionsMixin):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    is_active = models.BooleanField(default=True)
    is_superuser_custom = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'

class Address(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    pincode = models.CharField(max_length=6)
    house = models.CharField(max_length=100)
    area = models.CharField(max_length=100)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name}, {self.city}"

class PasswordResetOTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now)

    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))

class OTPRequestHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    requested_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - OTP at {self.requested_at}"
    
class LoginHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.email} - Login at {self.login_time}"
    

    #---------------Product_tables---------------------------
class Product(models.Model):
    
        brand_name=models.CharField(max_length=100)
        product_name=models.CharField(max_length=100)
        product_id=models.CharField(max_length=20,unique=True)
        price=models.DecimalField(max_digits=10,decimal_places=2)
        quantity=models.IntegerField(default=5)
        description=models.TextField()
        specification=models.JSONField()

        def __str__(self):
          return self.product_name
        
class ProductImage(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='product_images/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.product.product_name} Image"       

class Cart(models.Model):
         user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
         product = models.ForeignKey('Product', on_delete=models.CASCADE)
         quantity = models.PositiveIntegerField(default=1)
         added_at = models.DateTimeField(auto_now_add=True)

         class Meta:
            unique_together = ('user', 'product')

         def __str__(self):
          return f"{self.user.username} - {self.product.name} x {self.quantity}"
         
#---------------------Order Model--------------------------
class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    address = models.ForeignKey(Address, on_delete=models.CASCADE)
    payment_mode = models.CharField(max_length=20, choices=[('COD', 'Cash On Delivery')])
    status = models.CharField(max_length=20, default='Placed')  # Placed, Cancelled, Delivered
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order #{self.id} by {self.user.username}"
    
class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)  # price at order time

    def __str__(self):
        return f"{self.product.product_name} x {self.quantity}"
      


    

    