from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
import random

from .models import (
    CustomUser, PasswordResetOTP, OTPRequestHistory, LoginHistory,
    Product, Cart, ProductImage, Address, Order, OrderItem,Favourite
)

# ------------------- Signup Serializer -------------------
class SignupSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'phone', 'name', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        return CustomUser.objects.create_user(**validated_data)


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name', 'is_superuser']


# ------------------- Custom Login Serializer -------------------
class CustomLoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            try:
                user = CustomUser.objects.get(phone=email)
            except CustomUser.DoesNotExist:
                raise serializers.ValidationError("Invalid email or phone")

        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password")

        if not user.is_active:
            raise serializers.ValidationError("User is inactive")

        refresh = RefreshToken.for_user(user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "id": user.id,
                "email": user.email,
                "phone": user.phone,
            }
        }


# ------------------- OTP Serializers -------------------
class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def create(self, validated_data):
        email = validated_data['email']
        otp = str(random.randint(100000, 999999))
        PasswordResetOTP.objects.create(email=email, otp=otp)

        send_mail(
            subject="Your OTP for Password Reset",
            message=f"Your OTP is: {otp}",
            from_email="yourprojectemail@gmail.com",
            recipient_list=[email],
        )
        return {"message": "OTP sent successfully."}


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def create(self, validated_data):
        email = validated_data['email']
        otp = str(random.randint(100000, 999999))

        PasswordResetOTP.objects.filter(email=email).delete()
        PasswordResetOTP.objects.create(email=email, otp=otp)

        send_mail(
            subject="Your New OTP",
            message=f"Your OTP is: {otp}",
            from_email="yourprojectemail@gmail.com",
            recipient_list=[email]
        )
        return {"message": "OTP resent successfully."}


class OTPVerifySerializer(serializers.Serializer):
    otp = serializers.IntegerField()

    def validate(self, attrs):
        otp = attrs.get("otp")
        email = self.context.get("email")

        if not email:
            raise serializers.ValidationError("Email not provided")

        try:
            otp_obj = PasswordResetOTP.objects.filter(email=email, otp=otp).latest('created_at')
        except PasswordResetOTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP")

        if timezone.now() - otp_obj.created_at > timedelta(minutes=10):
            raise serializers.ValidationError("OTP expired")

        return attrs


class SetNewPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        email = self.context.get("email")
        if not email:
            raise serializers.ValidationError("Email not provided")

        user = CustomUser.objects.get(email=email)
        user.set_password(validated_data['new_password'])
        user.save()

        PasswordResetOTP.objects.filter(email=email).delete()
        return user


# ------------------- SuperUser Promote/Demote -------------------
class SuperUserActionSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()

    def validate(self, data):
        request_user = self.context['request'].user
        if not request_user.is_authenticated or not request_user.is_superuser_custom:
            raise serializers.ValidationError("Only superusers can perform this action.")
        return data

    def create(self, validated_data):
        user_id = validated_data['user_id']
        try:
            user = CustomUser.objects.get(id=user_id)
            user.is_superuser_custom = True
            user.save()
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")


# ------------------- History Serializers -------------------
class OTPRequestHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = OTPRequestHistory
        fields = ['id', 'user', 'requested_at']


class LoginHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginHistory
        fields = ['id', 'user', 'login_time', 'ip_address', 'user_agent']


# ------------------- Product Serializers -------------------
class ProductImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ['id', 'product', 'image', 'uploaded_at']


class ProductSerializer(serializers.ModelSerializer):
    images = ProductImageSerializer(many=True, read_only=True)

    class Meta:
        model = Product
        fields = [
            'id', 'brand_name', 'product_name', 'product_id',
            'price', 'quantity', 'description', 'specification', 'images'
        ]

    def validate_specification(self, value):
        required_keys = ["frame_width", "frame_size", "material", "shape", "weight"]
        missing_keys = [key for key in required_keys if key not in value]

        if missing_keys:
            raise serializers.ValidationError(
                f"Missing keys in specification: {', '.join(missing_keys)}"
            )
        return value


# ------------------- Cart Serializer -------------------
class CartSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        source='product',
        write_only=True
    )

    class Meta:
        model = Cart
        fields = ['id', 'user', 'product', 'product_id', 'quantity', 'added_at']
        read_only_fields = ['user']

    def validate(self, attrs):
        user = self.context['request'].user
        product = attrs.get('product')

        if self.context['request'].method == 'POST':
            if Cart.objects.filter(user=user, product=product).exists():
                raise serializers.ValidationError("Product already in cart.")
        return attrs

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


# ------------------- Address Serializer -------------------
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = [
            'id',         #  PK field (important)
            'user',       #  read-only
            'full_name',
            'phone',
            'pincode',
            'house',
            'area',
            'city',
            'state',
            'created_at'  # 🔒 read-only
        ]
        read_only_fields = ['user', 'created_at']


# ------------------- Order Serializers -------------------



class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ['product', 'quantity', 'price']

class OrderSerializer(serializers.ModelSerializer):
    address = AddressSerializer(read_only=True) #-------> adress isliye postman me nahi dal rahe kyuki pehle se bol diya hai read_only 
    address_id = serializers.IntegerField(write_only=True)
    items = OrderItemSerializer(many=True, read_only=True)
    

    class Meta:
        model = Order
        fields = ['id', 'user', 'address', 'address_id', 'payment_mode', 'status', 'created_at','items']
        read_only_fields = ['id', 'user', 'status', 'created_at']

#---------------------------------------------------------------
class FavouriteSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    class Meta:
        model = Favourite
        fields = ['id', 'product']

