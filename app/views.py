from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    SignupSerializer, CustomLoginSerializer, ResendOTPSerializer,
    SendOTPSerializer, UserListSerializer, SuperUserActionSerializer,
    SetNewPasswordSerializer, OTPVerifySerializer, OTPRequestHistorySerializer,
    LoginHistorySerializer, ProductSerializer, CartSerializer, AddressSerializer,
    OrderSerializer
)

from .models import (
    CustomUser, OTPRequestHistory, LoginHistory,
    Product, Cart, ProductImage, Address, Order, OrderItem
)

from .permissions import IsSuperUserOnly
from .utils import get_client_ip


# ---------------- Auth Views ----------------

class SignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "User created successfully",
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendOTPView(APIView):
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                OTPRequestHistory.objects.create(user=user)
            except CustomUser.DoesNotExist:
                pass
            return Response({"message": "OTP sent successfully."}, status=200)
        return Response(serializer.errors, status=400)


class CustomLoginView(APIView):
    def post(self, request):
        serializer = CustomLoginSerializer(data=request.data)
        if serializer.is_valid():
            validated = serializer.validated_data
            user = CustomUser.objects.get(id=validated["user"]["id"])
            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")
            )
            return Response(validated, status=200)
        return Response(serializer.errors, status=400)


class VerifyOTPView(APIView):
    def post(self, request):
        otp = request.data.get("otp")
        email = request.data.get("email")
        serializer = OTPVerifySerializer(data={"otp": otp}, context={"email": email})
        if serializer.is_valid():
            request.session['reset_email'] = email
            return Response({"message": "OTP verified successfully"}, status=200)
        return Response(serializer.errors, status=400)


class SetNewPasswordView(APIView):
    def post(self, request):
        email = request.session.get("reset_email")
        if not email:
            return Response({'error': 'Session expired. Please verify OTP again.'}, status=400)
        serializer = SetNewPasswordSerializer(data=request.data, context={"email": email})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password reset successful"}, status=200)
        return Response(serializer.errors, status=400)


class ResendOTPView(APIView):
    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "OTP resent successfully."}, status=200)
        return Response(serializer.errors, status=400)


class UserListView(APIView):
    permission_classes = [IsSuperUserOnly]
    def get(self, request):
        users = CustomUser.objects.all()
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data)


class MakeSuperUserView(APIView):
    permission_classes = [IsSuperUserOnly]
    def post(self, request):
        serializer = SuperUserActionSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User promoted to superuser successfully."})
        return Response(serializer.errors, status=400)


class RevokeSuperUserView(APIView):
    permission_classes = [IsSuperUserOnly]
    def post(self, request):
        serializer = SuperUserActionSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = CustomUser.objects.get(id=serializer.validated_data['user_id'])
            user.is_superuser_custom = False
            user.save()
            return Response({"message": f"{user.email} is no longer a superuser."})
        return Response(serializer.errors, status=400)


class OTPRequestHistoryView(APIView):
    permission_classes = [IsSuperUserOnly]
    def get(self, request):
        history = OTPRequestHistory.objects.all()
        serializer = OTPRequestHistorySerializer(history, many=True)
        return Response(serializer.data)


class LoginHistoryView(APIView):
    permission_classes = [IsSuperUserOnly]
    def get(self, request):
        logs = LoginHistory.objects.all().order_by('-login_time')
        serializer = LoginHistorySerializer(logs, many=True)
        return Response(serializer.data)


# ---------------- Product Views ----------------

class ProductCreateView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUserOnly]
    def post(self, request):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Product created successfully."}, status=201)
        return Response(serializer.errors, status=400)


class ProductSingleView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        try:
            product = Product.objects.get(pk=pk)
            serializer = ProductSerializer(product)
            return Response(serializer.data, status=200)
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)


class ProductListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data, status=200)


class ProductUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUserOnly]
    def put(self, request, pk):
        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)
        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Product updated successfully"})
        return Response(serializer.errors, status=400)


class ProductDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUserOnly]
    def delete(self, request, pk):
        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)
        product.delete()
        return Response({"message": "Product deleted successfully"}, status=204)


class ProductImageUploadView(APIView):
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        product_id = request.data.get('product')
        images = request.FILES.getlist('image')
        if not product_id:
            return Response({"error": "Product ID is required"}, status=400)
        try:
            product = Product.objects.get(id=product_id)
        except Product.DoesNotExist:
            return Response({"error": "Product not found"}, status=404)
        for img in images:
            ProductImage.objects.create(product=product, image=img)
        return Response({"message": "Images uploaded successfully"}, status=201)


# ---------------- Cart Views ----------------

class CartListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        cart_items = Cart.objects.filter(user=request.user)
        serializer = CartSerializer(cart_items, many=True)
        return Response(serializer.data)


class CartAddView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = CartSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Product added to cart"}, status=201)
        return Response(serializer.errors, status=400)


class CartUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, pk):
        try:
            cart_item = Cart.objects.get(id=pk, user=request.user)
        except Cart.DoesNotExist:
            return Response({"error": "Item not found"}, status=404)
        serializer = CartSerializer(cart_item, data=request.data, context={'request': request}, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Cart item updated"})
        return Response(serializer.errors, status=400)


class CartDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk):
        try:
            cart_item = Cart.objects.get(id=pk, user=request.user)
        except Cart.DoesNotExist:
            return Response({"error": "Item not found"}, status=404)
        cart_item.delete()
        return Response({"message": "Item removed from cart"}, status=204)


# ---------------- Address Views ----------------

class AddressCreateView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = AddressSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


class AddressListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        addresses = Address.objects.filter(user=request.user)
        serializer = AddressSerializer(addresses, many=True)
        return Response(serializer.data)


class AddressUpdateView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, pk):
        try:
            address = Address.objects.get(pk=pk, user=request.user)
        except Address.DoesNotExist:
            return Response({"error": "Address not found"}, status=404)
        serializer = AddressSerializer(address, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


class AddressDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk):
        try:
            address = Address.objects.get(pk=pk, user=request.user)
        except Address.DoesNotExist:
            return Response({"error": "Address not found"}, status=404)
        address.delete()
        return Response({"message": "Address deleted successfully"}, status=204)


# ---------------- Order Views ----------------

class PlaceOrderView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        address_id = request.data.get("address_id")
        payment_mode = request.data.get("payment_mode", "COD")

        try:
            address = Address.objects.get(id=address_id, user=user)
        except Address.DoesNotExist:
            return Response({"error": "Invalid address"}, status=400)

        cart_items = Cart.objects.filter(user=user)
        if not cart_items.exists():
            return Response({"error": "Cart is empty"}, status=400)

        order = Order.objects.create(user=user, address=address, payment_mode=payment_mode)

        for item in cart_items:
            product = item.product
            if product.quantity < item.quantity:
                return Response({"error": f"Insufficient stock for {product.name}"}, status=400)

            # Decrease product stock
            product.quantity -= item.quantity
            product.save()

            # Create order item
            OrderItem.objects.create(
                order=order,
                product=product,
                quantity=item.quantity,
                price=product.price
            )

        cart_items.delete()

        serializer = OrderSerializer(order)
        return Response({"message": "Order placed successfully", "order": serializer.data}, status=201)
    
class CancelOrderView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, order_id):
        user = request.user
        try:
            order = Order.objects.get(id=order_id, user=user)
        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=404)

        if order.status == 'Cancelled':
            return Response({"message": "Order is already cancelled"}, status=400)

        order.status = 'Cancelled'
        order.save()

        return Response({"message": f"Order #{order.id} cancelled successfully"})


class OrderListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        orders = Order.objects.filter(user=user).order_by('-created_at')
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)