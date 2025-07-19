from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    SignupView, CustomLoginView, SendOTPView, VerifyOTPView, SetNewPasswordView,
    ResendOTPView, MakeSuperUserView, UserListView, RevokeSuperUserView,
    OTPRequestHistoryView, LoginHistoryView,
    ProductImageUploadView, CartListView, CartAddView, CartUpdateView, CartDeleteView,
    ProductCreateView, ProductListView, ProductUpdateView, ProductDeleteView, ProductSingleView,
    AddressCreateView, AddressListView, AddressUpdateView, AddressDeleteView,CancelOrderView,
    PlaceOrderView,OrderListView,AddFavouriteView, RemoveFavouriteView, ListFavouritesView,ProductSearchView,ProductFilterView
)

urlpatterns = [

    # ----------- Auth Views -----------
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', CustomLoginView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('set-password/', SetNewPasswordView.as_view(), name='set-password'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('make-superuser/', MakeSuperUserView.as_view()),
    path('revoke-superuser/', RevokeSuperUserView.as_view()),
    path('users/', UserListView.as_view(), name='user-list'),
    path('login-history/', LoginHistoryView.as_view()),
    path('otp-history/', OTPRequestHistoryView.as_view()),

    # ----------- Product Views -----------
    path('product/create/', ProductCreateView.as_view(), name='product-create'),
    path('product/list/', ProductListView.as_view(), name='product-list'),
    path('product/<int:pk>/', ProductSingleView.as_view(), name='product-single'),
    path('product/update/<int:pk>/', ProductUpdateView.as_view(), name='product-update'),
    path('product/delete/<int:pk>/', ProductDeleteView.as_view(), name='product-delete'),
    path('upload-product-image/', ProductImageUploadView.as_view(), name='upload-product-image'),

    # ----------- Cart Views -----------
    path('cart/', CartListView.as_view(), name='cart-list'),
    path('cart/add/', CartAddView.as_view(), name='cart-add'),
    path('cart/update/<int:pk>/', CartUpdateView.as_view(), name='cart-update'),
    path('cart/delete/<int:pk>/', CartDeleteView.as_view(), name='cart-delete'),

    # ----------- Address Views -----------
    path('address/', AddressCreateView.as_view(), name='add-address'),
    path('address/list/', AddressListView.as_view(), name='list-address'),
    path('address/<int:pk>/update/', AddressUpdateView.as_view(), name='update-address'),
    path('address/<int:pk>/delete/', AddressDeleteView.as_view(), name='delete-address'),

    #-------------order-----------------------
    path('order/',PlaceOrderView.as_view(),name='order'),
    path('order/cncel/<int:order_id>/',CancelOrderView.as_view(),name='order-cancel'),
    path('orders/list/', OrderListView.as_view(), name='order-list'),

    #--------------favourites-------------------
     path('favourites/add/', AddFavouriteView.as_view(), name='add-favourite'),
    path('favourites/remove/<int:product_id>/', RemoveFavouriteView.as_view(), name='remove-favourite'),
    path('favourites/list/', ListFavouritesView.as_view(), name='list-favourites'),

    #------------------search-----------------
       path('products/search/', ProductSearchView.as_view(),name="product-search"),
        path('products/filter/', ProductFilterView.as_view(), name='product-filter'),
       


]

# For serving media files during development
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
