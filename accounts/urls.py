from django.urls import path
from .views import RegisterUserView,LoginUserView,Test, PasswordResetConfirm,PasswordResetView,SetNewPassword

urlpatterns = [
    path('register/',RegisterUserView.as_view(),name='register'),
    path('login/',LoginUserView.as_view(),name='login'),
    path('test/',Test.as_view(),name='test'),
    path('password-reset-confirm/<uidb64>/<token>/',PasswordResetConfirm.as_view(),name="password-reset-confirm"),
    path('password-reset-view',PasswordResetView.as_view(),name="password-rest-view"),
    path('set-new-password',SetNewPassword.as_view(),name='set-new-password'),
    #path('logout',LogoutUserView.as_view(),name='logout')
]