from django.contrib import admin
from django.urls import re_path, include

urlpatterns = [
    re_path('admin/', admin.site.urls),
    re_path('api/v1/auth/',include('accounts.urls')),
]
