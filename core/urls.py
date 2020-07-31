from rest_framework import routers

from .views import *

router = routers.DefaultRouter()
router.register(r'register', RegisterView, basename='Register')
router.register(r'login', LoginView, basename='Login')
router.register(r'list', ListView, base_name='list')

urlpatterns = router.urls
