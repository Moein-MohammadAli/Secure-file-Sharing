from rest_framework import routers

from .views import *

router = routers.DefaultRouter()
router.register(r'register', RegisterView, basename='Register')
router.register(r'login', LoginView, basename='Login')

urlpatterns = router.urls
