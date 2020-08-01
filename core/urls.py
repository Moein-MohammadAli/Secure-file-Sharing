from rest_framework import routers

from .views import *

router = routers.DefaultRouter()
router.register(r'register', RegisterView, basename='Register')
router.register(r'login', LoginView, basename='Login')
router.register(r'list', ListView, base_name='list')
router.register(r'upload', UploadView, base_name='upload')
router.register(r'read', ReadContentView, base_name='read')
router.register(r'write', WriteContentView, base_name='write')
router.register(r'get', GetFileView, base_name='get')

urlpatterns = router.urls
