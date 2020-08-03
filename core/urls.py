from rest_framework import routers

from .views import *

router = routers.DefaultRouter()
router.register(r'register', RegisterView, basename='Register')
router.register(r'login', LoginView, basename='Login')
router.register(r'list', ListView, base_name='List')
router.register(r'upload', UploadView, base_name='Upload')
router.register(r'read', ReadContentView, base_name='Read')
router.register(r'write', WriteContentView, base_name='Write')
router.register(r'get', GetFileView, base_name='Get')
router.register(r'chmod', ChangeAccessView, base_name='Access')

urlpatterns = router.urls
