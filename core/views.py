import logging
import json

from core.models import Account
from core.serializers import UserSerializer, AuthTokenSerializer
from rest_framework import filters
from rest_framework import viewsets, mixins, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from core.models import TokenAuth as Token
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from rest_framework.exceptions import AuthenticationFailed

from core.utils.CryptographyModule import CryptoCipher, get_data

logger = logging.getLogger(__name__)


class RegisterView(viewsets.GenericViewSet,
                   mixins.CreateModelMixin):
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        print(request.data['data'])
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        print(plain_text)
        data = json.loads(plain_text)
        data = data if isinstance(data, dict) else {}
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        password = data.pop('password')
        user = Account(**data)
        user.set_password(password)
        user.save()
        response = crypto_obj.encrypt_text("{}".format(
            {
                "response": "user created."
            }
        ))
        return Response({'response': response}, status.HTTP_201_CREATED)


class LoginView(viewsets.GenericViewSet,
                mixins.CreateModelMixin):
    serializer_class = AuthTokenSerializer
    queryset = Token.objects.all()
    DEFAULT_TOKEN_EXPIRE = getattr(settings, "DEFAULT_TOKEN_EXPIRE")

    def create(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        data = data if isinstance(data, dict) else {}
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        try:
            token, created = Token.objects.get_or_create(user=user)
            # Checking state that the token of user expired and generate new token for this user.
            if not created:
                if not (timezone.now() - timedelta(seconds=self.DEFAULT_TOKEN_EXPIRE['PER_USE'])) < token.last_use or \
                        not (timezone.now() - timedelta(seconds=self.DEFAULT_TOKEN_EXPIRE['TOTAL'])) < token.created:
                    token.delete()
                    token = Token.objects.create(user=user)
            headers = self.get_success_headers(serializer.data)
            response = crypto_obj.encrypt_text("{}".format(
                {
                    'token': token.key
                }
            ))
            return Response({'response': response}, status=status.HTTP_200_OK, headers=headers)
        except AuthenticationFailed as e:
            response = crypto_obj.encrypt_text("{}".format(
                {
                    'response': e
                }
            ))
            return Response({'response': response}, status=status.HTTP_401_UNAUTHORIZED)
