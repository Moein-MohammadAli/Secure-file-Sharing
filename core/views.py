import logging
import json
import os

from core.models import Account, File
from core.serializers import UserSerializer, AuthTokenSerializer, FileSerializer
from core.serializers import FileUploadSerializer, WriteFileSerializer
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
from django.db.utils import IntegrityError
from rest_framework.exceptions import AuthenticationFailed
from core.authentication import ExpireTokenAuthentication
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import JsonResponse

from core.utils.CryptographyModule import CryptoCipher, get_data

logger = logging.getLogger(__name__)


class RegisterView(viewsets.GenericViewSet,
                   mixins.CreateModelMixin):
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        data = data if isinstance(data, dict) else {}
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        password = data.pop('password')
        try:
            user = Account(**data)
            user.set_password(password)
            user.save()
            response = crypto_obj.encrypt_text("{}".format(
                {
                    "response": "user created."
                }
            ))
            return Response({'response': response}, status.HTTP_201_CREATED)
        except IntegrityError as e:
            response = crypto_obj.encrypt_text("{}".format(
                {
                    "response": "This username exist."
                }
            ))
            return Response({"response": response}, status.HTTP_400_BAD_REQUEST)


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
        try:
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
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
        except ValidationError as e:
            error = e.detail.get('response')
            response = crypto_obj.encrypt_text("{}".format(
                {
                    'response': error[0].__str__() if error else 'error'
                }
            ))
            return Response({'response': response}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response = crypto_obj.encrypt_text("{}".format(
                {
                    'response': e
                }
            ))
            return Response({'response': response}, status=status.HTTP_401_UNAUTHORIZED)


class ListView(viewsets.GenericViewSet, 
               mixins.ListModelMixin):
    queryset = File.objects.all()
    serializer_class = FileSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        queryset = self.get_queryset()
        serializer = FileSerializer(queryset, many=True)
        try:
            rsp = "{}".format(json.dumps(serializer.data))
            rsp = crypto_obj.encrypt_text(rsp)
            return Response({"response": rsp})
        except:
            print("No Date file in database")
            return Response({"response": {}})


class UploadView(viewsets.GenericViewSet,
                 mixins.CreateModelMixin):
    queryset = File.objects.all()
    serializer_class = FileUploadSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def put(self, request, *args, **kwargs):
        data = json.dumps(request.data)
        data = json.loads(data)
        data["owner"] = Account.objects.get(id=int(request.user.id))
        data["confidentiality_label"] = int(data["confidentiality_label"])
        data["integrity_label"] = int(data["integrity_label"])
        serializer = FileUploadSerializer(data=data)
        if serializer.is_valid():
            serializer.save(file_name=data["file_name"],
                                owner=data["owner"], 
                                confidentiality_label=data['confidentiality_label'],
                                integrity_label=data['integrity_label'])
            with open("./media/"+data["file_name"], 'w') as f:
                f.write(data["data_file"])
            return Response(status=status.HTTP_201_CREATED)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class ReadContentView(viewsets.GenericViewSet,
                      mixins.ListModelMixin):
    serializer_class = FileSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self.list(request)
        
    def list(self, request, *args, **kwargs):
        queryset = File.objects.get(file_name=request.data['file_name'])
        data = json.dumps(request.data)
        data = json.loads(data)
        with open("./media/"+data['file_name'], 'r') as f:
            content = f.read()
        return Response({'response': content})


class WriteContentView(viewsets.GenericViewSet,
                       mixins.ListModelMixin):
    
    serializer_class = FileSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self.list(request)
        
    def list(self, request, *args, **kwargs):
        queryset = File.objects.filter(file_name=request.data['file_name']).update(updated_at=datetime.now())
        data = json.dumps(request.data)
        data = json.loads(data)
        with open("./media/"+data['file_name'], 'w') as f:
            f.write(request.data['content'])
        return Response({'response': request.data['content']})

class GetFileView(viewsets.GenericViewSet,
                       mixins.ListModelMixin):
    
    serializer_class = FileSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self.list(request)
        
    def list(self, request, *args, **kwargs):
        queryset = File.objects.filter(file_name=request.data['file_name']).delete()
        data = json.dumps(request.data)
        data = json.loads(data)
        rsp = {
            "data_file": open("./media/"+data['file_name'], 'r'),
            "file_name": data['file_name']
        }
        os.remove("./media/"+data['file_name'])
        return Response({"response": rsp})
     