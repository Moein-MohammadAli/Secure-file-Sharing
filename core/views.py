import logging
import json
import os

from core.models import Account, File, AccessControl
from core.serializers import UserSerializer, AuthTokenSerializer, FileSerializer
from core.serializers import FileUploadSerializer, ChangeAccessControlSerializer
from rest_framework import filters
from rest_framework import viewsets, mixins, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from core.models import TokenAuth as Token
from django.utils import timezone
from datetime import timedelta
from django.db.utils import IntegrityError
from rest_framework.exceptions import AuthenticationFailed
from core.authentication import ExpireTokenAuthentication
from rest_framework.permissions import BasePermission, IsAuthenticated
from django.conf import settings

from core.utils.CryptographyModule import get_data
from core.utils.general import blake, Biba, BLP, has_access

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = getattr(settings, "MAX_FILE_SIZE")


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
            return Response({"response": rsp}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.debug(e)
            return Response({"response": {}})


class UploadView(viewsets.GenericViewSet,
                 mixins.CreateModelMixin):
    queryset = File.objects.all()
    serializer_class = FileUploadSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def put(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        data["owner"] = Account.objects.get(id=int(request.user.id))
        data["confidentiality_label"] = int(data["confidentiality_label"])
        data["integrity_label"] = int(data["integrity_label"])
        subj_conf = Account.objects.get(id=request.user.id).confidentiality_label
        subj_intg = Account.objects.get(id=request.user.id).integrity_label
        print(subj_conf, subj_intg, data["confidentiality_label"], data["integrity_label"])
        serializer = FileUploadSerializer(data=data)
        if serializer.is_valid() and \
                len(data['data_file']) <= MAX_FILE_SIZE and \
                not violate_access(subj_conf, subj_intg, data["confidentiality_label"], data["integrity_label"]):
            serializer.save(file_name=data["file_name"],
                            file_name_hashed=blake(data["file_name"]),
                            owner=data["owner"],
                            confidentiality_label=data['confidentiality_label'],
                            integrity_label=data['integrity_label'])
            with open("./media/"+blake(data["file_name"]), 'w') as f:
                f.write(data["data_file"])
            obj = File.objects.get(file_name_hashed=blake(data["file_name"]))
            AccessControl.objects.create(subject=data["owner"], obj=obj, access=7).save()
            return Response(status=status.HTTP_201_CREATED)
        else:
            if not len(data['data_file']) <= MAX_FILE_SIZE:
                logger.debug(
                    "Requested File is not valid due to maximum file limit size user {}".format(request.user.username))
            return Response(status=status.HTTP_400_BAD_REQUEST)


class ReadContentView(viewsets.GenericViewSet,
                      mixins.ListModelMixin):
    serializer_class = FileSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self.list(request)

    def list(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        try:
            queryset = File.objects.get(file_name_hashed=blake(data["file_name"]))
            subject_level = Account.objects.get(pk=request.user.id).confidentiality_label
            blp_access = BLP.s_property(subject_level, queryset.confidentiality_label)
            biba_access = Biba.s_property(subject_level, queryset.confidentiality_label)
            dac_access = has_access(request.user, queryset, "Get")
            if blp_access and biba_access and dac_access:
                if os.stat("./media/"+blake(data["file_name"])).st_size <= MAX_FILE_SIZE:
                    with open("./media/"+blake(data["file_name"]), 'r') as f:
                        content = f.read()
                    return Response({'response': crypto_obj.encrypt_text(content)}, status=status.HTTP_200_OK)
                else:
                    logger.debug("Requested File is not valid due to maximum file limit size user {}".format(
                        request.user.username))
            else:
                logger.critical({
                    "user": str(request.user.username),
                    "blp_access": blp_access,
                    "biba_access": biba_access,
                    "dac_access": dac_access
                })
                return Response({'response': crypto_obj.encrypt_text("Access Denied")}, status=status.HTTP_403_FORBIDDEN)
        except File.DoesNotExist as e:
            logger.debug(e)
            return Response({'response': crypto_obj.encrypt_text("File does not exist")}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class WriteContentView(viewsets.GenericViewSet,
                       mixins.ListModelMixin):

    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self.list(request)

    def list(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        try:
            queryset = File.objects.get(file_name_hashed=blake(data["file_name"]))
            subject_level = Account.objects.get(pk=request.user.id).confidentiality_label
            blp_access = BLP.star_property(subject_level, queryset.confidentiality_label)
            biba_access = Biba.star_property(subject_level, queryset.confidentiality_label)
            dac_access = has_access(request.user, queryset, "Get")
            if blp_access and biba_access and dac_access:
                if len(data['content']) <= MAX_FILE_SIZE:
                    File.objects.filter(file_name=blake(data["file_name"])).update(updated_at=timezone.now())
                    with open("./media/"+blake(data["file_name"]), 'w') as f:
                        f.write(data['content'])
                    return Response({'response': crypto_obj.encrypt_text("content written successfully")})
                else:
                    logger.debug(
                        "Requested File is not valid due to maximum file limit size user {}".format(
                            request.user.username)
                    )
            else:
                logger.critical({
                    "user": str(request.user.username),
                    "blp_access": blp_access,
                    "biba_access": biba_access,
                    "dac_access": dac_access
                })
                return Response({'response': crypto_obj.encrypt_text("Access Denied")}, status=status.HTTP_403_FORBIDDEN)
        except File.DoesNotExist as e:
            logger.debug(e)
            return Response({'response': crypto_obj.encrypt_text("File does not exist")}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class GetFileView(viewsets.GenericViewSet, mixins.ListModelMixin):

    serializer_class = FileSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        return self.list(request)

    def list(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        try:
            queryset = File.objects.get(file_name_hashed=blake(data["file_name"]))
            access_owner = True if request.user.id == queryset.owner.id else False
            dac_access = has_access(request.user, queryset, "Get")
            if access_owner or dac_access:
                if os.stat("./media/"+blake(data["file_name"])).st_size <= MAX_FILE_SIZE:
                    File.objects.filter(file_name_hashed=blake(data["file_name"])).delete()
                    rsp = {
                        "data_file": open("./media/"+blake(data["file_name"]), 'r').read(),
                        "file_name": data['file_name']
                    }
                    os.remove("./media/"+blake(data["file_name"]))
                    enc_rsp = crypto_obj.encrypt_text("{}".format(rsp))
                    return Response({"response": enc_rsp})
                else:
                    logger.debug(
                        "Requested File is not valid due to maximum file limit size user {}".format(
                            request.user.username
                        ))
            else:
                logger.critical({
                    "user": str(request.user.username),
                    "access_owner": access_owner,
                    "dac_access": dac_access
                })
                return Response({'response': crypto_obj.encrypt_text("Access Denied")}, status=status.HTTP_403_FORBIDDEN)
        except File.DoesNotExist as e:
            logger.debug(e)
            return Response({'response': crypto_obj.encrypt_text("File does not exist")}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class ChangeAccessView(viewsets.GenericViewSet,
                       mixins.ListModelMixin):
    queryset = AccessControl.objects.all()
    serializer_class = ChangeAccessControlSerializer
    authentication_classes = [ExpireTokenAuthentication]
    permission_classes = [BasePermission, IsAuthenticated]

    def post(self, request, *args, **kwargs):
        crypto_obj = get_data(request)
        plain_text = crypto_obj.decrypt_text(request.data['data']).replace('\'', '\"')
        data = json.loads(plain_text)
        try:
            record = {
                "subject": Account.objects.get(username=data["subject"]),
                "obj": File.objects.get(file_name_hashed=blake(data["obj"])),
                "access": int(data["access"])
            }
            owner_id = File.objects.get(file_name_hashed=blake(data["obj"])).owner.id
            serializer = ChangeAccessControlSerializer(data=record)
            if serializer.is_valid() and \
                    request.user.id == owner_id:
                serializer.save(subject=record['subject'],
                                obj=record['obj'],
                                access=record['access'])
                return Response({'response': crypto_obj.encrypt_text("Access assigned successfully")}, status=status.HTTP_200_OK)
            else:
                return Response({'response': crypto_obj.encrypt_text("Access assigned failed")}, status=status.HTTP_403_FORBIDDEN)
        except File.DoesNotExist as e:
            print(e)
            return Response({'response': crypto_obj.encrypt_text("File does not exist")}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

