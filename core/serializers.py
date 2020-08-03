import logging
from rest_framework import serializers
from django.utils.translation import ugettext_lazy as _
from core.models import Account, File, AccessControl
from core.utils.CryptographyModule import CryptoCipher
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from core.models import TokenAuth as Token
from django.conf import settings
from datetime import timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)

MAX_TRY = getattr(settings, "MAX_TRY")
MAX_TIME_TRY = getattr(settings, "MAX_TIME_TRY")


class UserSerializer(serializers.Serializer):
    username = serializers.CharField(label=_("Username"))
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False
    )
    confidentiality_label = serializers.IntegerField()
    integrity_label = serializers.IntegerField()

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    def validate_confidentiality_label(self, value):
        if not 0 < value < 5:
            raise serializers.ValidationError("confidentiality_label is invalid.")

    def validate_integrity_label(self, value):
        if not 0 < value < 5:
            raise serializers.ValidationError("integrity_label is invalid.")

    class Meta:
        fields = ['username', 'password', 'confidentiality_label', 'integrity_label']


class AuthTokenSerializer(serializers.Serializer):
    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass

    username = serializers.CharField(required=False, label=_("Username"))
    password = serializers.CharField(
        required=False,
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:

                usr = Account.objects.filter(username=username).first()
                if usr:
                    if usr.number_try >= MAX_TRY and Token.created >= timezone.now() - timedelta(seconds=MAX_TIME_TRY):
                        logger.critical("User {} try to login with incorrect password number try:{}".format(username, usr.number_try))
                        usr.number_try = 0
                        usr.save()
                    else:
                        usr.number_try = usr.number_try + 1
                        usr.save()
                else:
                    logger.critical("User {} try to login with incorrect password.".format(username))
                raise serializers.ValidationError({'response': 'Unable to log in with provided credentials.'})
        else:
            logger.debug("A user with send invalid data to server.")
            raise serializers.ValidationError({'response': 'Must include Username and Password.'})
        attrs['user'] = user
        return attrs


class FileSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(source='owner.username', read_only=True)

    class Meta:
        model = File
        fields = ['file_name', 'owner', 'confidentiality_label', 'integrity_label']


class FileUploadSerializer(serializers.ModelSerializer):

    class Meta:
        model = File
        fields = ['file_name', 'owner', 'confidentiality_label', 'integrity_label']


class ChangeAccessControlSerializer(serializers.ModelSerializer):
    obj = serializers.PrimaryKeyRelatedField(source='obj.file_name', read_only=True)
    subject = serializers.PrimaryKeyRelatedField(source='subject.username', read_only=True)
    class Meta:
        model = AccessControl
        fields = ['subject', 'obj', 'access']
