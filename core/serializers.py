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
        if value not in [1, 2, 3, 4]:
            raise serializers.ValidationError({'response': 'confidentiality_label is invalid.'})
        else:
            return value

    def validate_integrity_label(self, value):
        if value not in [1, 2, 3, 4]:
            raise serializers.ValidationError({'response': 'integrity_label is invalid.'})
        else:
            return value

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
<<<<<<< HEAD
                    print(Token.created.timestamp())
                    if usr.number_try >= MAX_TRY and Token.created > timezone.now() - timedelta(seconds=MAX_TIME_TRY):
=======
                    tk = Token.objects.filter(user__username=username).first()
                    if tk and usr.number_try >= MAX_TRY and tk.last_use > timezone.now() - timedelta(seconds=MAX_TIME_TRY):
                        logger.critical("User {} try to login with incorrect password number try:{}".format(username, usr.number_try))
                        usr.number_try = 0
                        usr.save()
                    elif usr.number_try >= MAX_TRY:
>>>>>>> 83926d05a32fb7db6e7de85053dcff9655589c1b
                        logger.critical("User {} try to login with incorrect password number try:{}".format(username, usr.number_try))
                        usr.number_try = 0
                        usr.save()
                    else:
<<<<<<< HEAD
                        print("hey there")
=======
                        logger.info("User {} try to login with incorrect password.".format(username))
>>>>>>> 83926d05a32fb7db6e7de85053dcff9655589c1b
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
