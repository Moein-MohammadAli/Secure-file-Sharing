from rest_framework.permissions import IsAuthenticated, BasePermission, SAFE_METHODS
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from core.models import TokenAuth
from datetime import timedelta
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class ExpireTokenAuthentication(TokenAuthentication):
    model = TokenAuth
    DEFAULT_TOKEN_EXPIRE = getattr(settings, "DEFAULT_TOKEN_EXPIRE")

    def authenticate_credentials(self, key):
        """
        In this function Inspired by authenticate_credentials of TokenAuthentication and
         added checking the expired token state.
        :param key:
        :return:
        """
        try:
            token = self.model.objects.select_related('user').get(key=key)
        except self.model.DoesNotExist:
            logger.critical("a user try to authenticate credential with incorrect token.")
            raise AuthenticationFailed(_('Invalid token.'))

        if not (timezone.now() - timedelta(seconds=self.DEFAULT_TOKEN_EXPIRE['PER_USE'])) < token.last_use or\
                not (timezone.now() - timedelta(seconds=self.DEFAULT_TOKEN_EXPIRE['TOTAL'])) < token.created:
            logger.critical("User {} try to authenticate credential with expired token".format(token.user.user))
            raise AuthenticationFailed(_('Expired token.'))

        if not token.user.is_active:
            raise AuthenticationFailed(_('User inactive or deleted.'))

        token.save()
        return token.user, token
