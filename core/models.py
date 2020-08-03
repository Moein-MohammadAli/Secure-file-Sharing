from django.db import models
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

# Create your models here.


class Account(User):
    CONF_LABEL = (
        (1, "TopSecret"),
        (2, "Secret"),
        (3, "Confidential"),
        (4, "Unclassified")
    )
    INTEGRITY_LABEL = (
        (1, "VeryTrusted"),
        (2, "Trusted"),
        (3, "SlightlyTrusted"),
        (4, "Untrusted")
    )
    confidentiality_label = models.IntegerField(blank=False, choices=CONF_LABEL)
    integrity_label = models.IntegerField(blank=False, choices=INTEGRITY_LABEL)


class TokenAuth(Token):
    """
    Extend last_use parameter for checking expire token.
    """
    last_use = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.key

class File(models.Model):
    CONF_LABEL = (
        (1, "TopSecret"),
        (2, "Secret"),
        (3, "Confidential"),
        (4, "Unclassified")
    )
    INTEGRITY_LABEL = (
        (1, "VeryTrusted"),
        (2, "Trusted"),
        (3, "SlightlyTrusted"),
        (4, "Untrusted")
    )
    file_name_hashed = models.CharField(max_length=32, blank=False, unique=True)
    file_name = models.CharField(max_length=32, blank=False, unique=True)
    owner = models.ForeignKey(Account, on_delete=models.CASCADE)
    confidentiality_label = models.IntegerField(blank=False, choices=CONF_LABEL)
    integrity_label = models.IntegerField(blank=False, choices=INTEGRITY_LABEL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class AccessControl(models.Model):
    ACCESS_TYPE = (
        (0, "None"),
        (1, "Read"),
        (2, "Write"),
        (3, "Read/Write"),
        (4, "Get")
    )
    subject = models.ForeignKey(Account, on_delete=models.CASCADE)
    obj = models.ForeignKey(File, on_delete=models.CASCADE)
    access = models.IntegerField(blank=False, choices=ACCESS_TYPE, default=0)

    class Meta:
        unique_together = ['subject', 'obj']