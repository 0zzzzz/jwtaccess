from django.conf import settings
from django.db import models


class OutstandingToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    jti = models.CharField(unique=True, max_length=255)
    token = models.TextField()
    created_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        abstract = 'jwtapp.tokens_models' not in settings.INSTALLED_APPS
        ordering = ('user',)

    def __str__(self):
        return f'Токен пользователя: {self.user} ({self.jti})'


class BlacklistedToken(models.Model):
    id = models.BigAutoField(primary_key=True, serialize=False)
    token = models.OneToOneField(OutstandingToken, on_delete=models.CASCADE)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = 'jwtapp.tokens_models' not in settings.INSTALLED_APPS

    def __str__(self):
        return f'Токен из черного списка пользователя: {self.token.user}'
