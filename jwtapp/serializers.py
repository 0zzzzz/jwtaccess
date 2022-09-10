from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import update_last_login
from rest_framework import exceptions, serializers
from .settings import api_settings
from .tokens import RefreshToken


class PasswordField(serializers.CharField):
    """
    Поле пароля
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('style', {})
        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True
        super().__init__(*args, **kwargs)


class TokenObtainSerializer(serializers.Serializer):
    """
    Валидация пользователя
    """
    username_field = get_user_model().USERNAME_FIELD
    token_class = None
    default_error_messages = {
        'no_active_account': 'Имя или пароль введены неправильно'
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields[self.username_field] = serializers.CharField()
        self.fields['password'] = PasswordField()

    def validate(self, attrs):
        authenticate_kwargs = {
            self.username_field: attrs[self.username_field],
            'password': attrs['password'],
        }
        try:
            authenticate_kwargs['request'] = self.context['request']
        except KeyError:
            pass
        self.user = authenticate(**authenticate_kwargs)
        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )
        return {}

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)


class TokenObtainPairSerializer(TokenObtainSerializer):
    """
    Получения access и refresh токенов
    """
    token_class = RefreshToken

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)
        return data


class TokenRefreshSerializer(serializers.Serializer):
    """
    Обновление access токена с помощью refresh токена
    """
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)
    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs['refresh'])
        data = {'access': str(refresh.access_token)}
        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    refresh.blacklist()
                except AttributeError:
                    pass
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()
            data['refresh'] = str(refresh)
        return data


class TokenBlacklistSerializer(serializers.Serializer):
    """
    Добавление токена в чёрный список
    """
    refresh = serializers.CharField()
    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs['refresh'])
        try:
            refresh.blacklist()
        except AttributeError:
            pass
        return {}


class RotatedRefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)
    token_class = RefreshToken

    def validate(self, attrs):
        refresh = self.token_class(attrs['refresh'])
        try:
            refresh.blacklist()
        except AttributeError:
            pass
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        if api_settings.ROTATE_REFRESH_TOKENS:
            if api_settings.BLACKLIST_AFTER_ROTATION:
                try:
                    refresh.blacklist()
                except AttributeError:
                    pass
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()
            data['refresh'] = str(refresh)
        return data

