from django.contrib.auth import get_user_model
from rest_framework import HTTP_HEADER_ENCODING, authentication
from .exceptions import AuthenticationFailed, InvalidToken, TokenError
from .settings import api_settings

AUTH_HEADER_TYPES = api_settings.AUTH_HEADER_TYPES

if not isinstance(api_settings.AUTH_HEADER_TYPES, (list, tuple)):
    AUTH_HEADER_TYPES = (AUTH_HEADER_TYPES,)

AUTH_HEADER_TYPE_BYTES = {h.encode(HTTP_HEADER_ENCODING) for h in AUTH_HEADER_TYPES}


class JWTAuthentication(authentication.BaseAuthentication):
    """
    Позволяет аутентифицировать пользователя через JWT указанный в header
    """
    www_authenticate_realm = 'api'
    media_type = 'application/json'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_model = get_user_model()

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None
        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token

    def authenticate_header(self, request):
        return f'{AUTH_HEADER_TYPES[0]} realm="{self.www_authenticate_realm}"'

    def get_header(self, request):
        """
        Извлекает header из запроса
        """
        header = request.META.get(api_settings.AUTH_HEADER_NAME)
        if isinstance(header, str):
            header = header.encode(HTTP_HEADER_ENCODING)
        return header

    def get_raw_token(self, header):
        """
        Извлекает непроверенный JWT из поля Authorization в header.
        """
        parts = header.split()
        if len(parts) == 0:
            # если пустое поле Authorization в header
            return None
        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
            # если header не содержит JWT
            return None
        if len(parts) != 2:
            raise AuthenticationFailed(
                'Поле Authorization в header должно содержать два значения разделенных пробелом',
                code='bad_authorization_header',
            )
        return parts[1]

    def get_validated_token(self, raw_token):
        """
        Проверяет закодированный JWT и возвращает проверенный токен
        """
        messages = []
        for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
            try:
                return AuthToken(raw_token)
            except TokenError as err:
                messages.append(
                    {
                        'token_class': AuthToken.__name__,
                        'token_type': AuthToken.token_type,
                        'message': err.args[0],
                    }
                )

        raise InvalidToken(
            {
                'detail': 'Данный токен недействителен',
                'messages': messages,
            }
        )

    def get_user(self, validated_token):
        """
        Метод пытается вернуть пользователя используя проверенный токен
        """
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError:
            raise InvalidToken('В токене не содержится идентификатора пользователя '
                               'который можно было бы распознать')
        try:
            user = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id})
        except self.user_model.DoesNotExist:
            raise AuthenticationFailed('Пользователь не найден', code='user_not_found')
        if not user.is_active:
            raise AuthenticationFailed('Пользователь неактивен', code='user_inactive')
        return user


def default_user_authentication_rule(user):
    """
    Использование данного метода не позволяет приложению упасть в ошибку
    при неправильном вводе пользователя
    """
    return user is not None and user.is_active
