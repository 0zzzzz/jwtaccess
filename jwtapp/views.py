from django.utils.module_loading import import_string
from rest_framework import generics, status
from rest_framework.response import Response
from .exceptions import InvalidToken, TokenError
from .serializers import RotatedRefreshTokenSerializer
from .settings import api_settings
from .authentication import AUTH_HEADER_TYPES


class TokenViewBase(generics.GenericAPIView):
    """
    Базовый класс для токенов
    """
    permission_classes = ()
    authentication_classes = ()
    serializer_class = None
    _serializer_class = ""
    www_authenticate_realm = "api"

    def get_serializer_class(self):
        """
        Если serializer_class определён в классе, то используем его, иначе получаем значение из настроек
        """
        if self.serializer_class:
            return self.serializer_class
        try:
            return import_string(self._serializer_class)
        except ImportError:
            msg = f'Невозможно импортировать сериализатор {self._serializer_class}'
            raise ImportError(msg)

    def get_authenticate_header(self, request):
        return f'{AUTH_HEADER_TYPES[0]} realm="{self.www_authenticate_realm}"'

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as err:
            raise InvalidToken(err.args[0])
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TokenObtainPairView(TokenViewBase):
    """
    Принимает имя пользователя и пароль, возвращает пару Access и Refresh токенов
    """
    _serializer_class = api_settings.TOKEN_OBTAIN_SERIALIZER


class TokenRefreshView(TokenViewBase):
    """
    Принимает Refresh токен, возвращает Access токен
    """
    _serializer_class = api_settings.TOKEN_REFRESH_SERIALIZER


class TokenBlacklistView(TokenViewBase):
    """
    Добавляет токен в чёрный список
    """
    _serializer_class = api_settings.TOKEN_BLACKLIST_SERIALIZER


class RotatedRefreshTokenView(TokenViewBase):
    """
    Обновляет пару Access и Refresh токенов
    """
    serializer_class = RotatedRefreshTokenSerializer
