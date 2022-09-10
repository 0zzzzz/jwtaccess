from datetime import timedelta
from uuid import uuid4
from django.conf import settings
from django.utils.module_loading import import_string
from .exceptions import TokenBackendError, TokenError
from .settings import api_settings
from .tokens_models.models import BlacklistedToken, OutstandingToken
from .utils import aware_utcnow, datetime_from_epoch, datetime_to_epoch
import bcrypt

salt = bcrypt.gensalt()


class Token:
    """
    Проверяет и обертывает существующий JWT или может использоваться для создания нового JWT
    """

    token_type = None
    lifetime = None

    def __init__(self, token=None, verify=True):
        if self.token_type is None or self.lifetime is None:
            raise TokenError('Невозможно создать токен без типа или срока действия')

        self.token = token
        self.current_time = aware_utcnow()

        if token is not None:
            # Был предоставлен зашифрованный токен
            token_backend = self.get_token_backend()

            # Раскодирование токена
            try:
                self.payload = token_backend.decode(token, verify=verify)
            except TokenBackendError:
                raise TokenError('Неверный токен или срок его действия истёк')

            if verify:
                self.verify()
        else:
            # Новый токен, пропускаем все шаги верификации
            self.payload = {api_settings.TOKEN_TYPE_CLAIM: self.token_type}

            # Задаём 'exp' и 'iat' значения по умолчанию
            self.set_exp(from_time=self.current_time, lifetime=self.lifetime)
            self.set_iat(at_time=self.current_time)

            # Задаём значение для 'jti'
            self.set_jti()

    def __repr__(self):
        return repr(self.payload)

    def __getitem__(self, key):
        return self.payload[key]

    def __setitem__(self, key, value):
        self.payload[key] = value

    def __delitem__(self, key):
        del self.payload[key]

    def __contains__(self, key):
        return key in self.payload

    def get(self, key, default=None):
        return self.payload.get(key, default)

    def __str__(self):
        """
        Возвращает токен в виде строки в кодировке base64
        """
        return self.get_token_backend().encode(self.payload)

    def verify(self):
        """
        Выполняет дополнительные шаги проверки, которые не выполнялись при расшифровке токена
        Метод работает при вызове refresh
        """
        if (
            api_settings.JTI_CLAIM is not None
            and api_settings.JTI_CLAIM not in self.payload
        ):
            raise TokenError('Token has no id')

        if api_settings.TOKEN_TYPE_CLAIM is not None:
            self.verify_token_type()

    def verify_token_type(self):
        """
        Выполняет проверку типа токена
        """
        try:
            token_type = self.payload[api_settings.TOKEN_TYPE_CLAIM]
        except KeyError:
            raise TokenError('У токена не задан тип')

        if self.token_type != token_type:
            raise TokenError('У токена задан неправильный тип')

    def set_jti(self):
        """
        Задаёт значение JTI(JWT id), которое с пренебрежимо малой вероятность продублируется
        """
        self.payload[api_settings.JTI_CLAIM] = uuid4().hex

    def set_exp(self, claim='exp', from_time=None, lifetime=None):
        """
        Задаёт срок действия токена
        """
        if from_time is None:
            from_time = self.current_time

        if lifetime is None:
            lifetime = self.lifetime

        self.payload[claim] = datetime_to_epoch(from_time + lifetime)

    def set_iat(self, claim='iat', at_time=None):
        """
        Задаёт время выдачи токена.
        """
        if at_time is None:
            at_time = self.current_time

        self.payload[claim] = datetime_to_epoch(at_time)

    def check_exp(self, claim='exp', current_time=None):
        """
        Проверяет, не истёк ли токен. Вызывает ошибку TokenError если срок его действия истёк
        """
        if current_time is None:
            current_time = self.current_time

        try:
            claim_value = self.payload[claim]
        except KeyError:
            raise TokenError(f'У токена нет "{claim}"')

        claim_time = datetime_from_epoch(claim_value)
        leeway = self.get_token_backend().get_leeway()
        if claim_time <= current_time - leeway:
            raise TokenError(f'Token "{claim}" claim has expired')

    @classmethod
    def for_user(cls, user):
        """
        Возвращает токен авторизации для введённого пользователя
        Для /api/token/
        """
        user_id = getattr(user, api_settings.USER_ID_FIELD)
        if not isinstance(user_id, int):
            user_id = str(user_id)

        token = cls()
        token[api_settings.USER_ID_CLAIM] = user_id

        return token

    _token_backend = None

    @property
    def token_backend(self):
        if self._token_backend is None:
            self._token_backend = import_string(
                'jwtapp.state.token_backend'
            )
        return self._token_backend

    def get_token_backend(self):
        return self.token_backend


class BlacklistMixin:
    """
    Черный список токенов
    """

    if 'jwtapp.tokens_models' in settings.INSTALLED_APPS:

        def verify(self, *args, **kwargs):
            self.check_blacklist()

            super().verify(*args, **kwargs)

        def check_blacklist(self):
            """
            Проверяет присутствие токена в черном списке, если токен там, то вызывает 'TokenError'.
            """
            jti = self.payload[api_settings.JTI_CLAIM]

            if BlacklistedToken.objects.filter(token__jti=jti).exists():
                raise TokenError('Токен в чёрном списке')

        def blacklist(self):
            """
            Убеждается, что данный токен в списке незавершенных токенов (outstanding token list) и
            добавляет его в черный список.
            """
            jti = self.payload[api_settings.JTI_CLAIM]
            exp = self.payload['exp']
            token, _ = OutstandingToken.objects.get_or_create(
                jti=jti,
                defaults={
                    'token': str(self),
                    'expires_at': datetime_from_epoch(exp),
                },
            )
            return BlacklistedToken.objects.get_or_create(token=token)

        @classmethod
        def for_user(cls, user):
            """
            Добавляет данный токен в список незавершенных
            """
            token = super().for_user(user)

            jti = token[api_settings.JTI_CLAIM]
            exp = token['exp']

            OutstandingToken.objects.create(
                user=user,
                jti=jti,
                token=bcrypt.hashpw(str(token).encode(), salt),
                created_at=token.current_time,
                expires_at=datetime_from_epoch(exp),
            )

            return token


class AccessToken(Token):
    token_type = 'access'
    lifetime = api_settings.ACCESS_TOKEN_LIFETIME


class RefreshToken(BlacklistMixin, Token):
    token_type = 'refresh'
    lifetime = api_settings.REFRESH_TOKEN_LIFETIME
    no_copy_claims = (
        api_settings.TOKEN_TYPE_CLAIM,
        'exp',
        api_settings.JTI_CLAIM,
        'jti',
    )
    access_token_class = AccessToken

    @property
    def access_token(self):
        """
        Возвращает access токен, созданный из refresh токена
        """
        access = self.access_token_class()
        access.set_exp(from_time=self.current_time)
        no_copy = self.no_copy_claims
        for claim, value in self.payload.items():
            if claim in no_copy:
                continue
            access[claim] = value

        return access


class UntypedToken(Token):
    token_type = 'untyped'
    lifetime = timedelta(seconds=0)

    def verify_token_type(self):
        """
        Токены без типа не проверяются на token_type
        """
        pass
