import json
import jwt
from datetime import timedelta
from typing import Optional, Type, Union
from jwt import InvalidAlgorithmError, InvalidTokenError
from .exceptions import TokenBackendError

try:
    from jwt import PyJWKClient, PyJWKClientError
    JWK_CLIENT_AVAILABLE = True
except ImportError:
    JWK_CLIENT_AVAILABLE = False


class TokenBackend:
    def __init__(
        self,
        algorithm,
        signing_key=None,
        verifying_key='',
        audience=None,
        issuer=None,
        jwk_url: str = None,
        leeway: Union[float, int, timedelta] = None,
        json_encoder: Optional[Type[json.JSONEncoder]] = None,
    ):

        self.algorithm = algorithm
        self.signing_key = signing_key
        self.verifying_key = verifying_key
        self.audience = audience
        self.issuer = issuer

        if JWK_CLIENT_AVAILABLE:
            self.jwks_client = PyJWKClient(jwk_url) if jwk_url else None
        else:
            self.jwks_client = None

        self.leeway = leeway
        self.json_encoder = json_encoder

    def get_leeway(self) -> timedelta:
        if self.leeway is None:
            return timedelta(seconds=0)
        elif isinstance(self.leeway, (int, float)):
            return timedelta(seconds=self.leeway)
        elif isinstance(self.leeway, timedelta):
            return self.leeway
        else:
            raise TokenBackendError(f'Нераспознанный формат "{type(self.leeway)}", '
                                    f'"leeway" должен быть типом int, float или timedelta')

    def get_verifying_key(self, token):
        if self.algorithm.startswith('HS'):
            return self.signing_key
        if self.jwks_client:
            try:
                return self.jwks_client.get_signing_key_from_jwt(token).key
            except PyJWKClientError as ex:
                raise TokenBackendError('Неправильный токен или срок его действия истёк') from ex
        return self.verifying_key

    def encode(self, payload):
        """
        Возвращает закодированный токен
        """
        jwt_payload = payload.copy()
        if self.audience is not None:
            jwt_payload['aud'] = self.audience
        if self.issuer is not None:
            jwt_payload['iss'] = self.issuer
        token = jwt.encode(
            jwt_payload,
            self.signing_key,
            algorithm=self.algorithm,
            json_encoder=self.json_encoder,
        )
        if isinstance(token, bytes):
            return token.decode('utf-8')
        return token

    def decode(self, token, verify=True):
        """
        Выполняет проверку данного токена
        """
        try:
            return jwt.decode(
                token,
                self.get_verifying_key(token),
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.get_leeway(),
                options={
                    'verify_aud': self.audience is not None,
                    'verify_signature': verify,
                },
            )
        except InvalidAlgorithmError as ex:
            raise TokenBackendError('Неверный алгоритм') from ex
        except InvalidTokenError as ex:
            raise TokenBackendError('Неправильный токен или срок его действия истёк') from ex
