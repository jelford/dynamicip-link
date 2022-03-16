import base64
from typing import Dict, Union, Protocol, TypeVar, Generic, cast
from dataclasses import dataclass

WWW_AUTH_HEADER = {'WWW-Authenticate': 'Basic realm="dynamicip-link"'}


class HttpError(Exception):
    def __init__(self, status, body, headers=None):
        assert status >= 100
        self.status = status
        self.body = body
        self.headers = headers or {}


class ClientError(HttpError):
    def __init__(self, status, body, headers=None):
        assert status in range(400, 500)
        super().__init__(status, body, headers or {})


def client_assert(condition: bool, status: int, error_msg: str, headers: Dict[str, str] = None) -> None:
    if not condition:
        raise ClientError(status, {'message': error_msg}, headers)


@dataclass
class AuthFailure:
    success: bool = False


U = TypeVar('U')


@dataclass
class AuthSuccess(Generic[U]):
    user: U
    success: bool = True


class Authenticator(Protocol[U]):
    def authenticate_user(self, username: str, authorization_token: bytes) -> Union[AuthSuccess[U], AuthFailure]:
        pass


def authenticate_from_header(auth_header, authenticator: Authenticator[U]) -> U:
    client_assert(auth_header is not None, 401, "Auth Failed: Missing Header", headers=WWW_AUTH_HEADER)
    scheme, *credentials = auth_header.split(' ', 1)
    client_assert(scheme.upper() == 'BASIC', 401, "Auth Failed: Unsupported Scheme", headers=WWW_AUTH_HEADER)
    client_assert(bool(credentials), 401, "Auth Failed: Missing Credentials", headers=WWW_AUTH_HEADER)

    try:
        bin_creds = base64.b64decode(''.join(credentials).encode('utf-8'))
        bin_usr, pw = bin_creds.split(b':')
        usr = bin_usr.decode('utf-8')
    except ValueError:
        raise ClientError(401, {'message': "Auth Failed: Malformed Credentials"}, headers=WWW_AUTH_HEADER)

    auth_result = authenticator.authenticate_user(usr, pw)
    if auth_result.success:
        result = cast(AuthSuccess[U], auth_result)
        return result.user
    else:

        raise ClientError(401, {'message': "Auth Failed: Bad Credentials"})
