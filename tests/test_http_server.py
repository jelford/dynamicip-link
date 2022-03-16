import http_server
import pytest
import base64


@pytest.fixture
def user_database():
    class UserDatabase:
        def authenticate_user(self, usr, pw) -> http_server.AuthSuccess[str]:
            return {
                ('user', b'pass'): http_server.AuthSuccess('ok')
            }.get((usr, pw), http_server.AuthFailure)

    return UserDatabase()


def _as_auth_header(user, pwd):
    # base64 wants to work with binary, but we get the auth header in string form
    creds = base64.b64encode(f"{user}:{pwd}".encode('utf-8')).decode('utf-8')
    return f'Basic {creds}'


def test_auth_from_header_when_correct_creds_returns_user(user_database):
    result = http_server.authenticate_from_header(_as_auth_header('user', 'pass'), user_database)
    assert result == 'ok'


# noinspection PyTypeChecker
def test_auth_from_header_when_no_creds_throws_error(user_database):
    with pytest.raises(http_server.ClientError):
        http_server.authenticate_from_header(None, None)
    with pytest.raises(http_server.ClientError):
        http_server.authenticate_from_header("not basic auth", None)


def test_auth_from_header_when_wrong_creds_throws_error(user_database):
    with pytest.raises(http_server.ClientError):
        http_server.authenticate_from_header(_as_auth_header('bad user', 'bad pass'), user_database)