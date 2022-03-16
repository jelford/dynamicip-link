import pytest

import auth
import hashlib
from unittest.mock import patch

import http_server


def _a_hash_for(user: str, salt: bytes, password: bytes) -> bytes:
    h = hashlib.blake2b()
    h.update(user.encode('utf-8'))
    h.update(salt)
    h.update(password)
    return h.digest()


def _auth_table_record(username, salt, sites, token_hash):
    return {
        'Item': {
            'username': {
                'S': username
            },
            'hash_algo': {
                'S': 'blake2b'
            },
            'salt': {
                'B': salt
            },
            'sites': {
                'SS': sites
            },
            'token_hash': {
                'B': token_hash
            }
        }
    }


@pytest.mark.parametrize("username, password, auth_table_record, expected",
                         [
                             (
                                     "test-user", b"test-pass",
                                     _auth_table_record("test-user", b"test-salt", ["site1.test.dynamicip.link"],
                                                        _a_hash_for("test-user", b"test-salt", b"test-pass")),
                                     http_server.AuthSuccess(auth.User("test-user", {"site1.test.dynamicip.link"})),
                             ),
                             (
                                     "test-user", b"test-wrong-pass",
                                     _auth_table_record("test-user", b"test-salt", [],
                                                        _a_hash_for("test-user", b"test-salt", b"test-pass")),
                                     http_server.AuthFailure(),
                             ),
                             (
                                     "test-user", b"test-pass",
                                     None,
                                     http_server.AuthFailure()
                             )
                         ])
def test_auth(username, password, auth_table_record, expected) -> None:
    with patch.object(auth.aws, "ddb") as dynamo:
        if auth_table_record is not None:
            dynamo.return_value.get_item.return_value = auth_table_record
        else:
            dynamo.return_value.exceptions.ResourceNotFoundException = Exception
            dynamo.return_value.get_item.side_effect = Exception("No results for this user")

        result = auth.DynamoAuthenticator().authenticate_user(username, password)

        assert result == expected
