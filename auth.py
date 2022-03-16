import base64
import hashlib
from dataclasses import dataclass
from typing import Union, Set
import random

import aws
from http_server import AuthSuccess, AuthFailure

@dataclass
class User:
    username: str
    owned_sites: Set[str]


def _are_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b): return False
    order = [i for i in range(len(a))]
    random.shuffle(order)
    result = True
    for i in order:
        if a[i] != b[i]:
            result = False
    return result


class DynamoAuthenticator:
    def authenticate_user(self, user: str, token: bytes) -> Union[AuthFailure, AuthSuccess[User]]:
        ddb = aws.ddb()
        try:
            usr = ddb.get_item(
                TableName='dynamicip-link.auth',
                Key={
                    'username': {
                        'S': user,
                    }
                },
                AttributesToGet=[
                    'salt', 'sites', 'hash_algo', 'token_hash'
                ],
                ConsistentRead=False,
            )
        except ddb.exceptions.ResourceNotFoundException:
            return AuthFailure()

        record = usr['Item']

        salt = record['salt']['B']
        hasher = {
            'blake2b': hashlib.blake2b,
        }[record['hash_algo']['S']]()

        hasher.update(user.encode('utf-8'))
        hasher.update(salt)
        hasher.update(token)
        digest = hasher.digest()
        target_digest = record['token_hash']['B']

        if _are_equal(digest, target_digest):
            return AuthSuccess(user=User(username=user, owned_sites=set(record['sites']['SS'])))
        else:
            return AuthFailure()
