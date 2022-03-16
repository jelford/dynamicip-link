import boto3
from functools import lru_cache


@lru_cache(maxsize=1)
def r53():
    return boto3.client('route53')


@lru_cache(maxsize=1)
def ddb():
    return boto3.client('dynamodb')
