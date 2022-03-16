#! /usr/bin/env python

from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Dict, Union, Any
import json

import auth
import aws
from http_server import client_assert, HttpError, ClientError, authenticate_from_header


_DOMAINS_PATH_PREFIX = "/link/"


def _get_target_ip(event) -> Union[IPv4Address, IPv6Address]:
    if event['headers'].get('content-type') == 'application/x-www-form-urlencoded':
        import urllib.parse
        if event['isBase64Encoded']:
            import base64
            params_str = base64.b64decode(event['body']).decode('utf-8')
        else:
            params_str = event['body']
        for k, v in urllib.parse.parse_qsl(params_str):
            if k == 'target_ip':
                target_ip_param = v
                break
        else:
            target_ip_param = None

    elif 'content-type' not in event['headers']:
        target_ip_param = event['queryStringParameters'].get('target_ip')
    else:
        raise ClientError(status=415, body={'message': "Content Type: expected 'application/x-www-form-urlencoded'"})

    client_assert(bool(target_ip_param), 400, "Missing parameter: target_ip")
    try:
        return ip_address(target_ip_param)
    except ValueError:
        raise ClientError(status=400, body={'message': "Bad parameter: target_ip"})



def run(event, context) -> Dict[Any, Any]:
    import json
    print('Event:', json.dumps(event))
    client_assert(event['requestContext']['http']['method'] == 'PUT', 405, 'Must PUT to update resources')

    user: auth.User = authenticate_from_header(event['headers'].get('authorization'), auth.DynamoAuthenticator())

    client_assert(event['requestContext']['http']['path'].startswith(_DOMAINS_PATH_PREFIX), 404, 'Bad Path: Expected /link/')
    target_site = event['requestContext']['http']['path'][len(_DOMAINS_PATH_PREFIX):]

    if target_site not in user.owned_sites:
        raise ClientError(403, {"message": "Authorization Error"})

    print(f"User '{user.username}' updating site '{target_site}'")

    target_ip = _get_target_ip(event)
    record_type = 'A' if target_ip.version == 4 else 'AAAA'

    r53 = aws.r53()
    dynamicip_zoneids = r53.list_hosted_zones_by_name(DNSName="dynamicip.link")
    dynamicip_zoneid = dynamicip_zoneids['HostedZones'][0]['Id']

    r53.change_resource_record_sets(
            HostedZoneId=dynamicip_zoneid,
            ChangeBatch={
                'Comment': 'Updated from api request',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': target_site,
                            'Type': record_type,
                            'TTL': 60,
                            'ResourceRecords': [
                                {
                                    'Value': target_ip.exploded,
                                }
                            ],
                        }
                    }
                ]
            }
        )

    response = {
            'statusCode': 200,
            'isBase64Encoded': False,
            'body': json.dumps({'status': 'ok', 'cname': target_site, 'ip': target_ip.exploded}),
            'headers': {'Content-Type': 'application/json'},
    }
    return response


def lambda_handler(event, context):

    try:
        return run(event, context)
    except HttpError as e:
        headers = {'Content-Type': 'application/json'}
        if e.headers is not None:
            headers.update(e.headers)
        return {
                "statusCode": e.status,
                "isBase64Encoded": False,
                "body": json.dumps(e.body),
                "headers": headers
        }

