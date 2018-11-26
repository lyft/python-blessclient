from __future__ import absolute_import
import boto3
import json
import requests
from requests_aws_sign import AWSV4Sign


class HousekeeperLambda(object):

    def __init__(self, config, creds, region):
        self.credentials = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        ).get_credentials()
        self.region = region
        self.service = 'execute-api'
        self.url = config['url']

    def getPrivateIpFromPublic(self, ip):
        auth = AWSV4Sign(self.credentials, self.region, self.service)
        response = requests.get('{0}/1/get-private-ip-from-public?ip={1}'.format(self.url, ip), auth=auth)
        payload = json.loads(response.content.decode("utf-8"))
        return payload['private_ip']