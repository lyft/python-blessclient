from __future__ import absolute_import
import boto3
import json
from .lambda_invocation_exception import LambdaInvocationException
from botocore.client import Config
from botocore.vendored.requests.exceptions import (ReadTimeout,
                                                   ConnectTimeout,
                                                   SSLError)


class BlessLambda(object):

    def __init__(self, config, creds, kmsauth_token, region):
        self.config = config
        self.kmsauth_token = kmsauth_token
        self.creds = creds
        self.region = region

    def getCert(self, payload):
        payload['kmsauth_token'] = self.kmsauth_token
        payload_json = json.dumps(payload)
        lambdabotoconfig = Config(
            connect_timeout=self.config['timeoutconfig']['connect'],
            read_timeout=self.config['timeoutconfig']['read']
        )
        try:
            mfa_lambda_client = boto3.client(
                'lambda',
                region_name=self.region,
                aws_access_key_id=self.creds['AccessKeyId'],
                aws_secret_access_key=self.creds['SecretAccessKey'],
                aws_session_token=self.creds['SessionToken'],
                config=lambdabotoconfig
            )
            response = mfa_lambda_client.invoke(
                FunctionName=self.config['functionname'],
                InvocationType='RequestResponse',
                LogType='Tail',
                Payload=payload_json,
                Qualifier=self.config['functionversion']
            )
            if response['StatusCode'] != 200:
                raise LambdaInvocationException('Error creating cert.')
        except ConnectTimeout:
            raise LambdaInvocationException('Timeout connecting to Lambda')
        except ReadTimeout:
            raise LambdaInvocationException('Timeout reading cert from Lambda')
        except SSLError:
            raise LambdaInvocationException('SSL error connecting to Lambda')
        except ValueError:
            # On a 404, boto tries to decode any body as json
            raise LambdaInvocationException('Invalid message format in Lambda response')
        payload = json.loads(response['Payload'].read())
        if 'certificate' not in payload:
            raise LambdaInvocationException('No certificate in response.')
        return payload['certificate']
