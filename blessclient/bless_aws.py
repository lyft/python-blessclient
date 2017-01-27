import boto3
import logging
from itertools import count, ifilter
from botocore.exceptions import DataNotFoundError
from lambda_invocation_exception import LambdaInvocationException
from random import randint
from time import sleep


def exponential_backoff_and_jitter_retry(cap, base, max_attempts):
    def retry(attempt):
        if attempt >= max_attempts:
            return None

        max_int = min(cap, base * 2 ** attempt)
        min_int = min(1, max_int)
        return randint(min_int, max_int)

    return retry


class BlessAWS(object):
    BOTO_WAIT_TIME_CAP = 10
    BOTO_WAIT_TIME_BASE = 2
    BOTO_MAX_RETRIES = 5

    def __init__(self):
        self.iam = None
        self.sts = None
        self.retry_policy = exponential_backoff_and_jitter_retry(
            cap=BlessAWS.BOTO_WAIT_TIME_CAP,
            base=BlessAWS.BOTO_WAIT_TIME_BASE,
            max_attempts=BlessAWS.BOTO_MAX_RETRIES
        )

    def iam_client(self):
        if not self.iam:
            for attempt in count():
                try:
                    self.iam = boto3.client('iam')
                    break
                except DataNotFoundError as e:
                    logging.exception('DataNotFoundError when trying to get the iam client.')
                    t = self.retry_policy(attempt)
                    if t is None:
                        logging.info('Not retrying')
                        raise LambdaInvocationException('Exhausted retries getting iam client')
                    logging.info('Retrying in {} seconds'.format(t))
                    sleep(t)
                    logging.info('Retrying now')
        return self.iam

    def sts_client(self):
        if not self.sts:
            self.sts = boto3.client('sts')
        return self.sts
