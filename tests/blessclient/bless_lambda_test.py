import pytest
from blessclient.bless_lambda import BlessLambda
from botocore.vendored.requests.exceptions import (ReadTimeout,
                                                   ConnectTimeout,
                                                   SSLError)
from blessclient.lambda_invocation_exception import LambdaInvocationException


TESTBLESSCONFIG = {
    'userrole': 'rolebar',
    'accountid': '111111111111',
    'functionname': 'lyft_bless',
    'functionversion': 'PROD-1-2',
    'certlifetime': 1800,
    'ipcachelifetime': 120,
    'timeoutconfig': {'connect': 5, 'read': 10}
}


@pytest.fixture(scope="module")
def lyftbless():
    return BlessLambda(
        config=TESTBLESSCONFIG,
        creds={
            'AccessKeyId': None,
            'SecretAccessKey': None,
            'SessionToken': None},
        kmsauth_token='my_kmsauth_token',
        region='us-east-1'
    )


def test_getCert(mocker, lyftbless):
    payloadmock = mocker.MagicMock()
    payloadmock.read.return_value = '{"certificate": "The Cert"}'
    clientmock = mocker.MagicMock()
    clientmock.invoke.return_value = {
        'StatusCode': 200,
        'Payload': payloadmock
    }
    botomock = mocker.patch('boto3.client')
    botomock.return_value = clientmock
    returned = lyftbless.getCert({'foo': 'bar'})
    assert returned == 'The Cert'


def test_getCert_ConnectTimeout(mocker, lyftbless):
    botomock = mocker.patch('boto3.client')
    botomock.side_effect = ConnectTimeout()
    with pytest.raises(LambdaInvocationException):
        lyftbless.getCert({'foo': 'bar'})
    botomock.assert_called_once()


def test_getCert_ReadTimeout(mocker, lyftbless):
    botomock = mocker.patch('boto3.client')
    botomock.side_effect = ReadTimeout()
    with pytest.raises(LambdaInvocationException):
        lyftbless.getCert({'foo': 'bar'})
    botomock.assert_called_once()


def test_getCert_SSLError(mocker, lyftbless):
    botomock = mocker.patch('boto3.client')
    botomock.side_effect = SSLError()
    with pytest.raises(LambdaInvocationException):
        lyftbless.getCert({'foo': 'bar'})
    botomock.assert_called_once()
