import blessclient.awsmfautils as awsmfautils
import os
import datetime


def test_unset_token():
    os.environ['AWS_ACCESS_KEY_ID'] = 'foo'
    os.environ['AWS_SESSION_TOKEN'] = 'foo'
    os.environ['AWS_SECURITY_TOKEN'] = 'foo'
    awsmfautils.unset_token()
    assert 'AWS_ACCESS_KEY_ID' not in os.environ
    assert 'AWS_SECRET_ACCESS_KEY' not in os.environ
    assert 'AWS_SESSION_TOKEN' not in os.environ
    assert 'AWS_SECURITY_TOKEN' not in os.environ


def test_get_serial(mock):
    list_mfa_devices = {
        u'MFADevices': [{
            u'UserName': 'foobar',
            u'SerialNumber': 'arn:aws:iam::000000000000:mfa/foobar',
            u'EnableDate': datetime.datetime.utcnow()
        }],
        u'IsTruncated': False,
        'ResponseMetadata': {
            'RetryAttempts': 0,
            'HTTPStatusCode': 200,
            'RequestId': '85d05b5b-d2ca-11e6-96b6-8503a2da6360',
            'HTTPHeaders': {
                'x-amzn-requestid': '85d05b5b-d2ca-11e6-96b6-8503a2da6360',
                'date': 'Wed, 04 Jan 2017 22:09:54 GMT',
                'content-length': '528',
                'content-type': 'text/xml'}
        }
    }
    iam_client = mock.Mock()
    iam_client.list_mfa_devices.return_value = list_mfa_devices
    serial = awsmfautils.get_serial(iam_client, 'foobar')
    iam_client.list_mfa_devices.assert_called_once_with(UserName='foobar')
    assert serial == 'arn:aws:iam::000000000000:mfa/foobar'


def test_get_role_arn():
    norole = awsmfautils.get_role_arn(
        'arn:aws:iam::000000000000:user/foobar', None)
    assert norole == ''
    rolebar = awsmfautils.get_role_arn(
        'arn:aws:iam::000000000000:user/foobar', 'rolebar')
    assert rolebar == 'arn:aws:iam::000000000000:role/rolebar'
    rolebar_acct = awsmfautils.get_role_arn(
        'arn:aws:iam::000000000000:user/foobar', 'rolebar', '111111111111')
    assert rolebar_acct == 'arn:aws:iam::111111111111:role/rolebar'
