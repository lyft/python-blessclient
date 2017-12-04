from __future__ import unicode_literals

from io import StringIO
import pytest
from blessclient.bless_config import BlessConfig


TEST_CONFIG = """
[MAIN]
region_aliases: iad, SFO
kms_service_name: bless-production
bastion_ips: 10.0.0.0/8,192.168.192.1
remote_user: foo

[CLIENT]
domain_regex: (i-.*|.*\.example\.com|\A10\.0(?:\.[0-9]{1,3}){2}\Z)$
cache_dir: .aws-mfa/session
cache_file: bless_cache.json
mfa_cache_dir: .aws-mfa/session
mfa_cache_file: token_cache.json
ip_urls: http://checkip.amazonaws.com, http://api.ipify.org
update_script: autoupdate.sh
user_session_length: 3600

[LAMBDA]
user_role: use-bless
account_id: 111111111111
functionname: lyft_bless
functionversion: PROD-1-2
certlifetime: 120
ipcachelifetime: 60
timeout_connect: 5
timeout_read: 10

[REGION_SFO]
awsregion: us-west-2
kmsauthkey: abcdefgh-0123-4567-8910-abcdefghijkl

[REGION_IAD]
awsregion: us-east-1
kmsauthkey: zxywvuts-0123-4567-8910-abcdefghijkl
"""

@pytest.fixture
def bless_config_test():
    configIO = StringIO(TEST_CONFIG)
    config = BlessConfig()
    config.set_config(config.parse_config_file(configIO))
    return config


def test_set():
    config = BlessConfig()
    config.set_config({'foo': 'bar'})
    assert config.blessconfig['foo'] == 'bar'


def test_get():
    config = BlessConfig()
    config.blessconfig = {'foo': 'bar'}
    assert config.get('foo') == 'bar'


def test_get_invalid():
    config = BlessConfig()
    config.blessconfig = {'foo': 'bar'}
    with pytest.raises(ValueError):
        config.get('DOESNOTEXIST')


def test_get_config():
    config = BlessConfig()
    config.blessconfig = {'foo': 'bar'}
    assert config.get_config() == {'foo': 'bar'}


def test_load_config():
    config = BlessConfig()
    configIO = StringIO(TEST_CONFIG)
    conf = config.parse_config_file(configIO)
    assert conf == {
        'KMSAUTH_CONFIG_SFO': {
            'kmskey': 'abcdefgh-0123-4567-8910-abcdefghijkl',
            'awsregion': 'us-west-2',
            'context': {'to': 'bless-production', 'user_type': 'user'}
        },
        'KMSAUTH_CONFIG_IAD': {
            'kmskey': 'zxywvuts-0123-4567-8910-abcdefghijkl',
            'awsregion': 'us-east-1',
            'context': {'to': 'bless-production', 'user_type': 'user'}
        },
        'REGION_ALIAS': {'IAD': 'us-east-1', 'SFO': 'us-west-2'},
        'BLESS_CONFIG': {
            'ipcachelifetime': 60,
            'functionname': 'lyft_bless',
            'functionversion': 'PROD-1-2',
            'userrole': 'use-bless',
            'timeoutconfig': {'read': 10, 'connect': 5},
            'certlifetime': 120,
            'accountid': '111111111111'
        },
        'AWS_CONFIG': {
            'bastion_ips': '10.0.0.0/8,192.168.192.1',
            'remote_user': 'foo'
        },
        'CLIENT_CONFIG': {
            'domain_regex': '(i-.*|.*\\.example\\.com|\\A10\\.0(?:\\.[0-9]{1,3}){2}\\Z)$',
            'cache_file': 'bless_cache.json',
            'mfa_cache_dir': '.aws-mfa/session',
            'cache_dir': '.aws-mfa/session',
            'mfa_cache_file': 'token_cache.json',
            'ip_urls': ['http://checkip.amazonaws.com', 'http://api.ipify.org'],
            'update_script': 'autoupdate.sh',
            'user_session_length': 3600,
            'usebless_role_session_length': 3600, # comes from BlessConfig.DEFAULT_CONFIG
        }
    }


def test_get_region_alias_from_aws_region(bless_config_test):
    assert bless_config_test.get_region_alias_from_aws_region('us-east-1') == 'IAD'
    with pytest.raises(ValueError):
        bless_config_test.get_region_alias_from_aws_region('foo-1')


def test_get_configs(bless_config_test):
    client_config = bless_config_test.get_client_config()
    assert 'domain_regex' in client_config
    lambda_config = bless_config_test.get_lambda_config()
    assert 'functionname' in lambda_config
    aws_config = bless_config_test.get_aws_config()
    assert 'bastion_ips' in aws_config
    assert 'remote_user' in aws_config


def test_set_lambda_config(bless_config_test):
    bless_config_test.set_lambda_config('ipcachelifetime', 1)
    lambda_config = bless_config_test.get_lambda_config()
    assert lambda_config['ipcachelifetime'] == 1
    assert bless_config_test.set_lambda_config('DOESNOTEXIST', 9000) == False

def test_set_client_config(bless_config_test):
    bless_config_test.set_client_config('update_script', 'foo.sh')
    client_config = bless_config_test.get_client_config()
    assert client_config['update_script'] == 'foo.sh'
    assert bless_config_test.set_client_config('DOESNOTEXIST', 9000) == False
