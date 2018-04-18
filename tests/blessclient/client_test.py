import blessclient.client as client
import pytest
from blessclient.bless_cache import BlessCache
from blessclient.bless_config import BlessConfig
import datetime
import time
import logging
import os


@pytest.fixture
def bless_config():
    bc = BlessConfig()
    bc.set_config({
        'REGION_ALIAS': {'IAD': 'us-east-1', 'SFO': 'us-west-2'},
        'BLESS_CONFIG': {
            'ipcachelifetime': 300,
            'functionname': 'lyft_bless',
            'functionversion': 'PROD-1-2',
            'userrole': 'role_bar',
            'timeoutconfig': {'read': 10, 'connect': 5},
            'certlifetime': 1800,
            'accountid': '111111111111'
        },
        'CLIENT_CONFIG': {
            'ip_urls': 'http://api.ipify.org, http://canihazip.com',
            'domain_regex': '(i-.*|.*\\.example\\.com|\\A10\\.0(?:\\.[0-9]{1,3}){2}\\Z)$',
            'cache_dir': '.aws-mfa/session',
            'cache_file': 'bless_cache.json',
            'mfa_cache_dir': '.aws-mfa/session',
            'mfa_cache_file': 'token_cache.json',
            'update_script': 'autoupdate.sh',
        },
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
        'VAULT_CONFIG': {
            'vault_addr': 'https://vault.example.com:1234',
            'auth_mount': 'okta',
            'ssh_backend_mount': 'ssh-client-signer',
            'ssh_backend_role': 'bless'
        }
    })
    return bc

def test_get_bless_cache_enabled(bless_config):
    bc = client.get_bless_cache(False, bless_config)
    assert type(bc).__name__ == 'BlessCache'
    assert bc.mode == client.BlessCache.CACHEMODE_ENABLED


def test_get_bless_cache_recache(bless_config):
    bc = client.get_bless_cache(True, bless_config)
    assert type(bc).__name__ == 'BlessCache'
    assert bc.mode == client.BlessCache.CACHEMODE_RECACHE


def test_get_region_from_code(bless_config):
    assert client.get_region_from_code('sfo', bless_config) == 'us-west-2'
    assert client.get_region_from_code('iad', bless_config) == 'us-east-1'


def test_get_region_from_code(bless_config):
    with pytest.raises(ValueError):
        client.get_region_from_code('foobar', bless_config)


def test_get_regions(bless_config):
    assert client.get_regions('us-west-2', bless_config) == ['us-west-2', 'us-east-1']
    assert client.get_regions('us-east-1', bless_config) == ['us-east-1', 'us-west-2']
    assert client.get_regions('FOOBAR', bless_config) == ['us-east-1', 'us-west-2']


def test_get_kmsauth_config(bless_config):
    con = client.get_kmsauth_config('us-west-2', bless_config)
    assert con['awsregion'] == 'us-west-2'


def test_clear_kmsauth_token_cache(null_bless_cache):
    kmsconfig = {'awsregion': 'us-east-1'}
    client.clear_kmsauth_token_cache(kmsconfig, null_bless_cache)
    assert null_bless_cache.cache[
        'kmsauth-us-east-1']['Expiration'] == '20160101T000000Z'


def test_get_kmsauth_token(mocker, null_bless_cache):
    tokenmock = mocker.MagicMock()
    tokenmock.get_token.return_value = b'KMSTOKEN'
    genermock = mocker.patch('kmsauth.KMSTokenGenerator')
    genermock.return_value = tokenmock
    kmsconfig = {'awsregion': 'us-east-1', 'context': {}, 'kmskey': None}
    token = client.get_kmsauth_token(
        None, kmsconfig, 'foouser', null_bless_cache)
    assert token == 'KMSTOKEN'


def test_get_kmsauth_token_cached():
    kmsconfig = {'awsregion': 'us-east-1', 'context': {}, 'kmskey': None}
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
    kmsauth_cache = {
        'token': 'KMSTOKEN',
        'Expiration': expiration.strftime('%Y%m%dT%H%M%SZ')
    }
    bless_cache = BlessCache(None, None, BlessCache.CACHEMODE_ENABLED)
    bless_cache.cache = {}
    bless_cache.set('kmsauth-us-east-1', kmsauth_cache)
    token = client.get_kmsauth_token(None, kmsconfig, 'foouser', bless_cache)
    assert token == 'KMSTOKEN'


def test_setup_logging(mocker):
    logmock = mocker.patch('logging.basicConfig')
    os.environ['BLESSDEBUG'] = '1'
    client.setup_logging()
    logmock.assert_called_with(level=logging.DEBUG)
    os.environ['BLESSDEBUG'] = '/log/file'
    client.setup_logging()
    logmock.assert_called_with(filename='/log/file', level=logging.DEBUG)
    os.environ['BLESSDEBUG'] = ''
    client.setup_logging()
    logmock.assert_called_with(level=logging.CRITICAL)


def test_make_cachable_creds():
    creds = {
        'Expiration': datetime.datetime.strptime('Jan 1 2017', '%b %d %Y'),
        'token': 'foo'
    }
    returned = client.make_cachable_creds(creds)
    assert creds['token'] == returned['token']
    assert returned['Expiration'] == '20170101T000000Z'


def test_uncache_creds():
    creds = {
        'Expiration': '19790101T000000Z',
        'token': 'foo'
    }
    returned = client.uncache_creds(creds)
    assert creds['token'] == returned['token']
    assert returned['Expiration'] < time.gmtime()


def test_ssh_agent_remove_bless(mocker):
    outputmock = mocker.patch('subprocess.check_output')
    outputmock.return_value = b'4096 SHA256:hwnh3ccCcxVUo6T6htWvHdkCx/UsNklwy2uQuiBaTLQ /Users/foobar/.ssh/blessid (RSA-CERT)'
    callmock = mocker.patch('subprocess.check_call')
    client.ssh_agent_remove_bless('blessid')
    outputmock.assert_called_once()
    callmock.assert_called_once()


def test_ssh_agent_add_bless(mocker):
    outputmock = mocker.patch('subprocess.check_output')
    outputmock.return_value = b'4096 SHA256:hwnh3ccCcxVUo6T6htWvHdkCx/UsNklwy2uQuiBaTLQ /Users/foobar/.ssh/blessid (RSA-CERT)'
    callmock = mocker.patch('subprocess.check_call')
    client.ssh_agent_add_bless('.ssh/blessid')
    outputmock.assert_called_once()
    callmock.assert_called_once()


def test_ssh_agent_add_bless_failed(mocker):
    outputmock = mocker.patch('subprocess.check_output')
    outputmock.return_value = b''
    callmock = mocker.patch('subprocess.check_call')
    logmock = mocker.patch('logging.debug')
    writemock = mocker.patch('sys.stderr.write')
    client.ssh_agent_add_bless('.ssh/blessid')
    outputmock.assert_called_once()
    callmock.assert_called_once()
    logmock.assert_called_once()
    writemock.assert_called_once()


def test_get_stderr_feedback():
    os.environ['BLESSQUIET'] = ''
    assert client.get_stderr_feedback() == True
    os.environ['BLESSQUIET'] = '1'
    assert client.get_stderr_feedback() == False


def test_check_fresh_cert(mocker, null_bless_cache):
    blessconfig = {
        'certlifetime': 600,
        'ipcachelifetime': 300
    }
    isfilemock = mocker.patch('os.path.isfile')
    isfilemock.return_value = True
    getmtimemock = mocker.patch('os.path.getmtime')
    getmtimemock.return_value = time.time()
    userIP = mocker.MagicMock()
    returned = client.check_fresh_cert(
        '/Users/foo/.ssh/blessid-cert.pub',
        blessconfig,
        null_bless_cache,
        userIP)
    isfilemock.assert_called_once()
    getmtimemock.assert_called_once()
    assert returned == True


def test_get_default_config_filename():
    default_filename = client.get_default_config_filename()
    assert default_filename[-15:] == 'blessclient.cfg'


def test_update_client(mocker, autoupdate_cache, bless_config):
    fsmock = mocker.patch('os.path.realpath')
    fsmock.return_value = '/User/foo/blessclient/blessclient/'
    isfilemock = mocker.patch('os.path.isfile')
    isfilemock.return_value = True
    popenmock = mocker.patch('subprocess.Popen')
    client.update_client(autoupdate_cache, bless_config)
    isfilemock.assert_called_once_with('/User/foo/blessclient/autoupdate.sh')
    popenmock.assert_called_once()


def test_update_client_invalid_update_script(mocker, autoupdate_cache, bless_config):
    fsmock = mocker.patch('os.path.realpath')
    fsmock.return_value = '/User/foo/blessclient/blessclient/'
    isfilemock = mocker.patch('os.path.isfile')
    logmock = mocker.patch('logging.warn')
    isfilemock.return_value = False
    client.update_client(autoupdate_cache, bless_config)
    isfilemock.assert_called_once_with('/User/foo/blessclient/autoupdate.sh')
    logmock.assert_called_once()


def test_update_client_invalid_update_script(mocker, null_bless_cache, bless_config):
    logmock = mocker.patch('logging.debug')
    client.update_client(null_bless_cache, bless_config)
    logmock.assert_called_with('Client does not need to upgrade yet.')


def test_update_config_from_env(mocker, bless_config):
    # First time without override set
    client.update_config_from_env(bless_config)
    assert bless_config.get_lambda_config()['ipcachelifetime'] == 300
    os.environ['BLESSIPCACHELIFETIME'] = '1'
    client.update_config_from_env(bless_config)
    assert bless_config.get_lambda_config()['ipcachelifetime'] == 1


@pytest.fixture
def autoupdate_cache(mocker):
    bless_cache = BlessCache(None, None, BlessCache.CACHEMODE_ENABLED)
    bless_cache.cache = {'last_updated': '20160101T000001Z'}
    mocker.patch.object(bless_cache, 'save')
    return bless_cache


@pytest.fixture
def null_bless_cache():
    bless_cache = BlessCache(None, None, BlessCache.CACHEMODE_DISABLED)
    bless_cache.cache = {}
    return bless_cache


def test_get_linux_username_Email():
    username = client.get_linux_username("john.doe@example.com")
    assert username == "john.doe"


def test_get_linux_username_EmailWithSpecialChars():
    username = client.get_linux_username("john.doe+test!#$%&'*+-/=?^_`{|}~abc@example.com")
    assert username == "john.doe"


def test_get_cached_auth_token_isEmpty(null_bless_cache):
    cache = null_bless_cache
    returned = client.get_cached_auth_token(cache)
    assert returned == None


def test_get_cached_auth_token_isValid(mocker):
    cachemock = mocker.MagicMock()
    cachemock.get.return_value = {
        "token": "test-token",
        "expiration": (
            datetime.datetime.utcnow() +
            datetime.timedelta(hours=1)
        ).strftime('%Y%m%dT%H%M%SZ'),
        "username": "john.doe"
    }
    returned = client.get_cached_auth_token(cachemock)
    assert returned == "test-token"


def test_get_cached_auth_token_isExpired(mocker):
    cachemock = mocker.MagicMock()
    cachemock.get.return_value = {
        "token": "test-token",
        "expiration": (
            datetime.datetime.utcnow() -
            datetime.timedelta(hours=1)
        ).strftime('%Y%m%dT%H%M%SZ'),
        "username": "john.doe"
    }
    returned = client.get_cached_auth_token(cachemock)
    assert returned == None


@pytest.fixture(scope='module')
def mock_get_credentials():
    username = "john.doe"
    password = "password"

    def mockreturn():
        return username, password

    return mockreturn


def test_auth_okta_noCache(mocker, monkeypatch, null_bless_cache, mock_get_credentials):

    clientmock = mocker.MagicMock()
    clientmock.auth.return_value = {
        "auth": {
            "client_token": "test-token",
            "lease_duration": 500,
            "metadata": {
                "username": "john.doe"
            }
        }
    }

    monkeypatch.setattr(client, 'get_credentials', mock_get_credentials)
    new_client, new_username = client.auth_okta(clientmock, "test_mount", null_bless_cache)
    assert new_username == "john.doe"


def test_auth_okta_Cache(mocker):
    class MockClient(object):
        def __init__(self):
            self.token = "test-token"

    cachemock = mocker.MagicMock()
    cachemock.get.return_value = {
        "token": "test-token",
        "expiration": (
            datetime.datetime.utcnow() +
            datetime.timedelta(hours=1)
        ).strftime('%Y%m%dT%H%M%SZ'),
        "username": "john.doe"
    }
    new_client, new_username = client.auth_okta(MockClient(), "test", cachemock)
    assert new_username == "john.doe"
