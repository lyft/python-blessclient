import time
import pytest
from blessclient.user_ip import UserIP
from blessclient.bless_cache import BlessCache

IP_URLS = ['http://checkip.amazonaws.com', 'http://api.ipify.org']

def test_getIP_fresh():
    user_ip = UserIP(None, 10, IP_URLS)
    user_ip.fresh = True
    user_ip.currentIP = '1.1.1.1'
    assert user_ip.getIP() == '1.1.1.1'


def test_getIP_cached():
    bc = BlessCache(None, None, BlessCache.CACHEMODE_ENABLED)
    bc.cache = {}
    bc.set('lastip', '1.1.1.1')
    bc.set('lastipchecktime', time.time())
    user_ip = UserIP(bc, 10, IP_URLS)
    assert user_ip.getIP() == '1.1.1.1'


def test_getIP_fetched(mocker):
    bc = BlessCache(None, None, BlessCache.CACHEMODE_ENABLED)
    bc.cache = {}
    mocker.patch.object(bc, 'save')
    user_ip = UserIP(bc, 10, IP_URLS)
    mocker.patch.object(user_ip, '_fetchIP')
    user_ip._fetchIP.return_value = '1.1.1.1'
    assert user_ip.getIP() == '1.1.1.1'
    user_ip._fetchIP.assert_called_once()
    bc.save.assert_called_once()


def test_getIP_fetched_fail(mocker):
    bc = BlessCache(None, None, BlessCache.CACHEMODE_ENABLED)
    bc.cache = {}
    mocker.patch.object(bc, 'save')
    user_ip = UserIP(bc, 10, IP_URLS)
    mocker.patch.object(user_ip, '_fetchIP')
    user_ip._fetchIP.return_value = None
    with pytest.raises(Exception):
        user_ip.getIP()
    user_ip._fetchIP.assert_called()
