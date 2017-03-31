from blessclient.bless_cache import BlessCache


def test_get():
    bc = BlessCache(None, None, BlessCache.CACHEMODE_ENABLED)
    bc.cache = {'foo': 'bar'}
    assert bc.get('foo') == 'bar'
    assert bc.get('DOESNOTEXIST') is None


def test_get_nocache():
    bc = BlessCache(None, None, BlessCache.CACHEMODE_DISABLED)
    bc.cache = {'foo': 'bar'}
    assert bc.get('foo') is None


def test_set():
    bc = BlessCache(None, None, BlessCache.CACHEMODE_DISABLED)
    bc.cache = {}
    bc.set('foo', 'bar')
    assert bc.cache == {'foo': 'bar'}
    assert bc.dirty == True


def test_save_cache(tmpdir):
    bc = BlessCache(str(tmpdir), 'cache', BlessCache.CACHEMODE_ENABLED)
    bc.cache = {'foo': 'bar'}
    bc.dirty = True
    bc.save()
    assert len(tmpdir.listdir()) == 1


def test_load_cache(tmpdir):
    tmpdir.join('readcache').write('{"foo": "bar"}')
    bc = BlessCache(str(tmpdir), 'readcache', BlessCache.CACHEMODE_ENABLED)
    bar = bc.get('foo')
    assert bar == 'bar'


def test_load_cache(tmpdir):
    tmpdir.join('readcache_corrupted').write('{"foo": "bar"}}}')
    bc = BlessCache(str(tmpdir), 'readcache_corrupted', BlessCache.CACHEMODE_ENABLED)
    bar = bc.get('foo')
    assert bar == None
