import contextlib
import logging
import string
import time
from urllib2 import urlopen

VALID_IP_CHARACTERS = string.hexdigits + '.:'


class UserIP(object):

    def __init__(self, bless_cache, maxcachetime, ip_urls, fixed_ip=False):
        self.fresh = False
        self.currentIP = None
        self.cache = bless_cache
        self.maxcachetime = maxcachetime
        self.ip_urls = ip_urls
        if fixed_ip:
            self.currentIP = fixed_ip
            self.fresh = True

    def getIP(self):
        if self.fresh and self.currentIP:
            return self.currentIP
        lastip = self.cache.get('lastip')
        lastiptime = self.cache.get('lastipchecktime')
        if lastiptime and lastiptime + self.maxcachetime > time.time():
            return lastip
        self._refreshIP()
        return self.currentIP

    def _refreshIP(self):
        logging.debug("Getting current public IP")

        ip = None
        for url in self.ip_urls:
            if ip:
                break
            else:
                ip = self._fetchIP(url)

        if not ip:
            raise Exception('Could not refresh public IP')

        self.currentIP = ip
        self.fresh = True
        self.cache.set('lastip', self.currentIP)
        self.cache.set('lastipchecktime', time.time())
        self.cache.save()

    def _fetchIP(self, url):
        try:
            with contextlib.closing(urlopen(url, timeout=2)) as f:
                if f.getcode() == 200:
                    content = f.read().strip()
                    for c in content[:40]:
                        if c not in VALID_IP_CHARACTERS:
                            raise ValueError("Public IP response included invalid character '{}'.".format(c))
                    return content
        except:
            logging.debug('Could not refresh public IP from {}'.format(url), exc_info=True)

        return None
