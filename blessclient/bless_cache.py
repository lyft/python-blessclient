from __future__ import absolute_import
import json
import logging
import os


class BlessCache(object):
    CACHEMODE_DISABLED = 'disabled'
    CACHEMODE_RECACHE = 'recache'
    CACHEMODE_ENABLED = 'enabled'

    def __init__(self, filepath, filename, cachemode=CACHEMODE_ENABLED):
        self.filepath = filepath
        self.filename = filename
        self.mode = cachemode
        self.cache = None
        self.dirty = False

    def get(self, key):
        if self.mode != self.CACHEMODE_ENABLED:
            logging.debug("Cache get disabled")
            return None
        value = None
        if self.cache is None:
            self.loadCache()
        if key in self.cache.keys():
            value = self.cache[key]
        return value

    def set(self, key, value):
        if self.cache is None:
            self.loadCache()
        self.dirty = True
        self.cache[key] = value

    def save(self):
        if self.dirty and self.mode != self.CACHEMODE_DISABLED:
            self.saveCache()

    def loadCache(self):
        self.cache = {}
        cache_file_path = os.path.join(self.filepath, self.filename)
        if os.path.isfile(cache_file_path):
            with open(cache_file_path, 'r') as cache:
                try:
                    self.cache = json.load(cache)
                except:
                    logging.error("Corrupted cache, using empty cache")
        logging.debug("Cache loaded: {}".format(self.cache))

    def saveCache(self):
        if not os.path.exists(self.filepath):
            os.makedirs(self.filepath)
        cache_file_path = os.path.join(self.filepath, self.filename)
        with open(cache_file_path, 'w') as cache:
            json.dump(self.cache, cache)
            logging.debug("Cache saved")
