import pickle

from flask import current_app
from redis import Redis


class RuntimeConfig(object):
    redis: Redis

    def __init__(self, app):
        self.redis = app.extensions["redis"]

    def __getitem__(self, key):
        if self.redis.hexists("runtime_config", key):
            return pickle.loads(self.redis.hget("runtime_config", key))
        return current_app.config[key]

    def __setitem__(self, key, value):
        self.redis.hset("runtime_config", key, pickle.dumps(value))

    def __delitem__(self, key):
        self.redis.hdel("runtime_config", key)

    def __contains__(self, key):
        return self.redis.hexists("runtime_config", key)

    def __len__(self):
        return self.redis.hlen("runtime_config")

    def __iter__(self):
        yield from map(lambda s: s.decode("utf-8"), self.redis.hkeys("runtime_config"))

    def get(self, key, default=None):
        if self.redis.hexists("runtime_config", key):
            return pickle.loads(self.redis.hget("runtime_config", key))
        return current_app.config.get(key, default)

    def keys(self):
        return list(self)

    def values(self):
        return list(map(pickle.dumps, self.redis.hvals("runtime_config")))

    def items(self):
        return list(zip(self.keys(), self.values()))
