import sys
from abc import ABC
import logging

from dependency_injector import resources
from dogpile.cache import make_region, CacheRegion

from services.cache import ElasticacheIAMProvider


class DogpileCacheResource(resources.Resource, ABC):
    _DOGPILE_CACHE_MODULE_PATH = "dogpile.cache.redis"
    _CACHE_EXPIRATION_TIME = 3600
    _CACHE_PORT = 6379


class DogpileCacheDevResource(DogpileCacheResource):
    def init(self, connection_url: str) -> CacheRegion:
        return make_region().configure(
            self._DOGPILE_CACHE_MODULE_PATH,
            expiration_time=self._CACHE_EXPIRATION_TIME,
            arguments={
                "url": connection_url
            }
        )


class DogpileCacheProdResource(DogpileCacheResource):
    def init(
        self,
        cache_endpoint: str,
        credential_provider: ElasticacheIAMProvider
    ) -> CacheRegion:
        return make_region().configure(
            self._DOGPILE_CACHE_MODULE_PATH,
            expiration_time=self._CACHE_EXPIRATION_TIME,
            arguments={
                "host": cache_endpoint,
                "port": self._CACHE_PORT,
                "connection_kwargs": {
                    "credential_provider": credential_provider,
                    "ssl": True
                }

            }
        )


def get_logger(log_level: str) -> logging.Logger:
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setLevel(log_level)
    _logger = logging.getLogger("fde-portal")
    _logger.setLevel(log_level)
    _logger.addHandler(log_handler)

    return _logger
