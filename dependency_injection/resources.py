from dependency_injector import resources
from dogpile.cache import make_region, CacheRegion


class DogpileCacheResource(resources.Resource):
    _DOGPILE_CACHE_MODULE_PATH = "dogpile.cache.memory"

    def init(self) -> CacheRegion:
        return make_region().configure(
            self._DOGPILE_CACHE_MODULE_PATH,
            expiration_time=3600
        )
