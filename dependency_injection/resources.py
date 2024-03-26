from typing import Optional

from dependency_injector import resources
from dependency_injector.resources import T
from dogpile.cache import make_region


class DogpileCacheResource(resources.Resource):
    _DOGPILE_CACHE_MODULE_PATH = "dogpile.cache.memory"

    def init(self) -> Optional[T]:
        return make_region().configure(
            self._DOGPILE_CACHE_MODULE_PATH,
            expiration_time=3600
        )