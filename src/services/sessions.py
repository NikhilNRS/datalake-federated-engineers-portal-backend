from dogpile.cache import CacheRegion
from starsessions import SessionStore


class DogpileSessionStore(SessionStore):
    def __init__(self, cache_region: CacheRegion):
        self._cache_region = cache_region

    async def read(self, session_id: str, lifetime: int) -> bytes:
        cache_key = self.get_cache_key(session_id)
        cached_value = self._cache_region.get(
            cache_key
        )

        assert isinstance(cached_value, bytes)

        return cached_value

    async def write(
        self,
        session_id: str,
        data: bytes,
        lifetime: int,
        ttl: int
    ) -> str:
        cache_key = self.get_cache_key(session_id)
        self._cache_region.set(cache_key, data)

        return session_id

    async def remove(self, session_id: str) -> None:
        cache_key = self.get_cache_key(session_id)
        self._cache_region.delete(cache_key)

    async def exists(self, session_id: str) -> bool:
        cache_key = self.get_cache_key(session_id)
        return not self._cache_region.get(cache_key)

    @staticmethod
    def get_cache_key(session_id: str) -> str:
        return f"session_{session_id}"
