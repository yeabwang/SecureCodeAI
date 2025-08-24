"""Production-grade LRU caching system for intelligent code chunking."""

import hashlib
import logging
import threading
import time
from functools import lru_cache, wraps
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from cachetools import TTLCache, LRUCache
import weakref

from .config import CacheConfig
from .exceptions import CacheError
from .utils.metrics import MetricsCollector


logger = logging.getLogger(__name__)


class ProductionCache:
    """Multi-tier LRU caching system with TTL support and memory management."""
    
    def __init__(self, config: CacheConfig, metrics: Optional[MetricsCollector] = None):
        self.config = config
        self.metrics = metrics
        
        # Multi-tier cache architecture
        self.l1_cache = LRUCache(maxsize=config.chunk_cache_size // 4)  # Hot chunks
        self.l2_cache = TTLCache(maxsize=config.chunk_cache_size, ttl=config.chunk_ttl)  # Warm chunks
        self.ast_cache = LRUCache(maxsize=config.ast_cache_size)  # Parsed ASTs
        self.token_cache = TTLCache(maxsize=config.token_cache_size, ttl=config.token_ttl)  # Token counts
        self.file_hash_cache = LRUCache(maxsize=64)  # File hashes
        
        # Thread safety
        self._locks = {
            'l1': threading.RLock(),
            'l2': threading.RLock(),
            'ast': threading.RLock(),
            'token': threading.RLock(),
            'hash': threading.RLock()
        }
        
        # Memory monitoring
        self._memory_usage = 0
        self._last_cleanup = time.time()
        
        # Statistics
        self._stats = {
            'l1_hits': 0, 'l1_misses': 0,
            'l2_hits': 0, 'l2_misses': 0,
            'ast_hits': 0, 'ast_misses': 0,
            'token_hits': 0, 'token_misses': 0,
            'evictions': 0, 'cleanups': 0
        }
        
        logger.info(f"ProductionCache initialized with L1:{config.chunk_cache_size//4}, "
                   f"L2:{config.chunk_cache_size}, AST:{config.ast_cache_size}, "
                   f"Token:{config.token_cache_size}")
    
    @lru_cache(maxsize=128)
    def _compute_key(self, prefix: str, content: str, *args) -> str:
        """Compute cache key with optional arguments."""
        key_parts = [prefix, content] + [str(arg) for arg in args]
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode('utf-8')).hexdigest()
    
    def get_chunks(self, file_path: str, file_mtime: float) -> Optional[List[Any]]:
        """Get chunks from cache with L1 -> L2 fallback."""
        cache_key = self._compute_key("chunks", file_path, file_mtime)
        
        # Try L1 cache first (hot data)
        with self._locks['l1']:
            if cache_key in self.l1_cache:
                self._stats['l1_hits'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "l1", True)
                return self.l1_cache[cache_key]
            else:
                self._stats['l1_misses'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "l1", False)
        
        # Try L2 cache (warm data)
        with self._locks['l2']:
            if cache_key in self.l2_cache:
                chunks = self.l2_cache[cache_key]
                
                # Promote to L1 cache
                with self._locks['l1']:
                    self.l1_cache[cache_key] = chunks
                
                self._stats['l2_hits'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "l2", True)
                return chunks
            else:
                self._stats['l2_misses'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "l2", False)
        
        return None
    
    def set_chunks(self, file_path: str, file_mtime: float, chunks: List[Any]) -> None:
        """Store chunks in cache with automatic tier management."""
        cache_key = self._compute_key("chunks", file_path, file_mtime)
        
        try:
            # Store in L2 cache first
            with self._locks['l2']:
                self.l2_cache[cache_key] = chunks
            
            # Also store in L1 if recently accessed
            with self._locks['l1']:
                self.l1_cache[cache_key] = chunks
            
            if self.metrics:
                self.metrics.record_cache_operation("set", "chunks", True)
        
        except Exception as e:
            logger.error(f"Failed to cache chunks for {file_path}: {e}")
            if self.metrics:
                self.metrics.record_cache_operation("set", "chunks", False)
    
    def get_ast(self, content_hash: str) -> Optional[Any]:
        """Get parsed AST from cache."""
        with self._locks['ast']:
            if content_hash in self.ast_cache:
                self._stats['ast_hits'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "ast", True)
                return self.ast_cache[content_hash]
            else:
                self._stats['ast_misses'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "ast", False)
                return None
    
    def set_ast(self, content_hash: str, ast_data: Any) -> None:
        """Store parsed AST in cache."""
        try:
            with self._locks['ast']:
                self.ast_cache[content_hash] = ast_data
            
            if self.metrics:
                self.metrics.record_cache_operation("set", "ast", True)
        
        except Exception as e:
            logger.error(f"Failed to cache AST: {e}")
            if self.metrics:
                self.metrics.record_cache_operation("set", "ast", False)
    
    def get_token_count(self, content_hash: str) -> Optional[int]:
        """Get token count from cache."""
        with self._locks['token']:
            if content_hash in self.token_cache:
                self._stats['token_hits'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "token", True)
                return self.token_cache[content_hash]
            else:
                self._stats['token_misses'] += 1
                if self.metrics:
                    self.metrics.record_cache_operation("get", "token", False)
                return None
    
    def set_token_count(self, content_hash: str, token_count: int) -> None:
        """Store token count in cache."""
        try:
            with self._locks['token']:
                self.token_cache[content_hash] = token_count
            
            if self.metrics:
                self.metrics.record_cache_operation("set", "token", True)
        
        except Exception as e:
            logger.error(f"Failed to cache token count: {e}")
            if self.metrics:
                self.metrics.record_cache_operation("set", "token", False)
    
    @lru_cache(maxsize=64)
    def get_file_hash(self, file_path: str, mtime: float) -> str:
        """Get file hash with LRU caching."""
        return self._compute_key("file", file_path, mtime)
    
    def cleanup_expired(self) -> None:
        """Clean up expired cache entries."""
        current_time = time.time()
        
        if current_time - self._last_cleanup < 60:  # Cleanup at most once per minute
            return
        
        try:
            # L2 cache has TTL, so expired entries are automatically removed
            # We just need to track evictions
            
            self._stats['cleanups'] += 1
            self._last_cleanup = current_time
            
            if self.config.enable_memory_monitoring:
                self._check_memory_usage()
            
            logger.debug("Cache cleanup completed")
        
        except Exception as e:
            logger.error(f"Cache cleanup failed: {e}")
    
    def _check_memory_usage(self) -> None:
        """Check memory usage and perform cleanup if needed."""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / (1024 * 1024)
            
            if memory_mb > self.config.max_memory_mb * self.config.memory_cleanup_threshold:
                logger.warning(f"Memory usage {memory_mb:.1f}MB exceeds threshold, performing aggressive cleanup")
                self._aggressive_cleanup()
        
        except ImportError:
            pass  # psutil not available
        except Exception as e:
            logger.error(f"Memory check failed: {e}")
    
    def _aggressive_cleanup(self) -> None:
        """Perform aggressive cache cleanup."""
        # Clear L1 cache first (can be repopulated from L2)
        with self._locks['l1']:
            self.l1_cache.clear()
        
        # Clear oldest half of L2 cache
        with self._locks['l2']:
            items = list(self.l2_cache.items())
            items_to_remove = len(items) // 2
            for i in range(items_to_remove):
                key, _ = items[i]
                if key in self.l2_cache:
                    del self.l2_cache[key]
        
        # Clear oldest ASTs
        with self._locks['ast']:
            items = list(self.ast_cache.items())
            items_to_remove = len(items) // 3
            for i in range(items_to_remove):
                key, _ = items[i]
                if key in self.ast_cache:
                    del self.ast_cache[key]
        
        self._stats['evictions'] += 1
        logger.info("Aggressive cache cleanup completed")
    
    def get_stats(self) -> Dict[str, Union[int, float]]:
        """Get cache statistics."""
        total_l1_ops = self._stats['l1_hits'] + self._stats['l1_misses']
        total_l2_ops = self._stats['l2_hits'] + self._stats['l2_misses']
        total_ast_ops = self._stats['ast_hits'] + self._stats['ast_misses']
        total_token_ops = self._stats['token_hits'] + self._stats['token_misses']
        
        return {
            'l1_size': len(self.l1_cache),
            'l1_maxsize': self.l1_cache.maxsize,
            'l1_hit_rate': self._stats['l1_hits'] / max(total_l1_ops, 1),
            
            'l2_size': len(self.l2_cache),
            'l2_maxsize': self.l2_cache.maxsize,
            'l2_hit_rate': self._stats['l2_hits'] / max(total_l2_ops, 1),
            
            'ast_size': len(self.ast_cache),
            'ast_maxsize': self.ast_cache.maxsize,
            'ast_hit_rate': self._stats['ast_hits'] / max(total_ast_ops, 1),
            
            'token_size': len(self.token_cache),
            'token_maxsize': self.token_cache.maxsize,
            'token_hit_rate': self._stats['token_hits'] / max(total_token_ops, 1),
            
            'total_evictions': self._stats['evictions'],
            'total_cleanups': self._stats['cleanups']
        }
    
    def clear_all(self) -> None:
        """Clear all caches."""
        with self._locks['l1']:
            self.l1_cache.clear()
        with self._locks['l2']:
            self.l2_cache.clear()
        with self._locks['ast']:
            self.ast_cache.clear()
        with self._locks['token']:
            self.token_cache.clear()
        with self._locks['hash']:
            self.get_file_hash.cache_clear()
        
        logger.info("All caches cleared")


def lru_cache_with_ttl(maxsize: int = 128, ttl: int = 300):
    """Custom LRU+TTL decorator for method caching."""
    def decorator(func: Callable) -> Callable:
        cache = TTLCache(maxsize=maxsize, ttl=ttl)
        cache_lock = threading.RLock()
        stats = {'hits': 0, 'misses': 0}
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key
            key = str(args) + str(sorted(kwargs.items()))
            
            with cache_lock:
                if key in cache:
                    stats['hits'] += 1
                    return cache[key]
                
                stats['misses'] += 1
                result = func(*args, **kwargs)
                cache[key] = result
                return result
        
        def cache_info():
            with cache_lock:
                return {
                    'hits': stats['hits'],
                    'misses': stats['misses'],
                    'maxsize': maxsize,
                    'currsize': len(cache),
                    'ttl': ttl
                }
        
        def cache_clear():
            with cache_lock:
                cache.clear()
                stats['hits'] = stats['misses'] = 0
        
        setattr(wrapper, 'cache_info', cache_info)
        setattr(wrapper, 'cache_clear', cache_clear)
        return wrapper
    
    return decorator


class CacheManager:
    """Manager for coordinating multiple cache instances."""
    
    def __init__(self):
        self.caches: Dict[str, ProductionCache] = {}
        self._lock = threading.RLock()
    
    def register_cache(self, name: str, cache: ProductionCache) -> None:
        """Register a cache instance."""
        with self._lock:
            self.caches[name] = cache
            logger.info(f"Cache '{name}' registered")
    
    def get_cache(self, name: str) -> Optional[ProductionCache]:
        """Get a cache instance by name."""
        with self._lock:
            return self.caches.get(name)
    
    def cleanup_all(self) -> None:
        """Clean up all registered caches."""
        with self._lock:
            for name, cache in self.caches.items():
                try:
                    cache.cleanup_expired()
                    logger.debug(f"Cleaned up cache '{name}'")
                except Exception as e:
                    logger.error(f"Failed to cleanup cache '{name}': {e}")
    
    def get_all_stats(self) -> Dict[str, Dict[str, Union[int, float]]]:
        """Get statistics for all caches."""
        with self._lock:
            return {
                name: cache.get_stats()
                for name, cache in self.caches.items()
            }
    
    def clear_all(self) -> None:
        """Clear all registered caches."""
        with self._lock:
            for name, cache in self.caches.items():
                try:
                    cache.clear_all()
                    logger.info(f"Cleared cache '{name}'")
                except Exception as e:
                    logger.error(f"Failed to clear cache '{name}': {e}")


# Global cache manager instance
cache_manager = CacheManager()
