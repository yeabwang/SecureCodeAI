"""Production-grade metrics collection for intelligent code chunking."""

import time
import logging
from typing import Dict, List, Optional, Any, Union
from functools import wraps
from datetime import datetime, timedelta
from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
import threading

from ..config import MonitoringConfig


logger = logging.getLogger(__name__)


# Prometheus metrics
CHUNK_PROCESSING_TIME = Histogram(
    'chunking_processing_seconds',
    'Time spent processing chunks',
    ['language', 'strategy', 'file_size_category']
)

CHUNK_SIZE_DISTRIBUTION = Histogram(
    'chunk_size_tokens',
    'Distribution of chunk sizes in tokens',
    ['language', 'chunk_type']
)

CACHE_OPERATIONS = Counter(
    'cache_operations_total',
    'Total cache operations',
    ['operation', 'cache_type', 'result']
)

PARSING_ERRORS = Counter(
    'parsing_errors_total',
    'Total parsing errors',
    ['language', 'error_type']
)

TOKEN_USAGE = Histogram(
    'token_usage_per_operation',
    'Token usage per operation',
    ['operation_type', 'model']
)

CHUNK_VALIDATION_RESULTS = Counter(
    'chunk_validation_total',
    'Chunk validation results',
    ['validation_type', 'result']
)

MEMORY_USAGE = Gauge(
    'memory_usage_bytes',
    'Current memory usage in bytes',
    ['component']
)

CHUNKING_ERRORS = Counter(
    'chunking_errors_total',
    'Total chunking errors',
    ['error_type', 'strategy']
)

# Custom gauges for real-time monitoring
ACTIVE_CHUNKS = Gauge('active_chunks', 'Number of chunks currently being processed')
CACHE_HIT_RATE = Gauge('cache_hit_rate', 'Current cache hit rate', ['cache_type'])
PROCESSING_QUEUE_SIZE = Gauge('processing_queue_size', 'Size of processing queue')


class MetricsCollector:
    """Production metrics collector for chunking operations."""
    
    def __init__(self, config: MonitoringConfig):
        self.config = config
        self.start_time = datetime.utcnow()
        
        # Internal counters
        self._operation_counts: Dict[str, int] = {}
        self._error_counts: Dict[str, int] = {}
        self._timing_data: Dict[str, List[float]] = {}
        self._cache_stats: Dict[str, Dict[str, int]] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Start Prometheus server if enabled
        if config.enable_prometheus:
            try:
                start_http_server(config.metrics_port)
                logger.info(f"Prometheus metrics server started on port {config.metrics_port}")
            except Exception as e:
                logger.error(f"Failed to start Prometheus server: {e}")
    
    def record_chunk_processing(self, language: str, strategy: str, 
                               file_size_mb: float, processing_time: float) -> None:
        """Record chunk processing metrics."""
        size_category = self._categorize_file_size(file_size_mb)
        
        CHUNK_PROCESSING_TIME.labels(
            language=language,
            strategy=strategy,
            file_size_category=size_category
        ).observe(processing_time)
        
        with self._lock:
            key = f"processing_{language}_{strategy}"
            self._operation_counts[key] = self._operation_counts.get(key, 0) + 1
            
            if key not in self._timing_data:
                self._timing_data[key] = []
            self._timing_data[key].append(processing_time)
    
    def record_chunk_size(self, language: str, chunk_type: str, 
                         token_count: int) -> None:
        """Record chunk size distribution."""
        CHUNK_SIZE_DISTRIBUTION.labels(
            language=language,
            chunk_type=chunk_type
        ).observe(token_count)
    
    def record_cache_operation(self, operation: str, cache_type: str, 
                              hit: bool) -> None:
        """Record cache operation."""
        result = "hit" if hit else "miss"
        
        CACHE_OPERATIONS.labels(
            operation=operation,
            cache_type=cache_type,
            result=result
        ).inc()
        
        with self._lock:
            if cache_type not in self._cache_stats:
                self._cache_stats[cache_type] = {"hits": 0, "misses": 0}
            
            if hit:
                self._cache_stats[cache_type]["hits"] += 1
            else:
                self._cache_stats[cache_type]["misses"] += 1
            
            # Update hit rate gauge
            total = self._cache_stats[cache_type]["hits"] + self._cache_stats[cache_type]["misses"]
            hit_rate = self._cache_stats[cache_type]["hits"] / total if total > 0 else 0
            CACHE_HIT_RATE.labels(cache_type=cache_type).set(hit_rate)
    
    def record_parsing_error(self, language: str, error_type: str) -> None:
        """Record parsing error."""
        PARSING_ERRORS.labels(
            language=language,
            error_type=error_type
        ).inc()
        
        with self._lock:
            key = f"parse_error_{language}_{error_type}"
            self._error_counts[key] = self._error_counts.get(key, 0) + 1
    
    def record_token_usage(self, operation_type: str, model: str, 
                          token_count: int) -> None:
        """Record token usage."""
        TOKEN_USAGE.labels(
            operation_type=operation_type,
            model=model
        ).observe(token_count)
    
    def record_chunk_validation(self, validation_type: str, 
                               is_valid: bool) -> None:
        """Record chunk validation result."""
        result = "valid" if is_valid else "invalid"
        
        CHUNK_VALIDATION_RESULTS.labels(
            validation_type=validation_type,
            result=result
        ).inc()
    
    def record_memory_usage(self, component: str, bytes_used: int) -> None:
        """Record memory usage."""
        MEMORY_USAGE.labels(component=component).set(bytes_used)
    
    def record_chunking_error(self, error_type: str, strategy: str) -> None:
        """Record chunking error."""
        CHUNKING_ERRORS.labels(
            error_type=error_type,
            strategy=strategy
        ).inc()
        
        with self._lock:
            key = f"chunk_error_{error_type}_{strategy}"
            self._error_counts[key] = self._error_counts.get(key, 0) + 1
    
    def set_active_chunks(self, count: int) -> None:
        """Set number of active chunks."""
        ACTIVE_CHUNKS.set(count)
    
    def set_queue_size(self, size: int) -> None:
        """Set processing queue size."""
        PROCESSING_QUEUE_SIZE.set(size)
    
    def _categorize_file_size(self, size_mb: float) -> str:
        """Categorize file size for metrics."""
        if size_mb < 0.1:
            return "tiny"
        elif size_mb < 1.0:
            return "small"
        elif size_mb < 10.0:
            return "medium"
        elif size_mb < 50.0:
            return "large"
        else:
            return "huge"
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics."""
        with self._lock:
            uptime = datetime.utcnow() - self.start_time
            
            return {
                "uptime_seconds": uptime.total_seconds(),
                "total_operations": sum(self._operation_counts.values()),
                "total_errors": sum(self._error_counts.values()),
                "operation_counts": dict(self._operation_counts),
                "error_counts": dict(self._error_counts),
                "cache_stats": dict(self._cache_stats),
                "average_processing_times": {
                    key: sum(times) / len(times) if times else 0
                    for key, times in self._timing_data.items()
                }
            }
    
    def reset_metrics(self) -> None:
        """Reset internal metrics (not Prometheus metrics)."""
        with self._lock:
            self._operation_counts.clear()
            self._error_counts.clear()
            self._timing_data.clear()
            self._cache_stats.clear()
            self.start_time = datetime.utcnow()


def timed_operation(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to time operations and record metrics."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                
                # Record successful operation
                processing_time = time.time() - start_time
                
                # Use appropriate histogram based on metric name
                if metric_name == "chunk_processing":
                    language = labels.get("language", "unknown") if labels else "unknown"
                    strategy = labels.get("strategy", "unknown") if labels else "unknown"
                    file_size_category = labels.get("file_size_category", "unknown") if labels else "unknown"
                    
                    CHUNK_PROCESSING_TIME.labels(
                        language=language,
                        strategy=strategy,
                        file_size_category=file_size_category
                    ).observe(processing_time)
                
                return result
                
            except Exception as e:
                # Record error
                error_type = type(e).__name__
                strategy = labels.get("strategy", "unknown") if labels else "unknown"
                
                CHUNKING_ERRORS.labels(
                    error_type=error_type,
                    strategy=strategy
                ).inc()
                
                raise
        
        return wrapper
    return decorator


class PerformanceProfiler:
    """Performance profiling for chunking operations."""
    
    def __init__(self):
        self.profiles: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.RLock()
    
    def start_profile(self, operation_id: str) -> Dict[str, Any]:
        """Start profiling an operation."""
        profile = {
            "operation_id": operation_id,
            "start_time": time.time(),
            "start_memory": self._get_memory_usage(),
            "checkpoints": []
        }
        
        with self._lock:
            if operation_id not in self.profiles:
                self.profiles[operation_id] = []
            self.profiles[operation_id].append(profile)
        
        return profile
    
    def checkpoint(self, profile: Dict[str, Any], checkpoint_name: str, 
                   metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a checkpoint to the profile."""
        checkpoint = {
            "name": checkpoint_name,
            "timestamp": time.time(),
            "memory": self._get_memory_usage(),
            "metadata": metadata or {}
        }
        
        profile["checkpoints"].append(checkpoint)
    
    def end_profile(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        """End profiling and calculate metrics."""
        end_time = time.time()
        end_memory = self._get_memory_usage()
        
        profile.update({
            "end_time": end_time,
            "end_memory": end_memory,
            "total_time": end_time - profile["start_time"],
            "memory_delta": end_memory - profile["start_memory"]
        })
        
        return profile
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0
    
    def get_profile_summary(self, operation_id: str) -> Dict[str, Any]:
        """Get summary of profiles for an operation."""
        with self._lock:
            profiles = self.profiles.get(operation_id, [])
            
            if not profiles:
                return {}
            
            total_times = [p.get("total_time", 0) for p in profiles if "total_time" in p]
            memory_deltas = [p.get("memory_delta", 0) for p in profiles if "memory_delta" in p]
            
            return {
                "operation_id": operation_id,
                "total_runs": len(profiles),
                "average_time": sum(total_times) / len(total_times) if total_times else 0,
                "min_time": min(total_times) if total_times else 0,
                "max_time": max(total_times) if total_times else 0,
                "average_memory_delta": sum(memory_deltas) / len(memory_deltas) if memory_deltas else 0,
                "total_checkpoints": sum(len(p.get("checkpoints", [])) for p in profiles)
            }
