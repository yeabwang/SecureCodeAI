"""Master orchestrator for intelligent code chunking."""

import time
import logging
import asyncio
from typing import List, Dict, Optional, Any, Set
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import ChunkingConfig
from .models import ChunkingResult, ChunkingContext, CodeChunk
from .parsers import parser_factory, language_registry
from .strategies import ChunkingStrategy, StrategySelector, ASTAwareStrategy, FocusBasedStrategy, HybridStrategy, FunctionBasedStrategy, SemanticStrategy
from .utils import TokenCounter, MetricsCollector, PerformanceProfiler
from .cache import ProductionCache, cache_manager
from .exceptions import ChunkingError, LanguageNotSupportedError
from ..core.models import Finding
from ..static_analysis import StaticAnalysisOrchestrator
from ..llm import GroqClient


logger = logging.getLogger(__name__)


class ChunkingOrchestrator:
    """Production orchestrator for intelligent code chunking with full PR0 integration."""
    
    def __init__(self, 
                 config: ChunkingConfig,
                 static_analyzer: Optional[StaticAnalysisOrchestrator] = None,
                 llm_client: Optional[GroqClient] = None):
        
        self.config = config
        self.static_analyzer = static_analyzer
        self.llm_client = llm_client
        
        # Initialize core components
        self.token_counter = TokenCounter(
            model=config.tokens.model,
            cache_size=config.cache.token_cache_size,
            cache_ttl=config.cache.token_ttl
        )
        
        # Initialize metrics if enabled
        self.metrics = None
        if config.monitoring.enable_prometheus:
            self.metrics = MetricsCollector(config.monitoring)
        
        # Initialize cache
        self.cache = ProductionCache(config.cache, self.metrics)
        cache_manager.register_cache("chunking", self.cache)
        
        # Initialize performance profiler
        self.profiler = PerformanceProfiler()
        
        # Initialize parser factory BEFORE strategies
        from .parsers import parser_factory
        self.parser_factory = parser_factory
        
        # Initialize strategies
        self.strategies = self._initialize_strategies()
        self.strategy_selector = StrategySelector(self.strategies)
        
        # Performance tracking
        self._total_files_processed = 0
        self._total_chunks_created = 0
        self._total_processing_time = 0.0
        
        logger.info(f"ChunkingOrchestrator initialized with {len(self.strategies)} strategies")
    
    def _initialize_strategies(self) -> List[ChunkingStrategy]:
        """Initialize available chunking strategies."""
        strategies = []
        
        try:
            # Get default parser for Python (most common language)
            default_parser = self.parser_factory.create_parser("python")
            
            # AST-aware strategy
            ast_strategy = ASTAwareStrategy(
                config=self.config,
                token_counter=self.token_counter,
                parser=default_parser
            )
            strategies.append(ast_strategy)
            
            # Focus-based strategy  
            focus_strategy = FocusBasedStrategy(
                config=self.config,
                token_counter=self.token_counter,
                parser=default_parser
            )
            strategies.append(focus_strategy)
            
            # Hybrid strategy
            hybrid_strategy = HybridStrategy(
                config=self.config,
                token_counter=self.token_counter,
                parser=default_parser
            )
            strategies.append(hybrid_strategy)
            
            # Function-based strategy
            function_strategy = FunctionBasedStrategy(
                config=self.config,
                token_counter=self.token_counter,
                parser=default_parser
            )
            strategies.append(function_strategy)
            
            # Semantic strategy
            semantic_strategy = SemanticStrategy(
                config=self.config,
                token_counter=self.token_counter,
                parser=default_parser
            )
            strategies.append(semantic_strategy)
            
            logger.info(f"Initialized {len(strategies)} chunking strategies")
            
        except Exception as e:
            logger.error(f"Failed to initialize strategies: {e}")
            raise ChunkingError(f"Strategy initialization failed: {e}")
        
        return strategies
    
    @lru_cache(maxsize=32)
    def get_chunking_strategy(self, file_type: str, finding_types: tuple) -> str:
        """Get optimal chunking strategy for file type and findings (cached)."""
        # Strategy selection logic
        if finding_types:
            return "focus_based"
        elif file_type in ['.py', '.js', '.ts', '.go', '.java']:
            return "ast_aware"
        else:
            return "ast_aware"  # Default
    
    async def process_codebase(self, project_path: Path, 
                              existing_findings: Optional[List[Finding]] = None) -> ChunkingResult:
        """Process entire codebase with intelligent chunking."""
        profile = self.profiler.start_profile("process_codebase")
        
        try:
            # Create chunking context
            context = ChunkingContext(
                project_root=project_path,
                existing_findings=existing_findings or []
            )
            
            # Discover source files
            source_files = self._discover_source_files(project_path)
            context.source_files = source_files
            
            self.profiler.checkpoint(profile, "files_discovered", 
                                   {"file_count": len(source_files)})
            
            # Process files
            if self.config.performance.enable_async_processing:
                result = await self._process_files_async(source_files, context)
            else:
                result = self._process_files_sync(source_files, context)
            
            self.profiler.checkpoint(profile, "files_processed", 
                                   {"chunks_created": result.total_chunks})
            
            # Post-process results
            self._post_process_results(result, context)
            
            # Update metrics
            self._total_files_processed += len(source_files)
            self._total_chunks_created += result.total_chunks
            
            if self.metrics:
                self.metrics.record_memory_usage("chunking_orchestrator", 
                                                self._get_memory_usage())
            
            logger.info(f"Processed {len(source_files)} files, created {result.total_chunks} chunks")
            
        except Exception as e:
            logger.error(f"Codebase processing failed: {e}")
            raise ChunkingError(f"Codebase processing failed: {e}")
        
        finally:
            self.profiler.end_profile(profile)
        
        return result
    
    async def process_single_file(self, file_path: Path, 
                                 context: Optional[ChunkingContext] = None) -> ChunkingResult:
        """Process a single file with intelligent chunking."""
        if context is None:
            context = ChunkingContext(source_files=[file_path])
        
        profile = self.profiler.start_profile(f"process_file_{file_path.name}")
        
        try:
            # Check cache first
            file_mtime = file_path.stat().st_mtime
            cached_result = self.cache.get_chunks(str(file_path), file_mtime)
            
            if cached_result and self.config.enable_chunking:
                logger.debug(f"Using cached chunks for {file_path}")
                if self.metrics:
                    self.metrics.record_cache_operation("get", "chunks", True)
                return self._convert_cached_to_result(cached_result, file_path)
            
            if self.metrics:
                self.metrics.record_cache_operation("get", "chunks", False)
            
            # Read file content
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                raise ChunkingError(f"Failed to read file {file_path}: {e}")
            
            self.profiler.checkpoint(profile, "file_read", 
                                   {"file_size": len(content)})
            
            # Get parser for the file
            try:
                parser = parser_factory.create_parser_for_file(file_path, content)
            except LanguageNotSupportedError:
                logger.warning(f"Language not supported for {file_path}, skipping")
                return ChunkingResult(source_file=file_path, strategy_used="unsupported")
            
            # Set parser for strategies
            for strategy in self.strategies:
                strategy.parser = parser
            
            # Select strategy
            strategy = self.strategy_selector.select_strategy(file_path, content, context)
            
            self.profiler.checkpoint(profile, "strategy_selected", 
                                   {"strategy": strategy.strategy_name})
            
            # Perform chunking
            result = strategy.chunk_content(content, file_path, context)
            
            # Cache the result
            if result.chunks:
                self.cache.set_chunks(str(file_path), file_mtime, result.chunks)
            
            self.profiler.checkpoint(profile, "chunking_complete", 
                                   {"chunks_created": len(result.chunks)})
            
            # Record metrics
            if self.metrics:
                file_size_mb = len(content) / (1024 * 1024)
                processing_time = result.processing_time_ms / 1000
                
                self.metrics.record_chunk_processing(
                    language=parser.language,
                    strategy=strategy.strategy_name,
                    file_size_mb=file_size_mb,
                    processing_time=processing_time
                )
                
                for chunk in result.chunks:
                    self.metrics.record_chunk_size(
                        language=parser.language,
                        chunk_type=chunk.chunk_type.value,
                        token_count=chunk.metadata.token_count
                    )
            
            logger.debug(f"Created {len(result.chunks)} chunks for {file_path} "
                        f"using {strategy.strategy_name} strategy")
            
        except Exception as e:
            logger.error(f"File processing failed for {file_path}: {e}")
            raise ChunkingError(f"File processing failed for {file_path}: {e}")
        
        finally:
            self.profiler.end_profile(profile)
        
        return result
    
    async def _process_files_async(self, files: List[Path], 
                                  context: ChunkingContext) -> ChunkingResult:
        """Process files asynchronously."""
        combined_result = ChunkingResult(
            source_files=files,
            strategy_used="mixed"
        )
        
        max_workers = self.config.performance.max_workers or min(4, len(files))
        
        async def process_file_async(file_path: Path) -> ChunkingResult:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, 
                lambda: asyncio.run(self.process_single_file(file_path, context))
            )
        
        # Process files with concurrency limit
        semaphore = asyncio.Semaphore(max_workers)
        
        async def process_with_semaphore(file_path: Path) -> ChunkingResult:
            async with semaphore:
                return await process_file_async(file_path)
        
        tasks = [process_with_semaphore(file_path) for file_path in files]
        
        # Execute tasks and collect results
        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                self._merge_results(combined_result, result)
            except Exception as e:
                logger.error(f"Async file processing failed: {e}")
                combined_result.errors.append(str(e))
        
        return combined_result
    
    def _process_files_sync(self, files: List[Path], 
                           context: ChunkingContext) -> ChunkingResult:
        """Process files synchronously."""
        combined_result = ChunkingResult(
            source_files=files,
            strategy_used="mixed"
        )
        
        for file_path in files:
            try:
                result = asyncio.run(self.process_single_file(file_path, context))
                self._merge_results(combined_result, result)
            except Exception as e:
                logger.error(f"Sync file processing failed for {file_path}: {e}")
                combined_result.errors.append(f"{file_path}: {e}")
        
        return combined_result
    
    def _discover_source_files(self, project_path: Path) -> List[Path]:
        """Discover source files in the project."""
        supported_extensions = language_registry.get_supported_extensions()
        source_files = []
        
        def should_exclude(path: Path) -> bool:
            """Check if path should be excluded."""
            path_str = str(path)
            for pattern in self.config.parser.exclude_patterns:
                if pattern.replace('*', '') in path_str:
                    return True
            return False
        
        for ext in supported_extensions.keys():
            pattern = f"**/*{ext}"
            for file_path in project_path.glob(pattern):
                if file_path.is_file() and not should_exclude(file_path):
                    # Check file size
                    try:
                        size_mb = file_path.stat().st_size / (1024 * 1024)
                        if size_mb <= self.config.performance.max_file_size_mb:
                            source_files.append(file_path)
                        else:
                            logger.warning(f"Skipping large file: {file_path} ({size_mb:.1f}MB)")
                    except Exception as e:
                        logger.warning(f"Could not check file size for {file_path}: {e}")
        
        logger.info(f"Discovered {len(source_files)} source files")
        return source_files
    
    def _merge_results(self, combined: ChunkingResult, single: ChunkingResult) -> None:
        """Merge a single file result into the combined result."""
        combined.chunks.extend(single.chunks)
        combined.chunk_relationships.extend(single.chunk_relationships)
        combined.overlap_regions.extend(single.overlap_regions)
        combined.validation_results.extend(single.validation_results)
        combined.errors.extend(single.errors)
        combined.warnings.extend(single.warnings)
        
        # Update statistics
        combined.total_chunks = len(combined.chunks)
        combined.total_tokens += single.total_tokens
        combined.total_lines += single.total_lines
        combined.processing_time_ms += single.processing_time_ms
        
        if combined.total_chunks > 0:
            combined.average_chunk_size = combined.total_tokens / combined.total_chunks
    
    def _post_process_results(self, result: ChunkingResult, context: ChunkingContext) -> None:
        """Post-process results for optimization and validation."""
        if not result.chunks:
            return
        
        # Calculate success metrics
        valid_chunks = sum(1 for chunk in result.chunks if self._validate_chunk(chunk))
        result.syntax_preservation_rate = valid_chunks / len(result.chunks)
        
        # Calculate boundary preservation (simplified)
        boundary_preserved = sum(1 for chunk in result.chunks 
                               if self._has_semantic_boundaries(chunk))
        result.boundary_preservation_rate = boundary_preserved / len(result.chunks)
        
        # Sort chunks by priority
        result.chunks.sort(key=lambda c: (c.focus_score, c.priority_weight), reverse=True)
    
    def _validate_chunk(self, chunk: CodeChunk) -> bool:
        """Validate a chunk."""
        # Basic validation
        if not chunk.content.strip():
            return False
        
        if chunk.metadata.token_count > self.config.tokens.max_tokens_per_chunk:
            return False
        
        if chunk.metadata.token_count < self.config.tokens.min_chunk_tokens:
            return False
        
        return True
    
    def _has_semantic_boundaries(self, chunk: CodeChunk) -> bool:
        """Check if chunk has semantic boundaries (simplified check)."""
        content = chunk.content.strip()
        
        # Check if starts with function/class/etc
        first_line = content.split('\n')[0].strip()
        if any(keyword in first_line for keyword in ['def ', 'class ', 'function ', 'const ', 'let ', 'var ']):
            return True
        
        return False
    
    def _convert_cached_to_result(self, cached_chunks: List[Any], 
                                 file_path: Path) -> ChunkingResult:
        """Convert cached chunks to ChunkingResult."""
        result = ChunkingResult(
            source_file=file_path,
            strategy_used="cached"
        )
        
        for chunk in cached_chunks:
            result.add_chunk(chunk)
        
        return result
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss
        except ImportError:
            return 0
    
    def get_orchestrator_stats(self) -> Dict[str, Any]:
        """Get orchestrator performance statistics."""
        cache_stats = self.cache.get_stats()
        strategy_stats = {
            strategy.strategy_name: strategy.get_strategy_metrics()
            for strategy in self.strategies
        }
        
        return {
            'total_files_processed': self._total_files_processed,
            'total_chunks_created': self._total_chunks_created,
            'total_processing_time': self._total_processing_time,
            'average_processing_time': (
                self._total_processing_time / max(self._total_files_processed, 1)
            ),
            'cache_stats': cache_stats,
            'strategy_stats': strategy_stats,
            'supported_languages': language_registry.get_supported_languages(),
            'registry_stats': language_registry.get_registry_stats()
        }
    
    def clear_caches(self) -> None:
        """Clear all caches."""
        self.cache.clear_all()
        self.token_counter.clear_cache()
        language_registry.clear_cache()
        self.strategy_selector.clear_cache()
        self.get_chunking_strategy.cache_clear()
        
        logger.info("All caches cleared")
    
    def cleanup(self) -> None:
        """Cleanup resources."""
        try:
            self.cache.cleanup_expired()
            cache_manager.cleanup_all()
            
            # Reset strategy metrics
            for strategy in self.strategies:
                strategy.reset_metrics()
            
            logger.info("Orchestrator cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


# Factory function for easy instantiation
def create_chunking_orchestrator(config: Optional[ChunkingConfig] = None,
                                static_analyzer: Optional[StaticAnalysisOrchestrator] = None,
                                llm_client: Optional[GroqClient] = None) -> ChunkingOrchestrator:
    """Create a production-ready chunking orchestrator."""
    if config is None:
        config = ChunkingConfig.get_production_config()
    
    return ChunkingOrchestrator(
        config=config,
        static_analyzer=static_analyzer,
        llm_client=llm_client
    )
