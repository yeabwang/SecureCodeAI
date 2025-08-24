"""Focus-based chunking strategy for intelligent code chunking."""

import time
import logging
from typing import List, Dict, Optional, Any, Set, Tuple
from pathlib import Path

from .base_strategy import ChunkingStrategy
from ..models import (
    CodeChunk, ChunkingResult, ChunkingContext, ChunkMetadata, 
    ChunkType, NodeType, ChunkFindingAssociation
)
from ..parsers import BaseParser
from ..utils import TokenCounter, timed_operation
from ..config import ChunkingConfig
from ..exceptions import ChunkingError
from ...core.models import Finding, SeverityLevel


logger = logging.getLogger(__name__)


class FocusBasedStrategy(ChunkingStrategy):
    """Focus-based chunking strategy that prioritizes security findings."""
    
    def __init__(self, 
                 config: ChunkingConfig,
                 token_counter: TokenCounter,
                 parser: Optional[BaseParser] = None):
        super().__init__(config, token_counter, parser)
        self.strategy_name = "focus_based"
        
        # Focus-specific configuration
        self.context_lines = config.strategy.focus_context_lines
        self.priority_weights = config.strategy.focus_priority_weights
        
        # Caching for finding analysis
        self._finding_cache: Dict[str, Any] = {}
    
    def can_handle(self, file_path: Path, content: str, 
                  context: ChunkingContext) -> bool:
        """Check if focus strategy can handle the content."""
        # Requires existing findings to focus on
        return len(context.existing_findings) > 0
    
    def get_priority(self, file_path: Path, content: str,
                    context: ChunkingContext) -> float:
        """Get priority for focus strategy."""
        if not context.existing_findings:
            return 0.0
        
        # Higher priority when there are high-severity findings
        findings_for_file = context.get_findings_for_file(file_path)
        if not findings_for_file:
            return 0.1
        
        # Calculate priority based on finding severity
        severity_score = 0.0
        for finding in findings_for_file:
            weight = self.priority_weights.get(finding.severity.value, 0.0)
            severity_score += weight * finding.confidence
        
        # Normalize by number of findings
        base_priority = min(severity_score / len(findings_for_file), 1.0)
        
        # Boost for critical findings
        has_critical = any(f.severity == SeverityLevel.CRITICAL for f in findings_for_file)
        if has_critical:
            base_priority = min(base_priority + 0.2, 1.0)
        
        return base_priority
    
    @timed_operation("chunk_processing", {"strategy": "focus_based"})
    def chunk_content(self, 
                     content: str,
                     file_path: Path,
                     context: ChunkingContext) -> ChunkingResult:
        """Chunk content using focus-based strategy."""
        start_time = time.time()
        result = ChunkingResult(
            source_file=file_path,
            strategy_used=self.strategy_name
        )
        
        try:
            # Get findings for this file
            findings = context.get_findings_for_file(file_path)
            if not findings:
                logger.warning(f"No findings for {file_path}, cannot apply focus strategy")
                return result
            
            # Create focus zones around findings
            focus_zones = self._create_focus_zones(findings, content, file_path)
            
            # Create chunks from focus zones
            chunks = self._create_focused_chunks(focus_zones, content, file_path, findings)
            
            # Add context chunks if needed
            context_chunks = self._create_context_chunks(chunks, content, file_path)
            chunks.extend(context_chunks)
            
            # Optimize chunks
            optimized_chunks = self.optimize_chunks(chunks)
            
            # Associate findings with chunks
            self._associate_findings_with_chunks(optimized_chunks, findings)
            
            # Add chunks to result
            for chunk in optimized_chunks:
                result.add_chunk(chunk)
            
            # Create relationships and overlaps
            result.chunk_relationships = self.calculate_chunk_relationships(optimized_chunks)
            result.overlap_regions = self.create_overlap_regions(optimized_chunks)
            
            # Calculate focus-specific metrics
            result.processing_time_ms = (time.time() - start_time) * 1000
            result.syntax_preservation_rate = self._calculate_syntax_preservation(optimized_chunks)
            
            self._chunks_created += len(optimized_chunks)
            self._total_processing_time += result.processing_time_ms / 1000
            
            logger.info(f"Focus strategy created {len(optimized_chunks)} chunks for {file_path} "
                       f"covering {len(findings)} findings")
            
        except Exception as e:
            error_msg = f"Focus chunking failed for {file_path}: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
            self._record_error(error_msg, {"file_path": str(file_path), "findings_count": len(context.existing_findings)})
        
        return result
    
    def _create_focus_zones(self, findings: List[Finding], content: str, 
                           file_path: Path) -> List[Dict[str, Any]]:
        """Create focus zones around security findings."""
        lines = content.splitlines()
        total_lines = len(lines)
        focus_zones = []
        
        # Group nearby findings
        finding_groups = self._group_nearby_findings(findings)
        
        for group in finding_groups:
            # Calculate zone boundaries
            min_line = min(f.location.start_line for f in group if f.location)
            max_line = max(f.location.end_line or f.location.start_line for f in group if f.location)
            
            # Expand zone with context
            start_line = max(1, min_line - self.context_lines)
            end_line = min(total_lines, max_line + self.context_lines)
            
            # Calculate priority score
            priority_score = self._calculate_zone_priority(group)
            
            focus_zone = {
                'start_line': start_line,
                'end_line': end_line,
                'findings': group,
                'priority_score': priority_score,
                'line_count': end_line - start_line + 1
            }
            
            focus_zones.append(focus_zone)
        
        # Sort by priority
        focus_zones.sort(key=lambda z: z['priority_score'], reverse=True)
        
        return focus_zones
    
    def _group_nearby_findings(self, findings: List[Finding]) -> List[List[Finding]]:
        """Group findings that are close to each other."""
        if not findings:
            return []
        
        # Sort findings by line number
        sorted_findings = sorted(
            [f for f in findings if f.location],
            key=lambda f: f.location.start_line
        )
        
        groups = []
        current_group = [sorted_findings[0]]
        
        for finding in sorted_findings[1:]:
            # Check if finding is close to the current group
            last_finding = current_group[-1]
            if (finding.location.start_line - 
                (last_finding.location.end_line or last_finding.location.start_line) <= 
                self.context_lines * 2):
                current_group.append(finding)
            else:
                # Start new group
                groups.append(current_group)
                current_group = [finding]
        
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _calculate_zone_priority(self, findings: List[Finding]) -> float:
        """Calculate priority score for a focus zone."""
        if not findings:
            return 0.0
        
        total_score = 0.0
        for finding in findings:
            severity_weight = self.priority_weights.get(finding.severity.value, 0.0)
            confidence_weight = finding.confidence
            total_score += severity_weight * confidence_weight
        
        # Normalize by number of findings (avoid dilution)
        return min(total_score / len(findings), 1.0)
    
    def _create_focused_chunks(self, focus_zones: List[Dict[str, Any]], 
                              content: str, file_path: Path,
                              findings: List[Finding]) -> List[CodeChunk]:
        """Create chunks from focus zones."""
        chunks = []
        lines = content.splitlines()
        
        for zone in focus_zones:
            try:
                # Extract zone content
                start_line = zone['start_line']
                end_line = zone['end_line']
                chunk_lines = lines[start_line-1:end_line]
                chunk_content = '\n'.join(chunk_lines)
                
                if not chunk_content.strip():
                    continue
                
                # Check token limit
                token_count = self.token_counter.count_tokens(chunk_content)
                if token_count > self.config.tokens.max_tokens_per_chunk:
                    # Split large zone
                    sub_chunks = self._split_large_zone(zone, content, file_path)
                    chunks.extend(sub_chunks)
                    continue
                
                # Create chunk metadata
                metadata = self._create_focused_chunk_metadata(
                    chunk_content, file_path, start_line, end_line, zone
                )
                
                # Create chunk
                chunk = CodeChunk(
                    content=chunk_content,
                    metadata=metadata,
                    chunk_type=ChunkType.FOCUSED,
                    security_findings=zone['findings'],
                    focus_score=zone['priority_score'],
                    priority_weight=zone['priority_score']
                )
                
                chunks.append(chunk)
                
            except Exception as e:
                logger.error(f"Failed to create focused chunk: {e}")
                continue
        
        return chunks
    
    def _split_large_zone(self, zone: Dict[str, Any], content: str, 
                         file_path: Path) -> List[CodeChunk]:
        """Split a large focus zone into smaller chunks."""
        lines = content.splitlines()
        max_tokens = self.config.tokens.max_tokens_per_chunk
        
        start_line = zone['start_line']
        end_line = zone['end_line']
        zone_lines = lines[start_line-1:end_line]
        
        # Split while trying to keep findings together
        chunks = []
        current_lines = []
        current_tokens = 0
        current_start = start_line
        
        for i, line in enumerate(zone_lines):
            line_tokens = self.token_counter.count_tokens(line)
            
            if current_tokens + line_tokens > max_tokens and current_lines:
                # Create chunk from current lines
                chunk_content = '\n'.join(current_lines)
                chunk_end = current_start + len(current_lines) - 1
                
                metadata = ChunkMetadata(
                    parent_file=file_path,
                    language=self._detect_language(file_path),
                    start_line=current_start,
                    end_line=chunk_end,
                    token_count=current_tokens,
                    character_count=len(chunk_content),
                    line_count=len(current_lines)
                )
                
                # Find findings in this sub-chunk
                sub_findings = self._find_findings_in_range(
                    zone['findings'], current_start, chunk_end
                )
                
                chunk = CodeChunk(
                    content=chunk_content,
                    metadata=metadata,
                    chunk_type=ChunkType.FOCUSED,
                    security_findings=sub_findings,
                    focus_score=self._calculate_zone_priority(sub_findings)
                )
                
                chunks.append(chunk)
                
                # Reset for next chunk
                current_lines = [line]
                current_tokens = line_tokens
                current_start = current_start + len(current_lines)
            else:
                current_lines.append(line)
                current_tokens += line_tokens
        
        # Add remaining lines
        if current_lines:
            chunk_content = '\n'.join(current_lines)
            chunk_end = current_start + len(current_lines) - 1
            
            metadata = ChunkMetadata(
                parent_file=file_path,
                language=self._detect_language(file_path),
                start_line=current_start,
                end_line=chunk_end,
                token_count=current_tokens,
                character_count=len(chunk_content),
                line_count=len(current_lines)
            )
            
            sub_findings = self._find_findings_in_range(
                zone['findings'], current_start, chunk_end
            )
            
            chunk = CodeChunk(
                content=chunk_content,
                metadata=metadata,
                chunk_type=ChunkType.FOCUSED,
                security_findings=sub_findings,
                focus_score=self._calculate_zone_priority(sub_findings)
            )
            
            chunks.append(chunk)
        
        return chunks
    
    def _create_context_chunks(self, focused_chunks: List[CodeChunk], 
                              content: str, file_path: Path) -> List[CodeChunk]:
        """Create context chunks to fill gaps between focused chunks."""
        if not focused_chunks:
            return []
        
        lines = content.splitlines()
        total_lines = len(lines)
        context_chunks = []
        
        # Sort focused chunks by line number
        sorted_chunks = sorted(focused_chunks, key=lambda c: c.metadata.start_line)
        
        # Create context chunk before first focused chunk
        first_chunk = sorted_chunks[0]
        if first_chunk.metadata.start_line > 1:
            context_chunk = self._create_single_context_chunk(
                content, file_path, 1, first_chunk.metadata.start_line - 1
            )
            if context_chunk:
                context_chunks.append(context_chunk)
        
        # Create context chunks between focused chunks
        for i in range(len(sorted_chunks) - 1):
            current_chunk = sorted_chunks[i]
            next_chunk = sorted_chunks[i + 1]
            
            gap_start = current_chunk.metadata.end_line + 1
            gap_end = next_chunk.metadata.start_line - 1
            
            if gap_end > gap_start:
                context_chunk = self._create_single_context_chunk(
                    content, file_path, gap_start, gap_end
                )
                if context_chunk:
                    context_chunks.append(context_chunk)
        
        # Create context chunk after last focused chunk
        last_chunk = sorted_chunks[-1]
        if last_chunk.metadata.end_line < total_lines:
            context_chunk = self._create_single_context_chunk(
                content, file_path, last_chunk.metadata.end_line + 1, total_lines
            )
            if context_chunk:
                context_chunks.append(context_chunk)
        
        return context_chunks
    
    def _create_single_context_chunk(self, content: str, file_path: Path,
                                    start_line: int, end_line: int) -> Optional[CodeChunk]:
        """Create a single context chunk."""
        if end_line <= start_line:
            return None
        
        lines = content.splitlines()
        chunk_lines = lines[start_line-1:end_line]
        chunk_content = '\n'.join(chunk_lines)
        
        if not chunk_content.strip():
            return None
        
        # Check if chunk is too large
        token_count = self.token_counter.count_tokens(chunk_content)
        if token_count > self.config.tokens.max_tokens_per_chunk:
            # Truncate to fit
            chunk_content = self.token_counter.truncate_to_tokens(
                chunk_content, self.config.tokens.max_tokens_per_chunk
            )
            token_count = self.config.tokens.max_tokens_per_chunk
        
        # Check minimum size
        if token_count < self.config.tokens.min_chunk_tokens:
            return None
        
        metadata = ChunkMetadata(
            parent_file=file_path,
            language=self._detect_language(file_path),
            start_line=start_line,
            end_line=end_line,
            token_count=token_count,
            character_count=len(chunk_content),
            line_count=end_line - start_line + 1
        )
        
        return CodeChunk(
            content=chunk_content,
            metadata=metadata,
            chunk_type=ChunkType.CONTEXT
        )
    
    def _create_focused_chunk_metadata(self, content: str, file_path: Path,
                                      start_line: int, end_line: int,
                                      zone: Dict[str, Any]) -> ChunkMetadata:
        """Create metadata for a focused chunk."""
        token_count = self.token_counter.count_tokens(content)
        
        # Extract node types from findings
        node_types = []
        for finding in zone['findings']:
            # This would be enhanced with actual AST analysis
            if 'function' in finding.description.lower():
                node_types.append(NodeType.FUNCTION_DEF)
            elif 'class' in finding.description.lower():
                node_types.append(NodeType.CLASS_DEF)
        
        return ChunkMetadata(
            parent_file=file_path,
            language=self._detect_language(file_path),
            start_line=start_line,
            end_line=end_line,
            token_count=token_count,
            character_count=len(content),
            line_count=end_line - start_line + 1,
            node_types=node_types
        )
    
    def _associate_findings_with_chunks(self, chunks: List[CodeChunk], 
                                       findings: List[Finding]) -> None:
        """Associate findings with their corresponding chunks."""
        for chunk in chunks:
            chunk_findings = []
            
            for finding in findings:
                if not finding.location:
                    continue
                
                # Check if finding overlaps with chunk
                if (finding.location.start_line >= chunk.metadata.start_line and
                    finding.location.start_line <= chunk.metadata.end_line):
                    chunk_findings.append(finding)
            
            chunk.security_findings = chunk_findings
            if chunk_findings:
                chunk.focus_score = self._calculate_zone_priority(chunk_findings)
    
    def _find_findings_in_range(self, findings: List[Finding], 
                               start_line: int, end_line: int) -> List[Finding]:
        """Find findings within a line range."""
        range_findings = []
        
        for finding in findings:
            if not finding.location:
                continue
            
            if (finding.location.start_line >= start_line and
                finding.location.start_line <= end_line):
                range_findings.append(finding)
        
        return range_findings
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file path."""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.go': 'go',
            '.java': 'java'
        }
        
        return extension_map.get(file_path.suffix.lower(), 'text')
    
    def _calculate_syntax_preservation(self, chunks: List[CodeChunk]) -> float:
        """Calculate syntax preservation rate."""
        if not chunks or not self.parser:
            return 1.0
        
        valid_chunks = 0
        for chunk in chunks:
            try:
                if self.parser.is_valid_syntax(chunk.content):
                    valid_chunks += 1
            except Exception:
                pass  # Count as invalid
        
        return valid_chunks / len(chunks) if chunks else 1.0
    
    def optimize_chunks(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Optimize chunks with focus-specific logic."""
        # Sort chunks by priority (focused chunks first)
        chunks.sort(key=lambda c: (c.focus_score, c.priority_weight), reverse=True)
        
        # Apply base optimization
        optimized = super().optimize_chunks(chunks)
        
        # Focus-specific optimizations
        optimized = self._prioritize_focused_chunks(optimized)
        
        return optimized
    
    def _prioritize_focused_chunks(self, chunks: List[CodeChunk]) -> List[CodeChunk]:
        """Ensure focused chunks with findings are prioritized."""
        focused_chunks = []
        context_chunks = []
        
        for chunk in chunks:
            if chunk.chunk_type == ChunkType.FOCUSED or chunk.security_findings:
                focused_chunks.append(chunk)
            else:
                context_chunks.append(chunk)
        
        # Sort focused chunks by priority
        focused_chunks.sort(key=lambda c: c.focus_score, reverse=True)
        
        # Return focused chunks first, then context
        return focused_chunks + context_chunks
