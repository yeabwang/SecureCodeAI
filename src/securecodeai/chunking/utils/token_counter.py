"""Production-grade token counting with tiktoken integration."""

import hashlib
import logging
from functools import lru_cache
from typing import Dict, List, Optional, Tuple, Union
from cachetools import TTLCache
import tiktoken

from ..config import TokenModel
from ..exceptions import TokenLimitExceededError


logger = logging.getLogger(__name__)


class TokenCounter:
    """Production token counter with caching and multiple model support."""
    
    def __init__(self, 
                 model: TokenModel = TokenModel.LLAMA_3_70B,
                 cache_size: int = 200,
                 cache_ttl: int = 300):
        
        self.model = model
        self.cache = TTLCache(maxsize=cache_size, ttl=cache_ttl)
        
        # Initialize tokenizer
        self.encoder = self._get_encoder(model)
        
        # Model-specific limits
        self.model_limits = {
            TokenModel.GPT_4: 8192,
            TokenModel.GPT_35_TURBO: 4096,
            TokenModel.CLAUDE_3: 200000,
            TokenModel.LLAMA_3_70B: 8192
        }
        
        self.max_tokens = self.model_limits.get(model, 4096)
        
        logger.info(f"TokenCounter initialized for {model} with max tokens: {self.max_tokens}")
    
    def _get_encoder(self, model: TokenModel) -> tiktoken.Encoding:
        """Get appropriate encoder for the model."""
        try:
            if model in [TokenModel.GPT_4, TokenModel.GPT_35_TURBO]:
                return tiktoken.encoding_for_model(model.value)
            else:
                # Use cl100k_base as approximation for other models
                return tiktoken.get_encoding("cl100k_base")
        except Exception as e:
            logger.warning(f"Failed to get encoder for {model}, using cl100k_base: {e}")
            return tiktoken.get_encoding("cl100k_base")
    
    @lru_cache(maxsize=64)
    def _get_content_hash(self, content: str) -> str:
        """Get hash of content for caching."""
        return hashlib.md5(content.encode('utf-8')).hexdigest()
    
    def count_tokens(self, text: str, use_cache: bool = True) -> int:
        """Count tokens in text with caching."""
        if not text:
            return 0
        
        cache_key = None
        if use_cache:
            content_hash = self._get_content_hash(text)
            cache_key = f"{self.model.value}:{content_hash}"
            
            if cache_key in self.cache:
                return self.cache[cache_key]
        
        try:
            token_count = len(self.encoder.encode(text))
            
            if use_cache and cache_key is not None:
                self.cache[cache_key] = token_count
            
            return token_count
            
        except Exception as e:
            logger.error(f"Failed to count tokens: {e}")
            # Fallback: rough estimation (4 chars per token)
            return len(text) // 4
    
    def count_tokens_batch(self, texts: List[str], use_cache: bool = True) -> List[int]:
        """Count tokens for multiple texts efficiently."""
        return [self.count_tokens(text, use_cache) for text in texts]
    
    def estimate_tokens(self, text: str) -> int:
        """Fast token estimation without encoding."""
        # Rough estimation: 4 characters per token
        return len(text) // 4
    
    def validate_token_limit(self, text: str, max_tokens: Optional[int] = None) -> bool:
        """Validate if text is within token limits."""
        limit = max_tokens or self.max_tokens
        token_count = self.count_tokens(text)
        return token_count <= limit
    
    def truncate_to_tokens(self, text: str, max_tokens: int, 
                          preserve_sentences: bool = True) -> str:
        """Truncate text to fit within token limit."""
        current_tokens = self.count_tokens(text)
        
        if current_tokens <= max_tokens:
            return text
        
        if preserve_sentences:
            return self._truncate_by_sentences(text, max_tokens)
        else:
            return self._truncate_by_tokens(text, max_tokens)
    
    def _truncate_by_sentences(self, text: str, max_tokens: int) -> str:
        """Truncate by complete sentences."""
        sentences = text.split('. ')
        result = ""
        
        for sentence in sentences:
            candidate = result + sentence + ". " if result else sentence + ". "
            if self.count_tokens(candidate) <= max_tokens:
                result = candidate
            else:
                break
        
        return result.rstrip(". ")
    
    def _truncate_by_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate by token count using binary search."""
        if not text:
            return text
        
        left, right = 0, len(text)
        result = ""
        
        while left < right:
            mid = (left + right + 1) // 2
            candidate = text[:mid]
            
            if self.count_tokens(candidate) <= max_tokens:
                result = candidate
                left = mid
            else:
                right = mid - 1
        
        return result
    
    def split_by_tokens(self, text: str, max_tokens: int, 
                       overlap_tokens: int = 0) -> List[str]:
        """Split text into chunks by token count."""
        if not text:
            return []
        
        chunks = []
        tokens = self.encoder.encode(text)
        
        if len(tokens) <= max_tokens:
            return [text]
        
        start = 0
        while start < len(tokens):
            end = min(start + max_tokens, len(tokens))
            
            # Extract chunk tokens
            chunk_tokens = tokens[start:end]
            chunk_text = self.encoder.decode(chunk_tokens)
            chunks.append(chunk_text)
            
            # Move start position with overlap
            start = end - overlap_tokens
            if start >= len(tokens):
                break
        
        return chunks
    
    def get_optimal_chunk_size(self, text: str, min_chunks: int = 1, 
                              max_chunks: int = 10) -> Tuple[int, int]:
        """Get optimal chunk size and count for text."""
        total_tokens = self.count_tokens(text)
        
        if total_tokens <= self.max_tokens:
            return total_tokens, 1
        
        # Try different chunk counts to find optimal size
        best_chunk_size = self.max_tokens
        best_chunk_count = max_chunks
        
        for chunk_count in range(min_chunks, max_chunks + 1):
            chunk_size = total_tokens // chunk_count
            
            if chunk_size <= self.max_tokens:
                if chunk_count < best_chunk_count:
                    best_chunk_size = chunk_size
                    best_chunk_count = chunk_count
                break
        
        return best_chunk_size, best_chunk_count
    
    def calculate_budget_allocation(self, template_tokens: int, 
                                  context_tokens: int,
                                  response_tokens: int) -> Dict[str, Union[int, float]]:
        """Calculate token budget allocation."""
        total_reserved = template_tokens + context_tokens + response_tokens
        
        if total_reserved >= self.max_tokens:
            raise TokenLimitExceededError(
                total_reserved, self.max_tokens,
                "Reserved tokens exceed model limit"
            )
        
        available_for_chunks = self.max_tokens - total_reserved
        
        return {
            "total_limit": self.max_tokens,
            "template_tokens": template_tokens,
            "context_tokens": context_tokens,
            "response_tokens": response_tokens,
            "available_for_chunks": available_for_chunks,
            "reserved_total": total_reserved,
            "utilization_percentage": (total_reserved / self.max_tokens) * 100
        }
    
    def get_cache_stats(self) -> Dict[str, Union[int, float]]:
        """Get cache performance statistics."""
        return {
            "cache_size": len(self.cache),
            "cache_maxsize": self.cache.maxsize,
            "cache_hit_rate": getattr(self.cache, 'hits', 0) / max(getattr(self.cache, 'hits', 0) + getattr(self.cache, 'misses', 0), 1)
        }
    
    def clear_cache(self) -> None:
        """Clear token cache."""
        self.cache.clear()
        logger.info("Token cache cleared")


class TemplateTokenManager:
    """Manages token counting for prompt templates."""
    
    def __init__(self, token_counter: TokenCounter):
        self.token_counter = token_counter
        self.template_cache: Dict[str, int] = {}
    
    @lru_cache(maxsize=64)
    def count_template_tokens(self, template_content: str, 
                             variables: Optional[Dict[str, str]] = None) -> int:
        """Count tokens in template with variable substitution."""
        if variables:
            # Simple variable substitution for estimation
            content = template_content
            for key, value in variables.items():
                placeholder = f"{{{key}}}"
                content = content.replace(placeholder, str(value))
        else:
            content = template_content
        
        return self.token_counter.count_tokens(content)
    
    def estimate_filled_template_tokens(self, template_content: str,
                                      avg_variable_length: int = 100) -> int:
        """Estimate tokens for filled template."""
        # Count placeholder variables
        import re
        placeholders = re.findall(r'\{[^}]+\}', template_content)
        
        # Replace placeholders with estimated content
        estimated_content = template_content
        for placeholder in placeholders:
            estimated_content = estimated_content.replace(
                placeholder, "x" * avg_variable_length
            )
        
        return self.token_counter.count_tokens(estimated_content)
    
    def get_template_budget(self, template_name: str, 
                           template_content: str) -> Dict[str, Union[str, int]]:
        """Get token budget information for a template."""
        base_tokens = self.token_counter.count_tokens(template_content)
        estimated_filled = self.estimate_filled_template_tokens(template_content)
        
        return {
            "template_name": template_name,
            "base_tokens": base_tokens,
            "estimated_filled_tokens": estimated_filled,
            "available_for_content": self.token_counter.max_tokens - estimated_filled
        }
