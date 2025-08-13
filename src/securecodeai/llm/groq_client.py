"""Groq LLM client for SecureCodeAI."""

import os
import time
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import tiktoken

from groq import Groq
from groq.types.chat import ChatCompletion
from groq.types.chat.chat_completion_message_param import ChatCompletionMessageParam


logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM with metadata."""
    content: str
    model: str
    tokens_used: int
    finish_reason: str
    response_time: float
    metadata: Dict[str, Any]


class GroqError(Exception):
    """Base exception for Groq client errors."""
    pass


class RateLimitError(GroqError):
    """Raised when rate limit is exceeded."""
    pass


class TokenLimitError(GroqError):
    """Raised when token limit is exceeded."""
    pass


class GroqClient:
    """Client for interacting with Groq API."""
    
    def __init__(self, 
                 api_key: Optional[str] = None,
                 model: str = "llama3-70b-8192",
                 max_tokens: int = 4096,
                 temperature: float = 0.1,
                 timeout: int = 30,
                 max_retries: int = 3,
                 requests_per_minute: int = 60,
                 tokens_per_minute: int = 50000):
        
        self.api_key = api_key or os.getenv('GROQ_API_KEY') or os.getenv('GROQ_API')
        if not self.api_key:
            raise GroqError("Groq API key not provided")
        
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Rate limiting
        self.requests_per_minute = requests_per_minute
        self.tokens_per_minute = tokens_per_minute
        self._request_times: List[float] = []
        self._token_usage: List[tuple[float, int]] = []  # (timestamp, tokens)
        
        # Initialize client
        self.client = Groq(api_key=self.api_key)
        
        # Token encoder for counting
        try:
            self.encoder = tiktoken.encoding_for_model("gpt-3.5-turbo")  # Close approximation
        except Exception:
            self.encoder = tiktoken.get_encoding("cl100k_base")
        
        self.logger = logging.getLogger(__name__)
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self) -> None:
        """Test the connection to Groq API."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10,
                temperature=0
            )
            self.logger.info("Successfully connected to Groq API")
        except Exception as e:
            raise GroqError(f"Failed to connect to Groq API: {e}")
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in text."""
        try:
            return len(self.encoder.encode(text))
        except Exception as e:
            self.logger.warning(f"Failed to count tokens: {e}")
            # Fallback estimation: ~4 chars per token
            return len(text) // 4
    
    def count_message_tokens(self, messages: List[Dict[str, str]]) -> int:
        """Count tokens in a list of messages."""
        total_tokens = 0
        
        for message in messages:
            # Add tokens for role and content
            total_tokens += self.count_tokens(message.get("role", ""))
            total_tokens += self.count_tokens(message.get("content", ""))
            total_tokens += 4  # Overhead per message
        
        total_tokens += 2  # Overhead for the conversation
        return total_tokens
    
    def _check_rate_limits(self, estimated_tokens: int) -> None:
        """Check if request would exceed rate limits."""
        current_time = time.time()
        
        # Clean old entries (older than 1 minute)
        self._request_times = [t for t in self._request_times if current_time - t < 60]
        self._token_usage = [(t, tokens) for t, tokens in self._token_usage if current_time - t < 60]
        
        # Check request rate limit
        if len(self._request_times) >= self.requests_per_minute:
            sleep_time = 60 - (current_time - self._request_times[0])
            if sleep_time > 0:
                self.logger.warning(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
        
        # Check token rate limit
        current_token_usage = sum(tokens for _, tokens in self._token_usage)
        if current_token_usage + estimated_tokens > self.tokens_per_minute:
            # Calculate sleep time needed
            oldest_usage_time = min(t for t, _ in self._token_usage) if self._token_usage else current_time
            sleep_time = 60 - (current_time - oldest_usage_time)
            if sleep_time > 0:
                self.logger.warning(f"Token limit would be exceeded, sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
    
    def _record_usage(self, tokens_used: int) -> None:
        """Record usage for rate limiting."""
        current_time = time.time()
        self._request_times.append(current_time)
        self._token_usage.append((current_time, tokens_used))
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        retry=retry_if_exception_type((RateLimitError, ConnectionError))
    )
    def _make_request(self, messages: List[ChatCompletionMessageParam], **kwargs) -> ChatCompletion:
        """Make a request to Groq API with retries."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=kwargs.get('max_tokens', self.max_tokens),
                temperature=kwargs.get('temperature', self.temperature),
                timeout=self.timeout,
                **{k: v for k, v in kwargs.items() if k not in ['max_tokens', 'temperature']}
            )
            return response
        except Exception as e:
            error_msg = str(e).lower()
            if 'rate limit' in error_msg or 'too many requests' in error_msg:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            elif 'timeout' in error_msg:
                raise ConnectionError(f"Request timeout: {e}")
            else:
                raise GroqError(f"API request failed: {e}")
    
    def chat_completion(self, 
                       messages: List[Dict[str, str]],
                       **kwargs) -> LLMResponse:
        """Send a chat completion request."""
        start_time = time.time()
        
        # Validate input
        if not messages:
            raise ValueError("Messages cannot be empty")
        
        # Convert dict messages to proper ChatCompletionMessageParam format
        formatted_messages: List[ChatCompletionMessageParam] = []
        for msg in messages:
            if msg.get("role") == "system":
                formatted_messages.append({"role": "system", "content": msg["content"]})
            elif msg.get("role") == "user":
                formatted_messages.append({"role": "user", "content": msg["content"]})
            elif msg.get("role") == "assistant":
                formatted_messages.append({"role": "assistant", "content": msg["content"]})
            else:
                # Default to user role if not specified
                formatted_messages.append({"role": "user", "content": msg.get("content", "")})
        
        # Count tokens
        input_tokens = self.count_message_tokens(messages)
        estimated_total_tokens = input_tokens + kwargs.get('max_tokens', self.max_tokens)
        
        # Check token limits
        if estimated_total_tokens > 8192:  # Model's context window
            raise TokenLimitError(f"Total tokens ({estimated_total_tokens}) exceed model limit")
        
        # Check rate limits
        self._check_rate_limits(estimated_total_tokens)
        
        try:
            # Make the request
            response = self._make_request(formatted_messages, **kwargs)
            
            # Extract response data
            content = response.choices[0].message.content or ""
            finish_reason = response.choices[0].finish_reason
            
            # Calculate tokens used
            output_tokens = self.count_tokens(content)
            total_tokens = input_tokens + output_tokens
            
            # Record usage
            self._record_usage(total_tokens)
            
            response_time = time.time() - start_time
            
            self.logger.debug(
                f"Groq request completed: {input_tokens} input tokens, "
                f"{output_tokens} output tokens, {response_time:.2f}s"
            )
            
            return LLMResponse(
                content=content,
                model=self.model,
                tokens_used=total_tokens,
                finish_reason=finish_reason,
                response_time=response_time,
                metadata={
                    'input_tokens': input_tokens,
                    'output_tokens': output_tokens,
                    'finish_reason': finish_reason,
                    'model': self.model,
                    'usage': getattr(response, 'usage', None),
                }
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            self.logger.error(f"Groq request failed after {response_time:.2f}s: {e}")
            raise
    
    def simple_completion(self, prompt: str, **kwargs) -> str:
        """Simple text completion."""
        messages = [{"role": "user", "content": prompt}]
        response = self.chat_completion(messages, **kwargs)
        return response.content
    
    def analyze_code(self, 
                    code: str,
                    context: str = "",
                    analysis_type: str = "security",
                    **kwargs) -> LLMResponse:
        """Analyze code for security issues."""
        
        system_prompt = self._get_analysis_system_prompt(analysis_type)
        
        user_prompt = f"""Please analyze the following code for security vulnerabilities:

{f'Context: {context}' if context else ''}

Code to analyze:
```
{code}
```

Please provide:
1. Identified vulnerabilities (if any)
2. Severity level (Critical/High/Medium/Low)
3. Confidence level (0.0-1.0)
4. Brief explanation
5. Remediation advice (if applicable)

Respond in JSON format."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        return self.chat_completion(messages, **kwargs)
    
    def _get_analysis_system_prompt(self, analysis_type: str) -> str:
        """Get system prompt for code analysis."""
        base_prompt = """You are a security expert specializing in code analysis. Your task is to identify security vulnerabilities in code with high accuracy and minimal false positives.

Guidelines:
- Focus on actual security issues, not code quality
- Be conservative with confidence scores
- Provide actionable remediation advice
- Consider the context when available
- Use standard vulnerability classifications (OWASP, CWE)
"""
        
        if analysis_type == "security":
            return base_prompt + """
Focus specifically on:
- Injection vulnerabilities (SQL, Command, Code)
- Authentication and authorization flaws
- Cryptographic issues
- Input validation problems
- Insecure configurations
- Hardcoded secrets
"""
        
        return base_prompt
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics."""
        current_time = time.time()
        
        # Clean old entries
        recent_requests = [t for t in self._request_times if current_time - t < 60]
        recent_tokens = [(t, tokens) for t, tokens in self._token_usage if current_time - t < 60]
        
        return {
            'requests_last_minute': len(recent_requests),
            'tokens_last_minute': sum(tokens for _, tokens in recent_tokens),
            'requests_per_minute_limit': self.requests_per_minute,
            'tokens_per_minute_limit': self.tokens_per_minute,
            'model': self.model,
            'total_requests': len(self._request_times),
            'total_tokens': sum(tokens for _, tokens in self._token_usage),
        }
