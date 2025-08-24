# SecureCodeAI

**Security analysis platform combining static analysis with intelligent code chunking and AI enhancement.**

## Inspiration & Problem Statement

Inspired by [claude-code-security](https://github.com/anthropics/claude-code-security-review) and [llm-security-scanner](https://github.com/iknowjason/llm-security-scanner), this project addresses key limitations in existing tools:

- **PR-only analysis**: Missing security issues in dependencies and broader codebase context
- **Context window limits**: Feeding entire codebases to LLMs reduces accuracy ([context rot](https://research.trychroma.com/context-rot))
- **Ground truth gaps**: LLM outputs lack solid foundation without static analysis validation
- **Cost inefficiency**: Large codebases result in excessive token usage

## Current Architecture

**Analysis Flow:**
```
Static Analysis (Ground Truth) → Intelligent Chunking → LLM Enhancement
    37 findings              →    4-11 chunks       →   Remediation advice
```

**Implementation Status:**
- **Phase 1 (PR0)**: Multi-tool static analysis with AI enhancement ✅
- **Phase 2 (PR1)**: Intelligent code chunking for security-focused analysis ✅  
- **Phase 3 (Planned)**: Two-tier LLM analysis with CWE-specific templates 🚧

## How It Works

**Current Pipeline:**

1. **Static Analysis Foundation**
   - Bandit, Semgrep, Safety scan codebase for security issues
   - 30-40 findings with confidence scoring and deduplication
   - Provides ground truth for LLM enhancement

2. **Intelligent Chunking** 
   - Focus-based strategy maps security findings to code chunks
   - 4-11 security-focused chunks per file (1000-6000 tokens)
   - Tree-sitter AST parsing preserves semantic boundaries

3. **LLM Enhancement**
   - GROQ API analyzes critical chunks with security context
   - Generates remediation advice and fix suggestions
   - 1000-1500 tokens consumed per analysis

**Target Architecture (In Development):**
- **High-level scanner**: CWE-specific triage (simple fix vs detailed analysis)
- **Deep analyzer**: Multi-template evidence gathering with 36+ vulnerability prompts
- **Intelligent routing**: Severity-based analysis depth selection

## What It Delivers

**Static Analysis Engine:**
- Multi-tool integration (Bandit, Semgrep, Safety)
- 37+ security findings across enterprise-scale codebases
- GROQ LLM enhancement for context and remediation advice
- JSON/table output formats with confidence scoring

**Intelligent Chunking System:**
- 5 chunking strategies (AST-aware, focus-based, hybrid, function-based, semantic)
- Security-focused chunk generation from static analysis findings
- LRU caching with 15.9x performance improvement
- Tree-sitter AST parsing for Python, JavaScript, Go, Java
- Token-optimized chunking for LLM context windows

## Installation

```bash
git clone https://github.com/yeabwang/SecureCodeAI.git
cd SecureCodeAI
pip install -e .
```

**Requirements**: Python 3.11+, optional GROQ API key for AI enhancement

## Get Free Groq api key

1. Sign up / Log in → Go to https://console.groq.com and create an account or log in.
2. Access API Keys page → In the dashboard, click your profile icon → select API Keys.
3. Create new key → Click Create API Key, name it, and confirm.
4. Copy and store → Copy the key securely (it won’t be shown again).

## Basic Usage

```bash
# Standard security analysis
python -m securecodeai.cli.main scan src/

# With AI enhancement (requires GROQ_API_KEY environment variable)
export GROQ_API_KEY="your_key_here"
python -m securecodeai.cli.main scan src/ -f json -o results.json
```

## Testing

Run the included integration tests to see the system in action:

```bash

# Test 1: Complete vulnerability integration (focus-based chunking)
python test_integrated_vulnerabilities.py  

# Test 2: Realistic enterprise scenarios
python test_realistic_scenario.py
```

## Expected Results

**Static Analysis Performance:**
- 30-40 security findings on enterprise codebases
- Support for 8+ vulnerability types (SQL injection, cryptographic issues, etc.)
- Multi-tool integration with deduplication

**Intelligent Chunking:**
- 4-11 security-focused chunks per file
- 1000-6000 tokens processed per file
- Focus-based strategy prioritizes critical vulnerabilities
- 15x+ cache performance improvement

**AI Enhancement:**
- 1000-1500 tokens consumed per analysis
- Structured remediation advice for high-confidence findings
- Model: llama3-70b-8192 via GROQ API

## Architecture

```
src/securecodeai/
├── core/
│   ├── analyzer.py           # Main analysis orchestrator
│   ├── config.py            # Configuration management
│   └── models.py            # Pydantic data models
├── static_analysis/
│   ├── bandit_analyzer.py   # Bandit integration
│   ├── semgrep_analyzer.py  # Semgrep integration
│   ├── safety_analyzer.py   # Safety integration
│   └── orchestrator.py      # Multi-tool coordination
├── chunking/
│   ├── orchestrator.py      # Chunking coordination
│   ├── strategies/          # 5 chunking strategies
│   ├── parsers/            # Tree-sitter AST parsers
│   ├── cache.py            # Production LRU caching
│   └── utils/              # Token counting, metrics
├── llm/
│   └── groq_client.py       # GROQ API integration
└── cli/
    └── main.py              # Command-line interface
```

## Development

```bash
# Development setup
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Run tests
python -m pytest

# Run integration tests
python test_integrated_vulnerabilities.py
python test_realistic_scenario.py
```

## Current Capabilities

**Tested on real codebases:**
- Analyzes 800+ line enterprise applications
- Detects 37 security findings across 7 vulnerability categories  
- Generates 4 security-focused chunks in 33ms processing time
- Integrates seamlessly with existing CI/CD workflows
- Caching and error handling

**Architecture highlights:**
- Modular design with pluggable analyzers
- Async processing with rate limiting
- Comprehensive error handling and logging
- Prometheus metrics integration ready
- Multi-language AST parsing support


#### Note
This project is in active development and some of the tests contain real vurnabilities so please take caution when you work and test.
Please leave a star if you like the project!

Thanks for checking it out 💚