# SecureCodeAI

**Security analysis tool combining multi-tool static analysis with AI-powered enhancement.**

Heyy!  

This project was inspired by [claude-code-security](https://github.com/anthropics/claude-code-security-review) and [llm-security-scanner](https://github.com/iknowjason/llm-security-scanner), which both do a great job performing context-aware security scans on PR changes.  

I felt they miss some core points:  

- **PR-only analysis**: Focusing only on PR changes may overlook security issues, especially when dependencies are involved.  
- **Context window limits**: Feeding all code into an LLM reduces accuracy as context grows ([context rot](https://research.trychroma.com/context-rot)).  
- **Ground truth support**: Small filtering works, but without solid ground truth, LLM outputs are hard to fully trust.  
- **Cost**: Large codebases and chunking increase token usage and price.  

### Approach

To address this, I started with the hypothesis of combining **static tools** (like Bandit, Safety) with **LLM analysis** in a well-designed context. So far:  

- Implemented static tool scanning + a simple Groq enhancer to expand context based on static analysis.
- Added 36+ vulnerability-specific prompts for detailed analysis with the high-level scanner and deep analyzer.  
- Developing a **two-level LLM scanning approach**:
  1. **High-level scanner**: Takes static analysis, uses prompt templates to detect potential issues, scores severity and decides whether it's (simple and provide suggestion, or detailed analysis).  
  2. **Deep analyzer**: Gathers all evidence (code chunk, templates, suspected issues) and reasons to provide detailed suggestions.  

This approach reduces token usage, improves context awareness, and defines ground rules for each security issue.  

This repo is under active change so shit might happen :)

## 🎯 What it  Delivers

A robust security analysis foundation with:
- **Multi-tool static analysis** (Bandit, SafetyFPR, Semgrep)
- **AI-powered finding enhancement** with Groq LLM integration
- **Comprehensive finding management** with deduplication and confidence scoring
- **Multiple output formats** (JSON, Table, SARIF ready)
- **Extensible plugin architecture** for future analysis tools

**validation(tested on our own codebase)**: Successfully detects 33+ security findings across 22 files, 3,271 lines of code. :) we need to work on security here too

## 🚀 Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/yeabwang/SecureCodeAI.git
cd SecureCodeAI
pip install -e .
```

### Basic Usage

```bash
# Analyze current directory
python -m securecodeai.cli.main scan .

# Analyze specific path with JSON output
python -m securecodeai.cli.main scan src/ -f json -o results.json

# Filter by severity
python -m securecodeai.cli.main scan src/ --severity-threshold high

# View available options
python -m securecodeai.cli.main scan --help
```

## Get Free Groq api key

1. Sign up / Log in → Go to https://console.groq.com and create an account or log in.
2. Access API Keys page → In the dashboard, click your profile icon → select API Keys.
3. Create new key → Click Create API Key, name it, and confirm.
4. Copy and store → Copy the key securely (it won’t be shown again).

### With LLM Enhancement

```bash
# Set up Groq API key
export GROQ_API_KEY="your_groq_api_key_here"

# Run analysis with AI enhancement (automatically enabled when API key is present)
python -m securecodeai.cli.main scan src/ -f table
```

## 🏗️ Architecture

### Core Components

```
src/securecodeai/
├── core/
│   ├── analyzer.py          # Main analysis orchestrator
│   ├── config.py           # YAML-based configuration system
│   └── models.py           # Pydantic data models (Finding, AnalysisResult)
├── static_analysis/
│   ├── base.py             # Abstract analyzer interface
│   ├── bandit_analyzer.py  # Bandit integration
│   ├── safety_analyzer.py  # Safety (dependency) integration  
│   ├── semgrep_analyzer.py # Semgrep integration
│   └── orchestrator.py     # Multi-tool coordination
├── llm/
│   └── groq_client.py      # Groq API client with rate limiting
├── cli/
│   └── main.py             # Click-based CLI interface
└── utils/
    └── output.py           # Output formatting utilities
```

### Data Models

**Finding**: Core vulnerability representation
```python
class Finding(BaseModel):
    id: str
    title: str
    description: str
    vulnerability_type: str
    severity: SeverityLevel  # low, medium, high, critical
    confidence: float        # 0.0-1.0
    location: Location
    source_tool: str
    remediation_advice: Optional[str]  # AI-generated
    fix_suggestion: Optional[str]      # AI-generated
```

**AnalysisResult**: Complete scan results
```python
class AnalysisResult(BaseModel):
    findings: List[Finding]
    total_files_analyzed: int
    total_lines_analyzed: int
    llm_tokens_used: int
    llm_requests_made: int
    # + summary statistics
```

## 🔧 Configuration

### YAML Configuration (optional)

```yaml
# securecodeai.yaml
static_analysis:
  bandit:
    enabled: true
    exclude_paths: ["tests/", "*.py"]
  safety:
    enabled: true
    check_environment: true
  semgrep:
    enabled: true

llm:
  provider: "groq"
  model: "llama3-70b-8192"
  max_tokens: 8192
  requests_per_minute: 30
  
output:
  format: "table"
  severity_threshold: "medium"
```

### Environment Variables

```bash
# Required for LLM enhancement
export GROQ_API_KEY="your_api_key"

# Optional configuration
export SECURECODEAI_CONFIG_PATH="/path/to/config.yaml"
export SECURECODEAI_LOG_LEVEL="INFO"
```

## 📊 Output Formats

### Table Format (Default)
```
SecureCodeAI Analysis Results
==================================================

Analysis completed in 15.2 seconds
Files analyzed: 22
Total findings: 2

Findings by Severity:
  High: 2

Detailed Findings:
--------------------

1. Bandit B324: hashlib
   Severity: HIGH
   Confidence: 0.90
   Location: src/securecodeai/static_analysis/orchestrator.py:156
   Description: Use of weak MD5 hash for security
   Remediation: Replace MD5 with SHA-256 for cryptographic security
```

### JSON Format
```json
{
  "findings": [
    {
      "id": "uuid",
      "title": "Bandit B324: hashlib", 
      "severity": "high",
      "confidence": 0.9,
      "location": {
        "file_path": "src/file.py",
        "start_line": 156
      },
      "remediation_advice": "Replace MD5 with SHA-256...",
      "fix_suggestion": "hashlib.sha256(data.encode()).hexdigest()"
    }
  ],
  "llm_tokens_used": 2319,
  "llm_requests_made": 8
}
```

## 🧪 Testing & Quality

### Running Tests

```bash
# All tests (29 tests)
python -m pytest

# With coverage
python -m pytest --cov=src/securecodeai

# Specific test categories
python -m pytest tests/test_llm.py          # LLM integration tests
python -m pytest tests/test_integration.py  # End-to-end tests
```

### Test Coverage
- **Overall**: 58% coverage
- **Core Models**: 95% coverage  
- **LLM Client**: 79% coverage
- **Configuration**: 74% coverage

## 🔍  Performance

**Validation Results** (scanning SecureCodeAI itself):
- ✅ **33 findings detected** across multiple vulnerability types
- ✅ **8 LLM-enhanced findings** with specific remediation advice
- ✅ **2,319 tokens processed** through AI enhancement
- ✅ **22 files analyzed** (3,271 lines of code)
- ✅ **Sub-15 second analysis time** for medium-sized projects

## 🛠️ Development

### Prerequisites
- Python 3.11+
- Git
- Optional: Groq API key for LLM features

### Development Setup

```bash
# Clone repository
git clone https://github.com/yeabwang/SecureCodeAI.git
cd SecureCodeAI

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
python -m pytest

# Run linting
ruff check src/
mypy src/
```

### Tool Integration Architecture

Each static analysis tool follows the `BaseStaticAnalyzer` interface:

```python
class BaseStaticAnalyzer(ABC):
    @abstractmethod
    def is_available(self) -> bool:
        """Check if tool is installed and accessible."""
        
    @abstractmethod  
    def analyze_path(self, path: Path) -> List[Finding]:
        """Analyze a file or directory path."""
```
