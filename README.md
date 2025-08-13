# SecureCodeAI

AI-powered security analysis tool with static analysis and LLM integration.

## Features

- **Multi-layered Analysis**: Combines static analysis tools (bandit, safety, semgrep) with LLM intelligence
- **Anti-hallucination Framework**: Multiple validation layers to ensure accuracy
- **Git Integration**: Seamless integration with Git workflows and CI/CD pipelines
- **Multiple Output Formats**: JSON, SARIF, HTML, and more
- **Configurable Rules**: Customizable security policies and thresholds

## Installation

```bash
pip install -e .
```

For development:
```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# Analyze current directory
securecodeai scan

# Analyze specific files
securecodeai scan src/

# Generate detailed report
securecodeai scan --format html --output report.html
```

## Development

This project is structured as follows:

```
src/securecodeai/
├── core/           # Core data models and configuration
├── static_analysis/ # Static analysis tool integrations
├── llm/            # LLM integration and prompt management
├── utils/          # Utility functions and helpers
└── cli/            # Command-line interface
```

## Contributing

This project follows a PR-based development workflow. Each major feature is developed in a separate branch and merged via pull request.

## License

MIT License - see LICENSE file for details.
