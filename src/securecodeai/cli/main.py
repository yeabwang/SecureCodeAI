"""Command-line interface for SecureCodeAI."""

import click
import logging
import sys
from pathlib import Path
from typing import List, Optional

from ..core import Config, SecurityAnalyzer, ScanMode, SeverityLevel, OutputFormat
from ..utils.output import OutputFormatter


def setup_logging(verbose: bool, quiet: bool) -> None:
    """Setup logging configuration."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


@click.group()
@click.version_option(version='0.1.0')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--quiet', '-q', is_flag=True, help='Suppress output except errors')
@click.option('--config', '-c', type=click.Path(exists=True, path_type=Path), 
              help='Configuration file path')
@click.pass_context
def cli(ctx, verbose: bool, quiet: bool, config: Optional[Path]):
    """SecureCodeAI - AI-powered security analysis tool."""
    ctx.ensure_object(dict)
    
    # Setup logging
    setup_logging(verbose, quiet)
    
    # Load configuration
    if config:
        ctx.obj['config'] = Config.load_from_file(config)
    else:
        # Try to find config file automatically
        config_file = Config.find_config_file()
        if config_file:
            ctx.obj['config'] = Config.load_from_file(config_file)
        else:
            ctx.obj['config'] = Config.get_default_config()
    
    # Override config with CLI options
    if verbose:
        ctx.obj['config'].output.verbose = True
    if quiet:
        ctx.obj['config'].output.quiet = True


@cli.command()
@click.argument('paths', nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option('--mode', '-m', type=click.Choice(['full', 'fast', 'targeted']), 
              help='Scan mode')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['table', 'json', 'sarif', 'html']),
              help='Output format')
@click.option('--output', '-o', type=click.Path(path_type=Path), 
              help='Output file path')
@click.option('--severity-threshold', 
              type=click.Choice(['info', 'low', 'medium', 'high', 'critical']),
              help='Minimum severity level to report')
@click.option('--confidence-threshold', type=float, 
              help='Minimum confidence score (0.0-1.0)')
@click.option('--parallel-workers', type=int, 
              help='Number of parallel workers')
@click.pass_context
def scan(ctx, 
         paths: tuple[Path, ...], 
         mode: Optional[str],
         output_format: Optional[str],
         output: Optional[Path],
         severity_threshold: Optional[str],
         confidence_threshold: Optional[float],
         parallel_workers: Optional[int]):
    """Scan files or directories for security vulnerabilities."""
    
    # Get configuration
    config = ctx.obj['config']
    
    # Override config with CLI arguments
    cli_args = {
        'format': output_format,
        'output': output,
        'severity_threshold': severity_threshold,
        'confidence_threshold': confidence_threshold,
        'parallel_workers': parallel_workers,
    }
    config = config.merge_with_cli_args(**{k: v for k, v in cli_args.items() if v is not None})
    
    # Default to current directory if no paths provided
    target_paths: List[Path]
    if not paths:
        target_paths = [Path.cwd()]
    else:
        target_paths = list(paths)
    
    # Convert mode string to enum
    scan_mode = None
    if mode:
        scan_mode = ScanMode(mode)
    
    try:
        # Create analyzer
        analyzer = SecurityAnalyzer(config)
        
        # Show analyzer info if verbose
        if config.output.verbose:
            click.echo("Analyzer Configuration:")
            info = analyzer.get_analyzer_info()
            for tool, details in info['static_analysis'].items():
                click.echo(f"  {tool}: {details['version']} ({'available' if details['available'] else 'unavailable'})")
            click.echo(f"  LLM: {'enabled' if info['llm_enabled'] else 'disabled'}")
            click.echo()
        
        # Run analysis
        if not config.output.quiet:
            click.echo(f"Analyzing {len(target_paths)} path(s)...")
        
        result = analyzer.analyze(target_paths, mode=scan_mode)
        
        # Format and output results
        formatter = OutputFormatter(config.output)
        output_text = formatter.format_result(result)
        
        if config.output.output_file:
            config.output.output_file.write_text(output_text, encoding='utf-8')
            if not config.output.quiet:
                click.echo(f"Results written to {config.output.output_file}")
        else:
            click.echo(output_text)
        
        # Exit with error code if high-severity issues found
        high_severity_count = (
            result.findings_by_severity.get(SeverityLevel.CRITICAL, 0) +
            result.findings_by_severity.get(SeverityLevel.HIGH, 0)
        )
        
        if high_severity_count > 0:
            sys.exit(1)
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if config.output.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.pass_context
def info(ctx):
    """Show information about the analyzer and its components."""
    config = ctx.obj['config']
    
    try:
        analyzer = SecurityAnalyzer(config)
        info = analyzer.get_analyzer_info()
        
        click.echo("SecureCodeAI Analyzer Information")
        click.echo("=" * 40)
        
        click.echo("\nStatic Analysis Tools:")
        for tool, details in info['static_analysis'].items():
            status = "✓" if details['available'] else "✗"
            click.echo(f"  {status} {tool.capitalize()}: {details['version']}")
            if details['supported_extensions']:
                click.echo(f"    Extensions: {details['supported_extensions']}")
        
        click.echo(f"\nLLM Integration: {'✓ Enabled' if info['llm_enabled'] else '✗ Disabled'}")
        
        if info['llm_enabled'] and 'llm_stats' in info:
            stats = info['llm_stats']
            click.echo(f"  Model: {stats['model']}")
            click.echo(f"  Usage: {stats['requests_last_minute']}/{stats['requests_per_minute_limit']} requests/min")
            click.echo(f"         {stats['tokens_last_minute']}/{stats['tokens_per_minute_limit']} tokens/min")
        
        click.echo(f"\nConfiguration:")
        click.echo(f"  Scan mode: {info['config']['scan_mode']}")
        click.echo(f"  Severity threshold: {info['config']['severity_threshold']}")
        click.echo(f"  Confidence threshold: {info['config']['confidence_threshold']}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.Path(path_type=Path), 
              default=Path('.securecodeai.yaml'),
              help='Output configuration file path')
@click.pass_context
def init(ctx, output: Path):
    """Initialize a new configuration file."""
    try:
        if output.exists():
            if not click.confirm(f"Configuration file {output} already exists. Overwrite?"):
                click.echo("Cancelled.")
                return
        
        # Create default configuration
        config = Config.get_default_config()
        
        # Save to file
        config.save_to_file(output)
        
        click.echo(f"Configuration file created: {output}")
        click.echo("Edit this file to customize your security analysis settings.")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
