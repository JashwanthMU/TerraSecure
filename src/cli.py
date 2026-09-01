import click
import json
import sys
import os
from colorama import init, Fore, Style
from scanner.analyzer import SecurityAnalyzer

# Initialize colorama
init(autoreset=True)

# Version
__version__ = "2.1.0"

VALID_CLOUDS = {'aws', 'azure', 'gcp'}


def print_version(ctx, param, value):
    """Eager callback so --version works without requiring PATH — Click
    validates required arguments during parsing, before a normal option's
    effect runs in the command body, so --version has to short-circuit
    before that happens."""
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"TerraSecure v{__version__}")
    ctx.exit()


@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--format', type=click.Choice(['text', 'json', 'sarif']), default='text',
              help='Output format (text, json, or sarif)')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'any']),
              default='critical',
              help='Exit with error code on severity level')
@click.option('--output', type=click.Path(), default=None,
              help='Save results to file')
@click.option('--cloud', default=None,
              help='Comma-separated list of clouds to scan: aws,azure,gcp (default: all detected)')
@click.option('--version', is_flag=True, expose_value=False, is_eager=True,
              callback=print_version, help='Show version and exit')
def scan(path, format, fail_on, output, cloud):
    """TerraSecure - Multi-Cloud AI-Powered Terraform Security Scanner

    Scans Terraform (.tf) files or directories for security
    misconfigurations across AWS, Azure, and GCP.
    """

    # Parse and validate --cloud filter
    providers = None
    if cloud:
        requested = {c.strip().lower() for c in cloud.split(',') if c.strip()}
        invalid = requested - VALID_CLOUDS
        if invalid:
            click.echo(f" Error: unknown cloud(s): {', '.join(sorted(invalid))}. "
                       f"Valid options: {', '.join(sorted(VALID_CLOUDS))}", err=True)
            sys.exit(1)
        providers = requested

    # Print banner for text output
    if format == 'text':
        print_banner()

    # Initialize analyzer
    analyzer = SecurityAnalyzer()

    # Scan path
    if os.path.isfile(path):
        results = analyzer.scan_file(path, providers=providers)
    else:
        results = analyzer.scan_directory(path, providers=providers)

    # Output based on format
    if format == 'sarif':
        output_sarif(results, path, output)
    elif format == 'json':
        output_json(results, output)
    else:
        output_text(results, output)

    # Determine exit code
    exit_code = get_exit_code(results, fail_on)

    sys.exit(exit_code)


def print_banner():
    """Print CLI banner"""
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                     TerraSecure                            ║
║       Multi-Cloud AI-Powered Terraform Security Scanner    ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def _format_ml_line(issue):
    """Build the ML risk line. Every issue carries ml_risk_score/
    ml_confidence now (analyzer attaches a placeholder for providers ML
    doesn't support), but a placeholder isn't a real score — show it
    plainly as not-applicable rather than a misleading percentage."""
    if issue.get('ml_prediction') == 'N/A':
        return "   ML: N/A (rule-based finding — ML scoring is AWS-only today)"
    if 'ml_risk_score' not in issue:
        return None
    risk = issue.get('ml_risk_score', 0.0)
    confidence = issue.get('ml_confidence', 0.0)
    ml_risk_color = Fore.RED if risk > 0.7 else Fore.YELLOW if risk > 0.4 else Fore.GREEN
    return f"   ML Risk: {ml_risk_color}{risk:.0%}{Style.RESET_ALL} | Confidence: {confidence:.0%}"


def output_text(results, output_file=None):
    """Output results in human-readable text format with LLM insights"""

    stats = results['stats']
    issues = results['issues']
    cloud_breakdown = results.get('cloud_breakdown', {})

    print(f"\n{Fore.CYAN}Scan Summary{Style.RESET_ALL}")
    print(f"{'='*60}")
    print(f"Total Resources Scanned: {results['total_resources']}")
    print(f"Resources Passed: {Fore.GREEN}{results['passed']}{Style.RESET_ALL}")
    print(f"Issues Found: {Fore.RED}{len(issues)}{Style.RESET_ALL}")
    if results.get('skipped_unknown_provider'):
        print(f"Skipped (unrecognized provider): {results['skipped_unknown_provider']}")
    if results.get('skipped_filtered_provider'):
        print(f"Skipped (excluded by --cloud): {results['skipped_filtered_provider']}")
    print()

    if cloud_breakdown:
        print(f"{Fore.CYAN}By Cloud:{Style.RESET_ALL}")
        for c in sorted(cloud_breakdown.keys()):
            print(f"  {c.upper():<6} {cloud_breakdown[c]}")
        print()

    print(f"{Fore.CYAN}Severity Breakdown:{Style.RESET_ALL}")
    print(f"  Critical: {Fore.RED}{stats['CRITICAL']}{Style.RESET_ALL}")
    print(f"  High:     {Fore.YELLOW}{stats['HIGH']}{Style.RESET_ALL}")
    print(f"  Medium:   {Fore.BLUE}{stats['MEDIUM']}{Style.RESET_ALL}")
    print(f"  Low:      {Fore.GREEN}{stats['LOW']}{Style.RESET_ALL}")
    print()

    if issues:
        print(f"{Fore.CYAN} Detailed Findings{Style.RESET_ALL}")
        print(f"{'='*60}\n")

        for i, issue in enumerate(issues, 1):
            severity_color = get_severity_color(issue['severity'])
            cloud_label = issue.get('cloud', 'unknown').upper()

            print(f"{severity_color}[{issue['severity']}] [{cloud_label}] {issue['message']}{Style.RESET_ALL}")
            print(f"   Resource: {issue['resource_type']}.{issue['resource_name']}")
            print(f"   File: {issue['file']}")

            ml_line = _format_ml_line(issue)
            if ml_line:
                print(ml_line)

            triggered = issue.get('triggered_features')
            if triggered:
                features_display = ', '.join(triggered[:3])
                if len(triggered) > 3:
                    features_display += f" (+{len(triggered)-3} more)"
                print(f"    Triggered: {features_display}")

            has_llm = 'llm_explanation' in issue and issue['llm_explanation']

            if has_llm:
                print(f"\n  {Fore.CYAN}━━━  AI-Enhanced Analysis ━━━{Style.RESET_ALL}")

                if issue.get('llm_explanation'):
                    print(f"\n  {Fore.WHITE} Explanation:{Style.RESET_ALL}")
                    print(f"     {issue['llm_explanation']}")

                if issue.get('llm_business_impact'):
                    print(f"\n  {Fore.YELLOW} Business Impact:{Style.RESET_ALL}")
                    print(f"     {issue['llm_business_impact']}")

                if issue.get('llm_attack_scenario'):
                    print(f"\n  {Fore.RED} Attack Scenario:{Style.RESET_ALL}")
                    print(f"     {issue['llm_attack_scenario']}")

                if issue.get('llm_detailed_fix'):
                    print(f"\n  {Fore.GREEN} Detailed Fix:{Style.RESET_ALL}")
                    fix_lines = issue['llm_detailed_fix'].split('\n')
                    for line in fix_lines:
                        if line.strip():
                            print(f"     {line}")
            else:
                # 'fix' was never actually populated by any rule engine —
                # they emit 'remediation'. Fall back through both so this
                # branch doesn't KeyError.
                remediation = issue.get('fix') or issue.get('remediation', 'Review and remediate this finding.')
                print(f"\n  Fix: {Fore.GREEN}{remediation}{Style.RESET_ALL}")

            print()
    else:
        print(f"{Fore.GREEN} No security issues found!{Style.RESET_ALL}")

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"TerraSecure Scan Results\n")
            f.write(f"{'='*60}\n\n")

            for issue in issues:
                cloud_label = issue.get('cloud', 'unknown').upper()
                f.write(f"[{issue['severity']}] [{cloud_label}] {issue['message']}\n")
                f.write(f"  Resource: {issue['resource_type']}.{issue['resource_name']}\n")
                f.write(f"  File: {issue['file']}\n")
                if 'ml_risk_score' in issue and issue.get('ml_prediction') != 'N/A':
                    f.write(f"  ML Risk: {issue['ml_risk_score']:.0%}\n")

                if issue.get('llm_explanation'):
                    f.write(f"\n  AI Explanation: {issue['llm_explanation']}\n")
                if issue.get('llm_business_impact'):
                    f.write(f"  Business Impact: {issue['llm_business_impact']}\n")
                if issue.get('llm_detailed_fix'):
                    f.write(f"  Detailed Fix: {issue['llm_detailed_fix']}\n")
                elif issue.get('remediation'):
                    f.write(f"  Fix: {issue['remediation']}\n")

                f.write('\n' + '-'*60 + '\n\n')

        print(f"{Fore.CYAN} Results saved to: {output_file}{Style.RESET_ALL}")


def output_json(results, output_file=None):
    """Output results in JSON format"""

    json_output = json.dumps(results, indent=2)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_output)
        print(f" Results saved to: {output_file}")
    else:
        print(json_output)


def output_sarif(results, scan_path, output_file=None):
    """
    Output results in SARIF format for GitHub Security integration

    Args:
        results: Scan results from SecurityAnalyzer
        scan_path: Path that was scanned
        output_file: Optional output file path
    """
    try:
        # Import SARIF formatter
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from src.formatters.sarif_formatter import SARIFFormatter
    except ImportError:
        try:
            from formatters.sarif_formatter import SARIFFormatter
        except ImportError:
            click.echo(" Error: SARIF formatter not found", err=True)
            click.echo("   Make sure src/formatters/sarif_formatter.py exists", err=True)
            sys.exit(1)

    # Convert issues to SARIF compatible format
    findings = []

    for issue in results.get('issues', []):
        finding = {
            'rule_id': issue.get('rule_id', 'TERRAFORM-SECURITY'),
            'title': issue.get('message', 'Security issue detected'),
            'description': issue.get('llm_explanation', issue.get('message', '')),
            'severity': issue.get('severity', 'medium').lower(),
            'file': issue.get('file', 'unknown'),
            'line': issue.get('line', 1),
            'resource': f"{issue.get('resource_type', 'unknown')}.{issue.get('resource_name', 'unknown')}",
            # Was missing entirely before — the SARIF formatter's cloud
            # tagging is a no-op without this key making it through.
            'cloud': issue.get('cloud', 'unknown'),
        }

        # Only attach ML fields to SARIF when ML actually ran (AWS-only
        # today). The issue dict always carries a placeholder now (for
        # schema consistency in tests/JSON output), but SARIF is
        # consumed by tools that will treat any numeric score as real —
        # don't forward the 'N/A' placeholder as if it were one.
        if 'ml_risk_score' in issue and issue.get('ml_prediction') != 'N/A':
            finding['ml_risk_score'] = issue['ml_risk_score']
            finding['ml_confidence'] = issue.get('ml_confidence', 0.0)

        # Add remediation if available
        if issue.get('llm_detailed_fix'):
            finding['remediation'] = issue['llm_detailed_fix']
        elif issue.get('remediation'):
            finding['remediation'] = issue['remediation']
        elif issue.get('fix'):
            finding['remediation'] = issue['fix']

        # Add references if available
        references = []
        if issue.get('llm_business_impact'):
            references.append(f"Business Impact: {issue['llm_business_impact'][:100]}")
        if issue.get('llm_attack_scenario'):
            references.append(f"Attack Scenario: {issue['llm_attack_scenario'][:100]}")

        if references:
            finding['references'] = references

        findings.append(finding)

    # Generate SARIF
    formatter = SARIFFormatter(tool_name="TerraSecure", tool_version=__version__)
    sarif_output = formatter.format(findings, scan_path=scan_path)

    # Output
    sarif_json = json.dumps(sarif_output, indent=2)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(sarif_json)

        # Summary for console
        num_rules = len(sarif_output['runs'][0]['tool']['driver']['rules'])
        num_results = len(sarif_output['runs'][0]['results'])

        print(f"\n{Fore.CYAN} SARIF Output Generated{Style.RESET_ALL}")
        print(f"{'='*60}")
        print(f"Version:  SARIF 2.1.0")
        print(f"Rules:    {num_rules}")
        print(f"Results:  {num_results}")
        print(f"File:     {output_file}")
        print(f"\n{Fore.GREEN} Ready for GitHub Security upload{Style.RESET_ALL}")
        print(f"\n Tip: Upload this file to GitHub Security tab:")
        print(f"   gh api repos/${{OWNER}}/${{REPO}}/code-scanning/sarifs \\")
        print(f"     --input {output_file}")

    else:
        # Print to stdout
        print(sarif_json)


def get_severity_color(severity):
    """Get colorama color for severity"""
    colors = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.YELLOW,
        'MEDIUM': Fore.BLUE,
        'LOW': Fore.GREEN
    }
    return colors.get(severity, Fore.WHITE)


def get_exit_code(results, fail_on):
    """Determine exit code based on findings"""

    stats = results['stats']

    if fail_on == 'critical' and stats['CRITICAL'] > 0:
        return 2
    elif fail_on == 'high' and (stats['CRITICAL'] > 0 or stats['HIGH'] > 0):
        return 1
    elif fail_on == 'medium' and (stats['CRITICAL'] > 0 or stats['HIGH'] > 0 or stats['MEDIUM'] > 0):
        return 1
    elif fail_on == 'any' and len(results['issues']) > 0:
        return 1

    return 0


if __name__ == '__main__':
    scan()