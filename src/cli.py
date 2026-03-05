import click
import json
import sys
import os
from colorama import init, Fore, Style
from scanner.analyzer import SecurityAnalyzer


init(autoreset=True)

@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--format', type=click.Choice(['text', 'json']), default='text',
              help='Output format (text or json)')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'any']), 
              default='critical',
              help='Exit with error code on severity level')
@click.option('--output', type=click.Path(), default=None,
              help='Save results to file')
def scan(path, format, fail_on, output):
    """
    TerraSecure - Scan Terraform files for security issues
    
    Usage:
        terrasecure scan ./terraform
        terrasecure scan main.tf --format json
        terrasecure scan . --fail-on high
    """
    
    if format == 'text':
        print_banner()

    analyzer = SecurityAnalyzer()
    

    if os.path.isfile(path):
        results = analyzer.scan_file(path)
    else:
        results = analyzer.scan_directory(path)
    
    if format == 'json':
        output_json(results, output)
    else:
        output_text(results, output)

    exit_code = get_exit_code(results, fail_on)
    
    sys.exit(exit_code)

def print_banner():
    """Print CLI banner"""
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                     TerraSecure                            ║
║          AI-Powered Terraform Security Scanner             ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def output_text(results, output_file=None):
    """Output results in human-readable text format with LLM insights"""
    
    stats = results['stats']
    issues = results['issues']

    print(f"\n{Fore.CYAN}Scan Summary{Style.RESET_ALL}")
    print(f"{'='*60}")
    print(f"Total Resources Scanned: {results['total_resources']}")
    print(f"Resources Passed: {Fore.GREEN}{results['passed']}{Style.RESET_ALL}")
    print(f"Issues Found: {Fore.RED}{len(issues)}{Style.RESET_ALL}")
    print()

    print(f"{Fore.CYAN}Severity Breakdown:{Style.RESET_ALL}")
    print(f"  Critical: {Fore.RED}{stats['CRITICAL']}{Style.RESET_ALL}")
    print(f"  High:     {Fore.YELLOW}{stats['HIGH']}{Style.RESET_ALL}")
    print(f"  Medium:   {Fore.BLUE}{stats['MEDIUM']}{Style.RESET_ALL}")
    print()
    
    if issues:
        print(f"{Fore.CYAN} Detailed Findings (with AI Analysis){Style.RESET_ALL}")
        print(f"{'='*60}\n")
        
        for i, issue in enumerate(issues, 1):
            severity_color = get_severity_color(issue['severity'])
            
            print(f"{severity_color}[{issue['severity']}] {issue['message']}{Style.RESET_ALL}")
            print(f"   Resource: {issue['resource_type']}.{issue['resource_name']}")
            print(f"   File: {issue['file']}")
            
            ml_risk_color = Fore.RED if issue['ml_risk_score'] > 0.7 else Fore.YELLOW if issue['ml_risk_score'] > 0.4 else Fore.GREEN
            print(f"   ML Risk: {ml_risk_color}{issue['ml_risk_score']:.0%}{Style.RESET_ALL} | Confidence: {issue['ml_confidence']:.0%}")
            
            if issue['triggered_features']:
                features_display = ', '.join(issue['triggered_features'][:3])
                if len(issue['triggered_features']) > 3:
                    features_display += f" (+{len(issue['triggered_features'])-3} more)"
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
                    print(f"\n  {Fore.RED}  Attack Scenario:{Style.RESET_ALL}")
                    print(f"     {issue['llm_attack_scenario']}")
                
                
                if issue.get('llm_detailed_fix'):
                    print(f"\n  {Fore.GREEN} Detailed Fix:{Style.RESET_ALL}")
                    
                    fix_lines = issue['llm_detailed_fix'].split('\n')
                    for line in fix_lines:
                        if line.strip():
                            print(f"     {line}")
                
                
            else:
                print(f"\n  Fix: {Fore.GREEN}{issue['fix']}{Style.RESET_ALL}")
            
            print()  
    else:
        print(f"{Fore.GREEN} No security issues found!{Style.RESET_ALL}")
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"TerraSecure Scan Results (with AI Analysis)\n")
            f.write(f"{'='*60}\n\n")
            
            for issue in issues:
                f.write(f"[{issue['severity']}] {issue['message']}\n")
                f.write(f"  Resource: {issue['resource_type']}.{issue['resource_name']}\n")
                f.write(f"  File: {issue['file']}\n")
                f.write(f"  ML Risk: {issue['ml_risk_score']:.0%}\n")
                
                if issue.get('llm_explanation'):
                    f.write(f"\n  AI Explanation: {issue['llm_explanation']}\n")
                if issue.get('llm_business_impact'):
                    f.write(f"  Business Impact: {issue['llm_business_impact']}\n")
                if issue.get('llm_detailed_fix'):
                    f.write(f"  Detailed Fix: {issue['llm_detailed_fix']}\n")
                
                f.write('\n' + '-'*60 + '\n\n')
        
        print(f"{Fore.CYAN} Results saved to: {output_file}{Style.RESET_ALL}")
def output_json(results, output_file=None):
    """Output results in JSON format"""
    
    json_output = json.dumps(results, indent=2)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(json_output)
        print(f"Results saved to: {output_file}")
    else:
        print(json_output)

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