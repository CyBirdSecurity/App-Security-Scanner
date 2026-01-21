# Claude Code Security Scanner

An AI-powered comprehensive security scanner GitHub Action using Claude to analyze entire application codebases for security vulnerabilities. This action provides intelligent, context-aware security analysis for complete repositories using Anthropic's Claude Code tool for deep semantic security analysis.

## Features

- **AI-Powered Analysis**: Uses Claude's advanced reasoning to detect security vulnerabilities with deep semantic understanding
- **Comprehensive Scanning**: Analyzes entire application codebases for complete security coverage
- **GitHub Code Scanning Integration**: Automatically uploads findings to GitHub's Security tab as Code Scanning alerts
- **Contextual Understanding**: Goes beyond pattern matching to understand code semantics  
- **Language Agnostic**: Works with any programming language
- **False Positive Filtering**: Advanced filtering to reduce noise and focus on real vulnerabilities
- **GraphQL Security**: Enhanced detection of GraphQL authorization vulnerabilities
- **Critical Severity Support**: Special handling for urgent sensitive data disclosure issues

## Quick Start

Add this to your repository's `.github/workflows/security.yml`:

```yaml
name: Weekly Security Scan

permissions:
  security-events: write  # Needed for uploading SARIF to Code Scanning
  contents: read
  actions: read

on:
  schedule:
    - cron: '0 6 * * 1'  # Run every Monday at 6 AM UTC
  workflow_dispatch:  # Allow manual triggering

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:      
      - uses: CyBirdSecurity/Claude-Security-Scanner@main
        with:
          upload-sarif: true
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
```

## Security Considerations

This action scans your entire codebase and should only be used in trusted repositories. The scanner requires read access to your repository contents and write access to security events for SARIF upload. Ensure your `CLAUDE_API_KEY` is stored securely in GitHub Secrets.

## Configuration Options

### Action Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `claude-api-key` | Anthropic Claude API key for security analysis. <br>*Note*: This API key needs to be enabled for both the Claude API and Claude Code usage. | None | Yes |
| `upload-sarif` | Whether to upload SARIF results to GitHub Code Scanning | `true` | No |
| `upload-results` | Whether to upload results as artifacts | `true` | No |
| `branch` | Branch to scan (defaults to repository default branch) | repository default | No |
| `exclude-directories` | Comma-separated list of directories to exclude from scanning | None | No |
| `claude-model` | Claude [model name](https://docs.anthropic.com/en/docs/about-claude/models/overview#model-names) to use. Defaults to latest Sonnet 4.5. | `claude-sonnet-4-5` | No |
| `claudecode-timeout` | Timeout for ClaudeCode analysis in minutes | `20` | No |
| `false-positive-filtering-instructions` | Path to custom false positive filtering instructions text file | None | No |
| `custom-security-scan-instructions` | Path to custom security scan instructions text file to append to audit prompt | None | No |

### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of security findings |
| `results-file` | Path to the results JSON file |

## How It Works

### Architecture

```
claudecode/
├── github_action_audit.py  # Main audit script for GitHub Actions
├── prompts.py              # Security audit prompt templates
├── findings_filter.py      # False positive filtering logic
├── claude_api_client.py    # Claude API client for false positive filtering
├── json_parser.py          # Robust JSON parsing utilities
├── requirements.txt        # Python dependencies
├── test_*.py               # Test suites
└── evals/                  # Eval tooling to test CC on arbitrary PRs
```

### Workflow

1. **Repository Analysis**: On a scheduled basis, Claude performs a comprehensive scan of the entire application codebase
2. **Deep Security Review**: Claude systematically examines all source code files for security vulnerabilities using advanced reasoning
3. **Finding Generation**: Security issues are identified with detailed explanations, severity ratings, and remediation guidance
4. **False Positive Filtering**: Advanced filtering removes low-impact or false positive prone findings to reduce noise
5. **Code Scanning Integration**: Findings are uploaded as SARIF to GitHub's Security tab for centralized vulnerability management

## Security Analysis Capabilities

### Types of Vulnerabilities Detected

- **Injection Attacks**: SQL injection, command injection, LDAP injection, XPath injection, NoSQL injection, XXE
- **Authentication & Authorization**: Broken authentication, privilege escalation, insecure direct object references, bypass logic, session flaws
- **Data Exposure**: Hardcoded secrets, sensitive data logging, information disclosure, PII handling violations
- **Cryptographic Issues**: Weak algorithms, improper key management, insecure random number generation
- **Input Validation**: Missing validation, improper sanitization, buffer overflows
- **Business Logic Flaws**: Race conditions, time-of-check-time-of-use (TOCTOU) issues
- **Configuration Security**: Insecure defaults, missing security headers, permissive CORS
- **Supply Chain**: Vulnerable dependencies, typosquatting risks
- **Code Execution**: RCE via deserialization, pickle injection, eval injection
- **Cross-Site Scripting (XSS)**: Reflected, stored, and DOM-based XSS

### False Positive Filtering

The tool automatically excludes a variety of low-impact and false positive prone findings to focus on high-impact vulnerabilities:
- Denial of Service vulnerabilities
- Rate limiting concerns
- Memory/CPU exhaustion issues
- Generic input validation without proven impact
- Open redirect vulnerabilities

The false positive filtering can also be tuned as needed for a given project's security goals.

### Benefits Over Traditional SAST

- **Contextual Understanding**: Understands code semantics and intent, not just patterns
- **Lower False Positives**: AI-powered analysis reduces noise by understanding when code is actually vulnerable
- **Detailed Explanations**: Provides clear explanations of why something is a vulnerability and how to fix it
- **Adaptive Learning**: Can be customized with organization-specific security requirements

## Installation & Setup

### GitHub Actions

Follow the Quick Start guide above. The action handles all dependencies automatically.

### GitHub Code Scanning Integration

The scanner automatically integrates with GitHub's Code Scanning feature by generating and uploading SARIF (Static Analysis Results Interchange Format) files. When `upload-sarif` is enabled (default), security findings will appear in your repository's **Security** tab under **Code scanning alerts**.

**Benefits of Code Scanning Integration:**
- **Centralized Security Dashboard**: All security findings appear in GitHub's Security tab
- **Alert Management**: Mark findings as resolved, dismissed, or create issues directly from alerts
- **Pull Request Integration**: Code scanning alerts automatically appear on pull requests affecting the flagged code
- **Historical Tracking**: Track security improvements over time with trend analysis
- **Severity Filtering**: Filter alerts by Critical, High, Medium, and Low severity levels

**Accessing Your Security Alerts:**
1. Navigate to your repository on GitHub
2. Click the **Security** tab
3. Select **Code scanning alerts** to view all findings
4. Click on individual alerts for detailed remediation guidance

The scanner uses the "Claude-Security-Scanner" category in Code Scanning to distinguish its findings from other security tools.

### Local Development

To run the security scanner locally against a specific PR, see the [evaluation framework documentation](claudecode/evals/README.md).

<a id="security-review-slash-command"></a>

## Claude Code Integration: /security-review Command 

By default, Claude Code ships a `/security-review` [slash command](https://docs.anthropic.com/en/docs/claude-code/slash-commands) that provides the same security analysis capabilities as the GitHub Action workflow, but integrated directly into your Claude Code development environment. To use this, simply run `/security-review` to perform a comprehensive security review of all pending changes.

### Customizing the Command

The default `/security-review` command is designed to work well in most cases, but it can also be customized based on your specific security needs. To do so: 

1. Copy the [`security-review.md`](https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md?plain=1) file from this repository to your project's `.claude/commands/` folder. 
2. Edit `security-review.md` to customize the security analysis. For example, you could add additional organization-specific directions to the false positive filtering instructions. 

## Custom Scanning Configuration

It is also possible to configure custom scanning and false positive filtering instructions, see the [`docs/`](docs/) folder for more details.  

## Testing

Run the test suite to validate functionality:

```bash
cd claude-code-security-review
# Run all tests
pytest claudecode -v
```

## Support

For issues or questions:
- Open an issue in this repository
- Check the [GitHub Actions logs](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/viewing-workflow-run-history) for debugging information

## License

MIT License - see [LICENSE](LICENSE) file for details.
