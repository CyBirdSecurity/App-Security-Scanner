#!/usr/bin/env python3
"""
Simplified PR Security Audit for GitHub Actions
Runs Claude Code security audit on current working directory and outputs findings to stdout
"""

import os
import sys
import json
import subprocess
import requests
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import re
import time

# Import existing components we can reuse
from claudecode.prompts import get_security_audit_prompt
from claudecode.findings_filter import FindingsFilter
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.constants import (
    EXIT_CONFIGURATION_ERROR,
    DEFAULT_CLAUDE_MODEL,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT
)
from claudecode.logger import get_logger
from claudecode.sarif_utils import findings_to_sarif_string

logger = get_logger(__name__)

class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass

class AuditError(ValueError):
    """Raised when security audit operations fail."""
    pass

class GitHubActionClient:
    """Simplified GitHub API client for GitHub Actions environment."""
    
    def __init__(self):
        """Initialize GitHub client using environment variables."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable required")
            
        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        # Get excluded directories from environment
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        self.excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []
        if self.excluded_dirs:
            print(f"[Debug] Excluded directories: {self.excluded_dirs}", file=sys.stderr)

    def get_pr_data(self, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Get PR metadata and files from GitHub API."""
        pr_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        response = requests.get(pr_url, headers=self.headers)
        response.raise_for_status()
        pr_data = response.json()

        files_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files?per_page=100"
        response = requests.get(files_url, headers=self.headers)
        response.raise_for_status()
        files_data = response.json()

        return {
            'number': pr_data['number'],
            'title': pr_data['title'],
            'body': pr_data.get('body', ''),
            'user': pr_data['user']['login'],
            'created_at': pr_data['created_at'],
            'updated_at': pr_data['updated_at'],
            'state': pr_data['state'],
            'head': {
                'ref': pr_data['head']['ref'],
                'sha': pr_data['head']['sha'],
                'repo': {
                    'full_name': pr_data['head']['repo']['full_name'] if pr_data['head']['repo'] else repo_name
                }
            },
            'base': {
                'ref': pr_data['base']['ref'],
                'sha': pr_data['base']['sha']
            },
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f['additions'],
                    'deletions': f['deletions'],
                    'changes': f['changes'],
                    'patch': f.get('patch', '')
                }
                for f in files_data
                if not self._is_excluded(f['filename'])
            ],
            'additions': pr_data['additions'],
            'deletions': pr_data['deletions'],
            'changed_files': pr_data['changed_files']
        }

    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get complete PR diff in unified format."""
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        headers = dict(self.headers)
        headers['Accept'] = 'application/vnd.github.diff'

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        return self._filter_generated_files(response.text)

    def _is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory patterns."""
        for excluded_dir in self.excluded_dirs:
            if excluded_dir.startswith('./'):
                normalized_excluded = excluded_dir[2:]
            else:
                normalized_excluded = excluded_dir

            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True
            if '/' + normalized_excluded + '/' in filepath:
                return True

        return False

    def _filter_generated_files(self, diff_text: str) -> str:
        """Filter out generated files and excluded directories from diff content."""
        file_sections = re.split(r'(?=^diff --git)', diff_text, flags=re.MULTILINE)
        filtered_sections = []

        for section in file_sections:
            if not section.strip():
                continue

            if ('@generated by' in section or
                '@generated' in section or
                'Code generated by OpenAPI Generator' in section or
                'Code generated by protoc-gen-go' in section):
                continue

            match = re.match(r'^diff --git a/(.*?) b/', section)
            if match:
                filename = match.group(1)
                if self._is_excluded(filename):
                    print(f"[Debug] Filtering out excluded file: {filename}", file=sys.stderr)
                    continue

            filtered_sections.append(section)

        return ''.join(filtered_sections)

    def upload_sarif(self, repo_name: str, sarif_str: str, commit_sha: str, ref: str, tool_name: str = "Claude Code Security Reviewer") -> Dict[str, Any]:
        """
        Upload SARIF to GitHub Code Scanning SARIF ingestion API.

        Endpoint: POST /repos/{owner}/{repo}/code-scanning/sarifs
        The token must have permission to upload code-scanning results (security_events: write).
        """
        url = f"https://api.github.com/repos/{repo_name}/code-scanning/sarifs"
        payload = {
            "commit_sha": commit_sha,
            "ref": ref,
            "sarif": sarif_str,
            "tool_name": tool_name
        }
        headers = dict(self.headers)
        # GitHub recommends application/vnd.github+json
        headers['Accept'] = 'application/vnd.github+json'
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()


class SimpleClaudeRunner:
    """Simplified Claude Code runner for GitHub Actions."""
    
    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize Claude runner."""
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT

    def run_security_audit(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run Claude Code security audit."""
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}

        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)

        try:
            cmd = [
                'claude',
                '--output-format', 'json',
                '--model', DEFAULT_CLAUDE_MODEL,
                '--disallowed-tools', 'Bash(ps:*)'
            ]

            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                result = subprocess.run(
                    cmd,
                    input=prompt,
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds
                )

                if result.returncode != 0:
                    if attempt == NUM_RETRIES - 1:
                        error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."
                        return False, error_details, {}
                    else:
                        time.sleep(5*attempt)
                        continue

                success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")

                if success:
                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'success' and
                        parsed_result.get('is_error') and
                        parsed_result.get('result') == 'Prompt is too long'):
                        return False, "PROMPT_TOO_LONG", {}

                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'error_during_execution' and
                        attempt == 0):
                        continue

                    parsed_results = self._extract_security_findings(parsed_result)
                    return True, "", parsed_results
                else:
                    if attempt == 0:
                        continue
                    else:
                        return False, "Failed to parse Claude output", {}

            return False, "Unexpected error in retry logic", {}

        except subprocess.TimeoutExpired:
            return False, f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Claude Code execution error: {str(e)}", {}

    def _extract_security_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract security findings from Claude's JSON response."""
        if isinstance(claude_output, dict):
            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    success, result_json = parse_json_with_fallbacks(result_text, "Claude result text")
                    if success and result_json and 'findings' in result_json:
                        return result_json

        return {
            'findings': [],
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            }
        }

    def validate_claude_available(self) -> Tuple[bool, str]:
        """Validate that Claude Code is available."""
        try:
            result = subprocess.run(
                ['claude', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                api_key = os.environ.get('ANTHROPIC_API_KEY', '')
                if not api_key:
                    return False, "ANTHROPIC_API_KEY environment variable is not set"
                return True, ""
            else:
                error_msg = f"Claude Code returned exit code {result.returncode}"
                if result.stderr:
                    error_msg += f". Stderr: {result.stderr}"
                if result.stdout:
                    error_msg += f". Stdout: {result.stdout}"
                return False, error_msg

        except subprocess.TimeoutExpired:
            return False, "Claude Code command timed out"
        except FileNotFoundError:
            return False, "Claude Code is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check Claude Code: {str(e)}"


def get_environment_config() -> Tuple[str, int]:
    """Get and validate environment configuration."""
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')

    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')

    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')

    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')
        
    return repo_name, pr_number


def initialize_clients() -> Tuple[GitHubActionClient, SimpleClaudeRunner]:
    """Initialize GitHub and Claude clients."""
    try:
        github_client = GitHubActionClient()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize GitHub client: {str(e)}')

    try:
        claude_runner = SimpleClaudeRunner()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize Claude runner: {str(e)}')

    return github_client, claude_runner


def initialize_findings_filter(custom_filtering_instructions: Optional[str] = None) -> FindingsFilter:
    """Initialize findings filter based on environment configuration."""
    try:
        use_claude_filtering = os.environ.get('ENABLE_CLAUDE_FILTERING', 'false').lower() == 'true'
        api_key = os.environ.get('ANTHROPIC_API_KEY')

        if use_claude_filtering and api_key:
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=False
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')


def run_security_audit(claude_runner: SimpleClaudeRunner, prompt: str) -> Dict[str, Any]:
    """Run the security audit with Claude Code."""
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)

    if not success:
        raise AuditError(f'Security audit failed: {error_msg}')

    return results


def apply_findings_filter(findings_filter, original_findings: List[Dict[str, Any]], 
                         pr_context: Dict[str, Any], github_client: GitHubActionClient) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives."""
    filter_success, filter_results, filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )

    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}

    final_kept_findings = []
    directory_excluded_findings = []

    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)

    all_excluded_findings = excluded_findings + directory_excluded_findings
    analysis_summary['directory_excluded_count'] = len(directory_excluded_findings)

    return final_kept_findings, all_excluded_findings, analysis_summary


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: GitHubActionClient) -> bool:
    file_path = finding.get('file', '')
    if not file_path:
        return False

    return github_client._is_excluded(file_path)


def main():
    """Main execution function for GitHub Action."""
    try:
        try:
            repo_name, pr_number = get_environment_config()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)

        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
                    logger.info(f"Loaded custom filtering instructions from {filtering_file}")
            except Exception as e:
                logger.warning(f"Failed to read filtering instructions file {filtering_file}: {e}")

        custom_scan_instructions = None
        scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if scan_file and Path(scan_file).exists():
            try:
                with open(scan_file, 'r', encoding='utf-8') as f:
                    custom_scan_instructions = f.read()
                    logger.info(f"Loaded custom security scan instructions from {scan_file}")
            except Exception as e:
                logger.warning(f"Failed to read security scan instructions file {scan_file}: {e}")

        try:
            github_client, claude_runner = initialize_clients()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)

        try:
            findings_filter = initialize_findings_filter(custom_filtering_instructions)
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)

        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            print(json.dumps({'error': f'Claude Code not available: {claude_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except Exception as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        prompt = get_security_audit_prompt(pr_data, pr_diff, custom_scan_instructions=custom_scan_instructions)

        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt)

        if not success and error_msg == "PROMPT_TOO_LONG":
            print(f"[Info] Prompt too long, retrying without diff. Original prompt length: {len(prompt)} characters", file=sys.stderr)
            prompt_without_diff = get_security_audit_prompt(pr_data, pr_diff, include_diff=False, custom_scan_instructions=custom_scan_instructions)
            print(f"[Info] New prompt length: {len(prompt_without_diff)} characters", file=sys.stderr)
            success, error_msg, results = claude_runner.run_security_audit(repo_dir, prompt_without_diff)

        if not success:
            print(json.dumps({'error': f'Security audit failed: {error_msg}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        original_findings = results.get('findings', [])

        pr_context = {
            'repo_name': repo_nombre,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', '')
        }