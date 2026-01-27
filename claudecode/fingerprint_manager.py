#!/usr/bin/env python3
"""
Alert Fingerprint Manager

Manages fingerprint persistence for existing open Code Scanning alerts to prevent
creating duplicate alerts when re-scanning the same vulnerabilities.
"""

import json
import requests
import hashlib
from typing import Dict, Any, List, Optional, Tuple
try:
    from claudecode.logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger(__name__)


class FingerprintManager:
    """Manages alert fingerprints to ensure existing open alerts maintain their fingerprints."""
    
    def __init__(self, github_token: str, repository: str):
        """Initialize fingerprint manager.
        
        Args:
            github_token: GitHub token with code-scanning:read permission
            repository: Repository in format 'owner/repo'
        """
        self.github_token = github_token
        self.repository = repository
        self.headers = {
            'Authorization': f'Bearer {github_token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        self.existing_fingerprints = {}  # Map: finding_signature -> existing_fingerprint
    
    def _create_finding_signature(self, finding: Dict[str, Any]) -> str:
        """Create a signature for a finding to match against existing alerts.
        
        Uses file path, line number, rule category, and core description content
        to create a stable signature that can match findings across scans.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Unique signature string for the finding
        """
        file_path = finding.get("file", "unknown")
        line = str(finding.get("line", 0))
        category = finding.get("category", "unknown")
        
        # Use first 200 chars of description for matching (more than fingerprint uses)
        description = finding.get("description", "")[:200]
        
        # Create signature
        signature_content = f"{file_path}:{line}:{category}:{description}"
        return hashlib.sha256(signature_content.encode('utf-8')).hexdigest()[:32]
    
    def _extract_existing_fingerprint(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract the existing fingerprint from a GitHub alert.
        
        Args:
            alert: GitHub Code Scanning alert
            
        Returns:
            Existing fingerprint if found, None otherwise
        """
        try:
            # Check most_recent_instance for fingerprints
            instance = alert.get('most_recent_instance', {})
            fingerprints = instance.get('fingerprints', {})
            
            # Look for our custom fingerprint
            claude_fingerprint = fingerprints.get('claude-scanner/v1')
            if claude_fingerprint:
                return claude_fingerprint
            
            # Fallback: look for any fingerprint we can reuse
            if fingerprints:
                # Use the first available fingerprint
                return list(fingerprints.values())[0]
                
            return None
            
        except Exception as e:
            logger.warning(f"Failed to extract fingerprint from alert {alert.get('number', 'unknown')}: {e}")
            return None
    
    def _convert_alert_to_finding_signature(self, alert: Dict[str, Any]) -> Optional[str]:
        """Convert a GitHub alert back to our finding signature format.
        
        Args:
            alert: GitHub Code Scanning alert
            
        Returns:
            Finding signature if convertible, None otherwise
        """
        try:
            # Extract location information
            instance = alert.get('most_recent_instance', {})
            location = instance.get('location', {})
            file_path = location.get('path', '')
            line = location.get('start_line', 0)
            
            # Extract rule information
            rule = alert.get('rule', {})
            rule_id = rule.get('id', '')
            rule_description = rule.get('description', '')
            
            if not file_path or not rule_id:
                return None
            
            # Create a finding-like object for signature generation
            pseudo_finding = {
                'file': file_path,
                'line': line,
                'category': rule_id,
                'description': rule_description
            }
            
            return self._create_finding_signature(pseudo_finding)
            
        except Exception as e:
            logger.warning(f"Failed to convert alert {alert.get('number', 'unknown')} to signature: {e}")
            return None
    
    def load_existing_fingerprints(self) -> int:
        """Load fingerprints from existing open Claude Security Scanner alerts.
        
        Returns:
            Number of existing fingerprints loaded
        """
        try:
            logger.info("Loading existing alert fingerprints...")
            
            # Get all open alerts
            url = f"https://api.github.com/repos/{self.repository}/code-scanning/alerts"
            params = {
                'state': 'open',
                'per_page': 100
            }
            
            all_alerts = []
            page = 1
            
            while True:
                params['page'] = page
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                
                alerts = response.json()
                if not alerts:
                    break
                
                all_alerts.extend(alerts)
                
                if len(alerts) < 100:
                    break
                page += 1
            
            # Filter to Claude Security Scanner alerts and extract fingerprints
            loaded_count = 0
            for alert in all_alerts:
                tool = alert.get('tool', {})
                tool_name = tool.get('name', '').lower()
                
                # Check if this is a Claude Security Scanner alert
                if ('claude' in tool_name and 'security' in tool_name) or tool_name == 'claude security scanner':
                    signature = self._convert_alert_to_finding_signature(alert)
                    existing_fingerprint = self._extract_existing_fingerprint(alert)
                    
                    if signature and existing_fingerprint:
                        self.existing_fingerprints[signature] = existing_fingerprint
                        loaded_count += 1
                        logger.debug(f"Loaded fingerprint for alert #{alert.get('number')}: {signature} -> {existing_fingerprint}")
            
            logger.info(f"Loaded {loaded_count} existing alert fingerprints")
            return loaded_count
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to load existing fingerprints: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error loading fingerprints: {e}")
            return 0
    
    def get_fingerprint_for_finding(self, finding: Dict[str, Any], default_fingerprint: str) -> Tuple[str, bool]:
        """Get the appropriate fingerprint for a finding.
        
        Args:
            finding: Finding dictionary
            default_fingerprint: New fingerprint to use if no existing one found
            
        Returns:
            Tuple of (fingerprint_to_use, is_existing_alert)
        """
        signature = self._create_finding_signature(finding)
        
        # Check if we have an existing fingerprint for this finding
        existing_fingerprint = self.existing_fingerprints.get(signature)
        
        if existing_fingerprint:
            logger.debug(f"Using existing fingerprint for {finding.get('file', 'unknown')}:{finding.get('line', 0)} - {signature}")
            return existing_fingerprint, True
        else:
            logger.debug(f"Using new fingerprint for {finding.get('file', 'unknown')}:{finding.get('line', 0)} - {signature}")
            return default_fingerprint, False
    
    def get_fingerprint_stats(self) -> Dict[str, int]:
        """Get statistics about fingerprint usage.
        
        Returns:
            Dictionary with fingerprint statistics
        """
        return {
            'existing_fingerprints_loaded': len(self.existing_fingerprints),
            'total_signatures': len(self.existing_fingerprints)
        }