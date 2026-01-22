#!/usr/bin/env python3
"""
Baseline validation system to ensure critical security findings persist across scans.
"""

import json
import os
import hashlib
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from claudecode.logger import get_logger

logger = get_logger(__name__)


class BaselineValidator:
    """Validates current findings against a baseline of previously discovered issues."""
    
    def __init__(self, workspace_path: Optional[str] = None):
        """Initialize baseline validator.
        
        Args:
            workspace_path: Path to workspace for storing baseline files
        """
        self.workspace_path = workspace_path or os.environ.get('GITHUB_WORKSPACE', '.')
        self.baseline_file = os.path.join(self.workspace_path, '.security_baseline.json')
        
    def _generate_finding_signature(self, finding: Dict[str, Any]) -> str:
        """Generate a stable signature for a security finding.
        
        Args:
            finding: Security finding to generate signature for
            
        Returns:
            Unique signature string
        """
        # Use stable elements for signature
        file_path = finding.get('file', '')
        line = finding.get('line', 0)
        category = finding.get('category', '')
        # Normalize description to remove dynamic content
        description = finding.get('description', '').split('(confidence:')[0].strip()
        normalized_desc = " ".join(description.lower().split())
        
        signature_data = f"{file_path}:{line}:{category}:{normalized_desc}"
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]
    
    def _is_critical_finding(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is considered critical and should never be lost.
        
        Args:
            finding: Security finding to check
            
        Returns:
            True if finding is critical
        """
        severity = finding.get('severity', '').upper()
        category = finding.get('category', '').lower()
        
        # Critical finding categories
        critical_categories = {
            'authentication_bypass', 'authorization_bypass', 'auth_bypass', 
            'privilege_escalation', 'idor', 'access_control_bypass'
        }
        
        return (severity == 'CRITICAL' or 
                (severity == 'HIGH' and category in critical_categories))
    
    def load_baseline(self) -> Dict[str, Any]:
        """Load existing security baseline.
        
        Returns:
            Baseline data or empty dict if no baseline exists
        """
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")
        
        return {'findings': {}, 'last_updated': '', 'scan_count': 0}
    
    def save_baseline(self, findings: List[Dict[str, Any]]) -> None:
        """Save current findings as new baseline.
        
        Args:
            findings: List of security findings to save
        """
        try:
            baseline_data = {
                'findings': {},
                'last_updated': str(os.environ.get('GITHUB_RUN_ID', 'local')),
                'scan_count': self.load_baseline().get('scan_count', 0) + 1
            }
            
            for finding in findings:
                if self._is_critical_finding(finding):
                    signature = self._generate_finding_signature(finding)
                    baseline_data['findings'][signature] = {
                        'file': finding.get('file'),
                        'line': finding.get('line'),
                        'severity': finding.get('severity'),
                        'category': finding.get('category'),
                        'description': finding.get('description', '').split('(confidence:')[0].strip(),
                        'first_seen': str(os.environ.get('GITHUB_RUN_ID', 'local')),
                        'last_seen': str(os.environ.get('GITHUB_RUN_ID', 'local'))
                    }
            
            with open(self.baseline_file, 'w', encoding='utf-8') as f:
                json.dump(baseline_data, f, indent=2)
            
            logger.info(f"Saved baseline with {len(baseline_data['findings'])} critical findings")
            
        except Exception as e:
            logger.error(f"Failed to save baseline: {e}")
    
    def validate_findings(self, current_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate current findings against baseline and restore missing critical findings.
        
        Args:
            current_findings: List of findings from current scan
            
        Returns:
            Enhanced findings list with restored critical findings
        """
        baseline = self.load_baseline()
        baseline_findings = baseline.get('findings', {})
        
        if not baseline_findings:
            logger.info("No baseline exists, saving current findings")
            self.save_baseline(current_findings)
            return current_findings
        
        # Generate signatures for current findings
        current_signatures = set()
        enhanced_findings = list(current_findings)
        
        for finding in current_findings:
            if self._is_critical_finding(finding):
                signature = self._generate_finding_signature(finding)
                current_signatures.add(signature)
        
        # Find missing critical findings
        missing_signatures = set(baseline_findings.keys()) - current_signatures
        
        if missing_signatures:
            logger.warning(f"Found {len(missing_signatures)} missing critical findings from baseline")
            
            for signature in missing_signatures:
                baseline_finding = baseline_findings[signature]
                
                # Recreate missing finding with baseline validation metadata
                restored_finding = {
                    'file': baseline_finding['file'],
                    'line': baseline_finding['line'],
                    'severity': baseline_finding['severity'],
                    'category': baseline_finding['category'],
                    'description': baseline_finding['description'],
                    'confidence': 1.0,  # Max confidence for baseline findings
                    'exploit_scenario': 'This critical finding was previously discovered and should be addressed. It has been restored from the security baseline to prevent regression.',
                    'recommendation': 'Review and address this previously identified critical security issue.',
                    '_baseline_metadata': {
                        'restored_from_baseline': True,
                        'first_seen': baseline_finding['first_seen'],
                        'last_seen': baseline_finding['last_seen'],
                        'signature': signature
                    },
                    '_filter_metadata': {
                        'confidence_score': 10.0,
                        'justification': 'Restored from security baseline - critical finding must not regress'
                    }
                }
                
                enhanced_findings.append(restored_finding)
                logger.info(f"Restored critical finding: {baseline_finding['category']} in {baseline_finding['file']}:{baseline_finding['line']}")
        
        # Update baseline with current findings
        self.save_baseline(enhanced_findings)
        
        return enhanced_findings