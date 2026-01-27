#!/usr/bin/env python3

from typing import List, Dict, Any, Optional
import json
import datetime
import hashlib
import uuid

def _severity_to_level(severity: str) -> str:
    # For security vulnerabilities, use 'warning' level with security severity
    if not severity:
        return "note"
    s = severity.strip().upper()
    if s in ["CRITICAL", "HIGH", "MEDIUM"]:
        return "warning"
    if s == "LOW":
        return "note"
    return "note"

def _get_security_severity(severity: str) -> str:
    if not severity:
        return "low"
    s = severity.strip().lower()
    if s == "critical":
        return "critical"
    if s == "high":
        return "high"
    if s == "medium":
        return "medium"
    if s == "low":
        return "low"
    return "low"

def _generate_custom_fingerprint(finding: Dict[str, Any], timestamp: str) -> str:
    """
    Generate a unique custom fingerprint for the finding to prevent GitHub from
    incorrectly correlating with previously closed alerts.
    
    Uses a combination of:
    - File path + line number (location)
    - Rule category (vulnerability type) 
    - Core description content (first 100 chars)
    - Timestamp (to ensure uniqueness across runs)
    - Random UUID component (final uniqueness guarantee)
    """
    file_path = finding.get("file", "unknown")
    line = str(finding.get("line", 0))
    category = finding.get("category", "unknown")
    description = finding.get("description", "")[:100]  # First 100 chars
    
    # Create a deterministic part based on the actual finding
    content_hash = hashlib.sha256(
        f"{file_path}:{line}:{category}:{description}".encode('utf-8')
    ).hexdigest()[:16]
    
    # Add timestamp and random component for uniqueness
    unique_id = str(uuid.uuid4())[:8]
    timestamp_hash = hashlib.md5(timestamp.encode('utf-8')).hexdigest()[:8]
    
    # Format: claude-{content_hash}-{timestamp_hash}-{unique_id}
    fingerprint = f"claude-{content_hash}-{timestamp_hash}-{unique_id}"
    
    return fingerprint

def findings_to_sarif(findings: List[Dict[str, Any]],
                      tool_name: str = "Claude Code Security Reviewer", 
                      tool_full_name: Optional[str] = None,
                      fingerprint_manager = None,
                      use_github_compatible_format: bool = False) -> Dict[str, Any]:
    """
    Convert security findings to SARIF 2.1.0 format with custom fingerprinting.
    
    This function generates custom fingerprints for each finding to prevent GitHub's
    Code Scanning from incorrectly correlating new vulnerabilities with previously
    closed alerts that have similar rule IDs or locations.
    
    Existing open alerts maintain their original fingerprints to prevent duplicates.
    
    Args:
        findings: List of finding dictionaries from security scan
        tool_name: Name of the security scanning tool
        tool_full_name: Full name of the tool (defaults to tool_name)
        fingerprint_manager: Optional FingerprintManager for existing alert handling
        
    Returns:
        SARIF 2.1.0 compliant dictionary with custom fingerprints
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    tool_full_name = tool_full_name or tool_name
    
    # Use GitHub-compatible format adjustments if requested
    if use_github_compatible_format:
        # Simplify tool name for better compatibility
        if "Claude" in tool_name:
            tool_name = "Claude-Scanner"
            tool_full_name = "Claude Security Scanner"
    
    rules_map: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rule_id = f.get("category", "unknown")
        if rule_id not in rules_map:
            description = f.get("description", "") or f"Security issue: {rule_id}"
            recommendation = f.get("recommendation", "")
            help_text = description
            if recommendation:
                help_text += f"\n\n**Recommendation:** {recommendation}"
            
            rule = {
                "id": str(rule_id),
                "name": str(rule_id).replace("_", " ").title(),
                "shortDescription": {"text": description},
                "fullDescription": {"text": help_text},
                "help": {"text": help_text}
            }
            
            # Add default security severity for the rule if this is a security finding
            severity = f.get("severity", "")
            if severity:
                security_severity = _get_security_severity(severity)
                rule["properties"] = {"security-severity": security_severity}
            
            rules_map[rule_id] = rule

    results: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = f.get("category", "unknown")
        level = _severity_to_level(f.get("severity", ""))
        message_text = f.get("description", "") or ""
        confidence = f.get("confidence")
        if confidence is not None:
            message_text = f"{message_text} (confidence: {confidence})"

        # Use relative path from repository root
        file_path = f.get("file", "<unknown>")
        if file_path.startswith("./"):
            file_path = file_path[2:]  # Remove leading ./
        
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": file_path}
            }
        }
        
        # Add region information if line number is available
        if isinstance(f.get("line"), int) and f["line"] > 0:
            location["physicalLocation"]["region"] = {
                "startLine": f["line"]
            }

        # Determine fingerprint - use existing for open alerts, new for others
        if fingerprint_manager:
            default_fingerprint = _generate_custom_fingerprint(f, timestamp)
            fingerprint_to_use, is_existing = fingerprint_manager.get_fingerprint_for_finding(f, default_fingerprint)
        else:
            fingerprint_to_use = _generate_custom_fingerprint(f, timestamp)
            is_existing = False
        
        result = {
            "ruleId": str(rule_id),
            "level": level,
            "message": {"text": message_text},
            "locations": [location]
        }
        
        # Add fingerprints - use GitHub-compatible format if requested
        if use_github_compatible_format:
            # Use partialFingerprints format that GitHub prefers
            result["partialFingerprints"] = {
                "primaryLocationLineHash": fingerprint_to_use
            }
        else:
            # Use our custom fingerprint format
            result["fingerprints"] = {
                "claude-scanner/v1": fingerprint_to_use
            }
        
        # Add security severity for vulnerability findings
        severity = f.get("severity", "")
        if severity:
            security_severity = _get_security_severity(severity)
            result["properties"] = result.get("properties", {})
            result["properties"]["security-severity"] = security_severity
        extras = {}
        for key in ("severity", "category", "confidence", "description", "extra"):
            if key in f:
                extras[key] = f[key]
        if extras:
            result["properties"] = result.get("properties", {})
            result["properties"]["claude_finding"] = extras
            
        # Add fingerprint metadata to properties for debugging (skip in GitHub-compatible mode)
        if not use_github_compatible_format:
            result["properties"] = result.get("properties", {})
            result["properties"]["claude_fingerprint_info"] = {
                "generated_at": timestamp,
                "scanner_version": "claude-security-scanner-v1.0",
                "fingerprint_method": "claude-scanner/v1",
                "is_existing_alert": is_existing,
                "fingerprint_source": "existing_alert" if is_existing else "new_generation"
            }

        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://www.schemastore.org/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "fullName": tool_full_name,
                        "version": "1.0.0",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/CyBirdSecurity/Claude-Security-Scanner",
                        "rules": list(rules_map.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": timestamp
                    }
                ],
                "results": results
            }
        ]
    }

    return sarif

def findings_to_sarif_string(findings: List[Dict[str, Any]], tool_name: str = "Claude Code Security Reviewer", fingerprint_manager = None, use_github_compatible_format: bool = False) -> str:
    sarif = findings_to_sarif(findings, tool_name=tool_name, fingerprint_manager=fingerprint_manager, use_github_compatible_format=use_github_compatible_format)
    return json.dumps(sarif, indent=2, ensure_ascii=False)