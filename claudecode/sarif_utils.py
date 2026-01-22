#!/usr/bin/env python3

from typing import List, Dict, Any, Optional
import json
import datetime
import hashlib

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

def findings_to_sarif(findings: List[Dict[str, Any]],
                      tool_name: str = "Claude Code Security Reviewer",
                      tool_full_name: Optional[str] = None) -> Dict[str, Any]:
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    tool_full_name = tool_full_name or tool_name
    
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

        # Generate stable partial fingerprint for result tracking
        # Use only stable elements: file path, line number, rule category, and core description
        core_description = f.get("description", "").split("(confidence:")[0].strip()  # Remove dynamic confidence info
        # Normalize description: remove extra whitespace and convert to lowercase for consistency
        normalized_description = " ".join(core_description.lower().split())
        fingerprint_data = f"{file_path}:{f.get('line', 0)}:{rule_id}:{normalized_description}"
        partial_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
        
        # Create multiple fingerprints for better stability
        line_based_fingerprint = partial_fingerprint
        
        # Content-based fingerprint (without line number for cases where lines shift)
        content_fingerprint_data = f"{file_path}:{rule_id}:{normalized_description}"
        content_fingerprint = hashlib.sha256(content_fingerprint_data.encode()).hexdigest()[:16]
        
        result = {
            "ruleId": str(rule_id),
            "level": level,
            "message": {"text": message_text},
            "locations": [location],
            "partialFingerprints": {
                "primaryLocationLineHash": line_based_fingerprint,
                "primaryLocationContentHash": content_fingerprint
            }
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
            result["properties"] = {"claude_finding": extras}

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

def findings_to_sarif_string(findings: List[Dict[str, Any]], tool_name: str = "Claude Code Security Reviewer") -> str:
    sarif = findings_to_sarif(findings, tool_name=tool_name)
    return json.dumps(sarif, indent=2, ensure_ascii=False)