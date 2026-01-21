#!/usr/bin/env python3

from typing import List, Dict, Any, Optional
import json
import datetime

def _severity_to_level(severity: str) -> str:
    if not severity:
        return "note"
    s = severity.strip().upper()
    if s == "CRITICAL":
        return "error"
    if s == "HIGH":
        return "error"
    if s == "MEDIUM":
        return "warning"
    if s == "LOW":
        return "note"
    return "note"

def findings_to_sarif(findings: List[Dict[str, Any]],
                      tool_name: str = "Claude Code Security Reviewer",
                      tool_full_name: Optional[str] = None) -> Dict[str, Any]:
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    tool_full_name = tool_full_name or tool_name
    
    rules_map: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rule_id = f.get("category", "unknown")
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": str(rule_id),
                "name": str(rule_id),
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": f.get("description", "") or ""},
                "help": {"text": f.get("description", "") or ""}
            }

    results: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = f.get("category", "unknown")
        level = _severity_to_level(f.get("severity", ""))
        message_text = f.get("description", "") or ""
        confidence = f.get("confidence")
        if confidence is not None:
            message_text = f"{message_text} (confidence: {confidence})"

        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.get("file", "<unknown>")},
                "region": {}
            }
        }
        if isinstance(f.get("line"), int):
            location["physicalLocation"]["region"]["startLine"] = f["line"]

        result = {
            "ruleId": str(rule_id),
            "level": level,
            "message": {"text": message_text},
            "locations": [location],
        }
        extras = {}
        for key in ("severity", "category", "confidence", "description", "extra"):
            if key in f:
                extras[key] = f[key]
        if extras:
            result["properties"] = {"claude_finding": extras}

        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
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
                        "executionSuccessfulKind": "completed",
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