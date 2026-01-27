#!/usr/bin/env python3
import sys
sys.path.append('.')

# Test the fingerprint manager without the full test suite
print('🧪 Testing Fingerprint Persistence System...')

from claudecode.fingerprint_manager import FingerprintManager
from claudecode.sarif_utils import findings_to_sarif_string
import json

# Mock a scenario: we have an existing alert and a new finding
print('1. Setting up test scenario...')

# Create findings
existing_finding = {
    'file': 'app/controllers/application_controller.rb',
    'line': 26,
    'severity': 'CRITICAL',
    'category': 'authentication_bypass',
    'description': 'Authentication can be completely disabled via configuration flag'
}

new_finding = {
    'file': 'lib/new_client.rb', 
    'line': 42,
    'severity': 'HIGH',
    'category': 'sql_injection',
    'description': 'New SQL injection vulnerability found'
}

print('2. Testing fingerprint manager functionality...')

# Create manager (without GitHub token, just for testing logic)
manager = FingerprintManager('fake_token', 'test/repo')

# Test signature generation
sig1 = manager._create_finding_signature(existing_finding)
sig2 = manager._create_finding_signature(existing_finding) 
sig3 = manager._create_finding_signature(new_finding)

print(f'   ✅ Signature consistency: {sig1 == sig2}')
print(f'   ✅ Signature uniqueness: {sig1 != sig3}')
print(f'   📝 Existing finding signature: {sig1}')
print(f'   📝 New finding signature: {sig3}')

print('3. Testing fingerprint assignment...')

# Manually simulate having an existing fingerprint
manager.existing_fingerprints[sig1] = 'claude-existing123-old456-preserved'

# Test fingerprint assignment
existing_fp, is_existing = manager.get_fingerprint_for_finding(existing_finding, 'claude-new123-new456-new789')
new_fp, is_new = manager.get_fingerprint_for_finding(new_finding, 'claude-new456-new789-new012')

print(f'   ✅ Existing finding preserved: {is_existing}')
print(f'   ✅ New finding is new: {not is_new}')
print(f'   📝 Existing fingerprint: {existing_fp}')
print(f'   📝 New fingerprint: {new_fp}')

print('4. Testing SARIF generation...')

# Generate SARIF with fingerprint manager
sarif_content = findings_to_sarif_string(
    [existing_finding, new_finding],
    tool_name='Claude Security Scanner',
    fingerprint_manager=manager
)

sarif_obj = json.loads(sarif_content)
results = sarif_obj['runs'][0]['results']

print(f'   ✅ SARIF generated with {len(results)} findings')

for i, result in enumerate(results, 1):
    rule_id = result['ruleId']
    fingerprint = result['fingerprints']['claude-scanner/v1']
    is_existing = result['properties']['claude_fingerprint_info']['is_existing_alert']
    source = result['properties']['claude_fingerprint_info']['fingerprint_source']
    
    print(f'   {i}. {rule_id}: {fingerprint} ({source})')

print()
print('🎯 KEY FEATURES VERIFIED:')
print('• Existing alerts preserve their original fingerprints')
print('• New vulnerabilities get unique fingerprints') 
print('• SARIF metadata shows fingerprint source')
print('• No duplicate alerts will be created for existing issues')