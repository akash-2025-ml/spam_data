import pandas as pd
import glob

def analyze_v1_to_v4(file_path):
    """Analyze v1-v4 files with the original schema"""
    df = pd.read_csv(file_path)
    issues = []
    
    # Check key malicious indicators that should be 0
    malicious_cols = [
        'sender_known_malicious', 'sender_spoof_detected', 'packer_detected',
        'any_file_hash_malicious', 'malicious_attachment_count', 'has_executable_attachment',
        'total_components_detected_malicious', 'return_path_known_malicious',
        'reply_path_known_malicious', 'smtp_ip_known_malicious', 'domain_known_malicious',
        'final_url_known_malicious', 'url_decoded_spoof_detected'
    ]
    
    for col in malicious_cols:
        if col in df.columns:
            malicious_rows = df[df[col] > 0]
            if len(malicious_rows) > 0:
                issues.append(f"{col}: {len(malicious_rows)} rows with value > 0")
    
    # Check suspicious string entropy (should be low)
    if 'max_suspicious_string_entropy_score' in df.columns:
        high_entropy = df[df['max_suspicious_string_entropy_score'] > 0.15]
        if len(high_entropy) > 0:
            issues.append(f"max_suspicious_string_entropy_score > 0.15: {len(high_entropy)} rows")
    
    # Check authentication results
    auth_issues = 0
    if all(col in df.columns for col in ['spf_result', 'dkim_result', 'dmarc_result']):
        auth_fail = df[(df['spf_result'] != 'pass') | (df['dkim_result'] != 'pass') | (df['dmarc_result'] != 'pass')]
        if len(auth_fail) > 0:
            spf_fail = len(df[df['spf_result'] != 'pass'])
            dkim_fail = len(df[df['dkim_result'] != 'pass'])
            dmarc_fail = len(df[df['dmarc_result'] != 'pass'])
            issues.append(f"Authentication failures - SPF: {spf_fail}, DKIM: {dkim_fail}, DMARC: {dmarc_fail}")
    
    # Check spam scores
    if 'content_spam_score' in df.columns:
        high_spam = df[df['content_spam_score'] > 0.3]
        if len(high_spam) > 0:
            issues.append(f"content_spam_score > 0.3: {len(high_spam)} rows")
    
    # Check if marked as spam before
    if 'user_marked_as_spam_before' in df.columns:
        spam_marked = df[df['user_marked_as_spam_before'] == 1]
        if len(spam_marked) > 0:
            issues.append(f"user_marked_as_spam_before = 1: {len(spam_marked)} rows")
    
    # Check return path mismatch
    if 'return_path_mismatch_with_from' in df.columns:
        mismatch = df[df['return_path_mismatch_with_from'] == 1]
        if len(mismatch) > 0:
            issues.append(f"return_path_mismatch_with_from = 1: {len(mismatch)} rows")
            
    return issues

def analyze_v5_to_v9(file_path):
    """Analyze v5-v9 files with the different schema"""
    df = pd.read_csv(file_path)
    issues = []
    
    # Check malicious scores
    malicious_score_cols = ['attachment_malicious_score', 'url_malicious_score']
    for col in malicious_score_cols:
        if col in df.columns:
            malicious_rows = df[df[col] > 0]
            if len(malicious_rows) > 0:
                issues.append(f"{col}: {len(malicious_rows)} rows with value > 0")
    
    # Check reputation scores (1 is bad, 0 is good for these)
    reputation_cols = ['sender_domain_reputation_score', 'sender_ip_reputation_score', 
                      'sender_email_reputation_score']
    for col in reputation_cols:
        if col in df.columns:
            bad_rep = df[df[col] == 1]
            if len(bad_rep) > 0:
                issues.append(f"{col} = 1 (bad reputation): {len(bad_rep)} rows")
    
    # Check authentication
    if all(col in df.columns for col in ['email_authentication_spf_pass', 'email_authentication_dkim_pass', 
                                           'email_authentication_dmarc_pass']):
        auth_fail = df[(df['email_authentication_spf_pass'] == 0) | 
                      (df['email_authentication_dkim_pass'] == 0) | 
                      (df['email_authentication_dmarc_pass'] == 0)]
        if len(auth_fail) > 0:
            spf_fail = len(df[df['email_authentication_spf_pass'] == 0])
            dkim_fail = len(df[df['email_authentication_dkim_pass'] == 0])
            dmarc_fail = len(df[df['email_authentication_dmarc_pass'] == 0])
            issues.append(f"Authentication failures - SPF: {spf_fail}, DKIM: {dkim_fail}, DMARC: {dmarc_fail}")
    
    # Check suspicious indicators
    suspicious_cols = ['url_phishing_likelihood', 'urgent_language_present', 
                      'financial_keywords_present', 'personal_info_request']
    for col in suspicious_cols:
        if col in df.columns:
            suspicious = df[df[col] > 0.1] if 'likelihood' in col else df[df[col] == 1]
            if len(suspicious) > 0:
                issues.append(f"{col}: {len(suspicious)} rows with suspicious values")
    
    # Check spelling/grammar errors
    if 'spelling_errors_ratio' in df.columns:
        high_errors = df[df['spelling_errors_ratio'] > 0.05]
        if len(high_errors) > 0:
            issues.append(f"spelling_errors_ratio > 0.05: {len(high_errors)} rows")
            
    if 'grammatical_errors_ratio' in df.columns:
        high_errors = df[df['grammatical_errors_ratio'] > 0.05]
        if len(high_errors) > 0:
            issues.append(f"grammatical_errors_ratio > 0.05: {len(high_errors)} rows")
    
    return issues

# Analyze all files
print("=== Analyzing No Action Signal Values ===\n")

for i in range(1, 10):
    file_path = f"/home/u3/email_data/spam_data/No_Action_100_v{i}.csv"
    print(f"\n--- Analyzing {file_path} ---")
    
    try:
        if i <= 4:
            issues = analyze_v1_to_v4(file_path)
        else:
            issues = analyze_v5_to_v9(file_path)
        
        if issues:
            print("Issues found:")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("No significant issues found - all values appear appropriate for No Action.")
            
    except Exception as e:
        print(f"Error analyzing file: {e}")

print("\n=== Summary ===")
print("\nKey findings:")
print("1. Files v1-v4 use one schema with explicit malicious indicator columns")
print("2. Files v5-v9 use a different schema with reputation scores and ratios")
print("3. Main concerns to check:")
print("   - Any malicious indicators should be 0")
print("   - Authentication (SPF/DKIM/DMARC) should mostly pass")
print("   - Spam scores should be low")
print("   - Suspicious string entropy should be low")
print("   - No urgent language or phishing indicators")