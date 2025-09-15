#!/usr/bin/env python3
"""
Generate 250 unique spam records and append to spam_new_250.csv
Distribution:
- 60 clear spam (0.8-0.98)
- 140 moderate spam (0.6-0.8)
- 50 borderline spam (0.5-0.6)
"""

import csv
import random
from datetime import datetime

# Constants
OUTPUT_FILE = '/home/u3/email_data/spam_data/spam_new_250.csv'
BATCH_SIZE = 50

# Enum values
SPF_RESULTS = ['pass', 'fail', 'softfail', 'neutral', 'none']
DKIM_RESULTS = ['pass', 'fail', 'none']
DMARC_RESULTS = ['pass', 'fail', 'softfail', 'none']
TLS_VERSIONS = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'SSL 3.0']
SSL_STATUS = ['valid', 'expired', 'self_signed', 'invalid_chain', 'revoked']
REQUEST_TYPES = ['gift_card_request', 'invoice_payment', 'invoice_verification', 
                 'urgent_callback', 'executive_request', 'link_click', 
                 'meeting_request', 'none']

def generate_spam_record(spam_type, record_num):
    """Generate a single spam record based on type"""
    
    # Set content_spam_score based on type
    if spam_type == 'clear':
        content_spam_score = round(random.uniform(0.8, 0.98), 2)
    elif spam_type == 'moderate':
        content_spam_score = round(random.uniform(0.6, 0.8), 2)
    else:  # borderline
        content_spam_score = round(random.uniform(0.5, 0.6), 2)
    
    # Generate bulk_message_indicator (~170 with 1, ~80 with 0 out of 250)
    bulk_message_indicator = 1 if random.random() < 0.68 else 0
    
    # Generate other fields with realistic variations
    record = {
        'sender_known_malicious': random.choice([0, 0, 0, 1]),  # Mostly 0
        'sender_domain_reputation_score': round(random.uniform(0.05, 0.25), 2),
        'sender_spoof_detected': random.choice([0, 0, 0, 0, 1]),  # Rarely 1
        'sender_temp_email_likelihood': round(random.uniform(0.85, 0.98), 2),
        'dmarc_enforced': 0,  # Mostly 0 for spam
        'packer_detected': 0,
        'any_file_hash_malicious': 0,
        'max_metadata_suspicious_score': round(random.uniform(0.25, 0.55), 2),
        'malicious_attachment_count': 0,
        'has_executable_attachment': 0,
        'unscannable_attachment_present': 0,
        'total_components_detected_malicious': 0,
        'total_yara_match_count': 0,
        'total_ioc_count': 0,
        'max_behavioral_sandbox_score': 0.0,
        'max_amsi_suspicion_score': 0.0,
        'any_macro_enabled_document': 0,
        'any_vbscript_javascript_detected': 0,
        'any_active_x_objects_detected': 0,
        'any_network_call_on_open': 0,
        'max_exfiltration_behavior_score': 0.0,
        'any_exploit_pattern_detected': 0,
        'total_embedded_file_count': random.randint(0, 4),
        'max_suspicious_string_entropy_score': round(random.uniform(0.35, 0.65), 2),
        'max_sandbox_execution_time': 0.0,
        'unique_parent_process_names': 'NULL',
        'return_path_mismatch_with_from': random.choice([0, 1]),
        'return_path_known_malicious': 0,
        'return_path_reputation_score': round(random.uniform(0.08, 0.22), 2),
        'reply_path_known_malicious': 0,
        'reply_path_diff_from_sender': random.choice([0, 1]),
        'reply_path_reputation_score': round(random.uniform(0.1, 0.25), 2),
        'smtp_ip_known_malicious': 0,
        'smtp_ip_geo': round(random.uniform(0.7, 0.95), 2),
        'smtp_ip_asn': round(random.uniform(0.65, 0.9), 2),
        'smtp_ip_reputation_score': round(random.uniform(0.05, 0.15), 2),
        'domain_known_malicious': 0,
        'url_count': random.randint(10, 35),
        'dns_morphing_detected': 0,
        'domain_tech_stack_match_score': round(random.uniform(0.8, 0.98), 2),
        'is_high_risk_role_targeted': random.choice([0, 0, 1]),
        'sender_name_similarity_to_vip': round(random.uniform(0.25, 0.45), 2),
        'urgency_keywords_present': 1,
        'request_type': random.choice(REQUEST_TYPES),
        'content_spam_score': content_spam_score,
        'user_marked_as_spam_before': 1,
        'bulk_message_indicator': bulk_message_indicator,
        'unsubscribe_link_present': 1,
        'marketing_keywords_detected': round(random.uniform(0.9, 0.99), 2),
        'html_text_ratio': round(random.uniform(0.05, 0.25), 2),
        'image_only_email': 0,
        'spf_result': random.choice(SPF_RESULTS),
        'dkim_result': random.choice(DKIM_RESULTS),
        'dmarc_result': random.choice(DMARC_RESULTS),
        'reverse_dns_valid': random.choice([0, 0, 0, 1]),
        'tls_version': random.choice(TLS_VERSIONS),
        'total_links_detected': random.randint(8, 30),
        'url_shortener_detected': 1,
        'url_redirect_chain_length': random.randint(1, 5),
        'final_url_known_malicious': 0,
        'url_decoded_spoof_detected': 0,
        'url_reputation_score': round(random.uniform(0.05, 0.22), 2),
        'ssl_validity_status': random.choice(SSL_STATUS),
        'site_visual_similarity_to_known_brand': round(random.uniform(0.2, 0.4), 2),
        'url_rendering_behavior_score': round(random.uniform(0.35, 0.55), 2),
        'link_rewritten_through_redirector': 0,
        'token_validation_success': 1,
        'Analysis_of_the_qrcode_if_present': random.choice([1, 2]),
        'classification': 'Spam'
    }
    
    return record

def main():
    """Main function to generate and append records in batches"""
    
    # Read existing headers
    with open(OUTPUT_FILE, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
    
    # Generate records
    all_records = []
    
    # Generate 60 clear spam records
    print("Generating 60 clear spam records (0.8-0.98)...")
    for i in range(60):
        all_records.append(generate_spam_record('clear', i))
    
    # Generate 140 moderate spam records
    print("Generating 140 moderate spam records (0.6-0.8)...")
    for i in range(140):
        all_records.append(generate_spam_record('moderate', i + 60))
    
    # Generate 50 borderline spam records
    print("Generating 50 borderline spam records (0.5-0.6)...")
    for i in range(50):
        all_records.append(generate_spam_record('borderline', i + 200))
    
    # Shuffle to mix the types
    random.shuffle(all_records)
    
    # Write in batches
    print(f"\nAppending {len(all_records)} records to {OUTPUT_FILE} in batches of {BATCH_SIZE}...")
    
    with open(OUTPUT_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        for i in range(0, len(all_records), BATCH_SIZE):
            batch = all_records[i:i + BATCH_SIZE]
            writer.writerows(batch)
            print(f"  Batch {i//BATCH_SIZE + 1}: Appended {len(batch)} records")
    
    print(f"\nSuccessfully appended {len(all_records)} unique spam records!")
    
    # Verify bulk_message_indicator distribution
    bulk_count = sum(1 for r in all_records if r['bulk_message_indicator'] == 1)
    print(f"\nBulk message indicator distribution: {bulk_count} with 1, {250 - bulk_count} with 0")

if __name__ == "__main__":
    main()