import csv
import random

# Define the header
header = [
    'sender_known_malicious', 'sender_domain_reputation_score', 'sender_spoof_detected', 'sender_temp_email_likelihood',
    'dmarc_enforced', 'packer_detected', 'any_file_hash_malicious', 'max_metadata_suspicious_score',
    'malicious_attachment_count', 'has_executable_attachment', 'unscannable_attachment_present',
    'total_components_detected_malicious', 'total_yara_match_count', 'total_ioc_count', 'max_behavioral_sandbox_score',
    'max_amsi_suspicion_score', 'any_macro_enabled_document', 'any_vbscript_javascript_detected',
    'any_active_x_objects_detected', 'any_network_call_on_open', 'max_exfiltration_behavior_score',
    'any_exploit_pattern_detected', 'total_embedded_file_count', 'max_suspicious_string_entropy_score',
    'max_sandbox_execution_time', 'unique_parent_process_names', 'return_path_mismatch_with_from',
    'return_path_known_malicious', 'return_path_reputation_score', 'reply_path_known_malicious',
    'reply_path_diff_from_sender', 'reply_path_reputation_score', 'smtp_ip_known_malicious', 'smtp_ip_geo',
    'smtp_ip_asn', 'smtp_ip_reputation_score', 'domain_known_malicious', 'url_count', 'dns_morphing_detected',
    'domain_tech_stack_match_score', 'is_high_risk_role_targeted', 'sender_name_similarity_to_vip',
    'urgency_keywords_present', 'request_type', 'content_spam_score', 'user_marked_as_spam_before',
    'bulk_message_indicator', 'unsubscribe_link_present', 'marketing_keywords_detected', 'html_text_ratio',
    'image_only_email', 'spf_result', 'dkim_result', 'dmarc_result', 'reverse_dns_valid', 'tls_version',
    'total_links_detected', 'url_shortener_detected', 'url_redirect_chain_length', 'final_url_known_malicious',
    'url_decoded_spoof_detected', 'url_reputation_score', 'ssl_validity_status', 'site_visual_similarity_to_known_brand',
    'url_rendering_behavior_score', 'link_rewritten_through_redirector', 'token_validation_success',
    'Analysis_of_the_qrcode_if_present', 'classification'
]

# Define enum values
request_types = ['gift_card_request', 'invoice_payment', 'invoice_verification', 'urgent_callback', 
                'executive_request', 'link_click', 'meeting_request', 'none']
spf_results = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']
dkim_results = ['pass', 'fail', 'none', 'policy', 'neutral', 'temperror', 'permerror']
dmarc_results = ['pass', 'fail', 'none', 'temperror', 'permerror']
tls_versions = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0']
ssl_statuses = ['valid', 'expired', 'self_signed', 'mismatch', 'revoked', 'invalid_chain', 'no_ssl', 'error']

def generate_spam_record(spam_type, bulk_indicator):
    """Generate a single spam record based on type"""
    record = []
    
    # Determine content_spam_score based on type
    if spam_type == 'clear':
        content_spam_score = round(random.uniform(0.8, 0.98), 2)
    elif spam_type == 'moderate':
        content_spam_score = round(random.uniform(0.6, 0.8), 2)
    else:  # borderline
        content_spam_score = round(random.uniform(0.5, 0.6), 3)
    
    # Generate values for each field
    record.append(random.choice([0, 0, 0, 0, 1]))  # sender_known_malicious (mostly 0)
    record.append(round(random.uniform(0.05, 0.55), 2))  # sender_domain_reputation_score
    record.append(random.choice([0, 0, 0, 1]))  # sender_spoof_detected
    record.append(round(random.uniform(0.01, 0.5), 3))  # sender_temp_email_likelihood
    record.append(random.choice([0, 0, 1]))  # dmarc_enforced
    record.append(0)  # packer_detected (always 0 for spam)
    record.append(0)  # any_file_hash_malicious (always 0 for spam)
    record.append(round(random.uniform(0.01, 0.3), 3))  # max_metadata_suspicious_score
    record.append(0)  # malicious_attachment_count
    record.append(0)  # has_executable_attachment
    record.append(random.choice([0, 0, 0, 0, 1]))  # unscannable_attachment_present
    record.append(0)  # total_components_detected_malicious
    record.append(random.choice([0, 0, 0, 1, 2]))  # total_yara_match_count
    record.append(random.choice([0, 0, 1]))  # total_ioc_count
    record.append(0.0)  # max_behavioral_sandbox_score
    record.append(0.0)  # max_amsi_suspicion_score
    record.append(0)  # any_macro_enabled_document
    record.append(0)  # any_vbscript_javascript_detected
    record.append(0)  # any_active_x_objects_detected
    record.append(0)  # any_network_call_on_open
    record.append(0.0)  # max_exfiltration_behavior_score
    record.append(0)  # any_exploit_pattern_detected
    record.append(random.choice([0, 0, 0, 1, 1, 2, 3]))  # total_embedded_file_count (0-4)
    record.append(round(random.uniform(0.05, 0.5), 2))  # max_suspicious_string_entropy_score
    record.append(0.0)  # max_sandbox_execution_time
    record.append('NULL')  # unique_parent_process_names
    record.append(random.choice([0, 1]))  # return_path_mismatch_with_from
    record.append(random.choice([0, 0, 1]))  # return_path_known_malicious
    record.append(round(random.uniform(0.1, 0.9), 2))  # return_path_reputation_score
    record.append(random.choice([0, 0, 1]))  # reply_path_known_malicious
    record.append(random.choice([0, 1]))  # reply_path_diff_from_sender
    record.append(round(random.uniform(0.1, 0.9), 2))  # reply_path_reputation_score
    record.append(random.choice([0, 0, 0, 1]))  # smtp_ip_known_malicious
    record.append(round(random.uniform(0.7, 0.95), 2))  # smtp_ip_geo (high risk)
    record.append(round(random.uniform(0.6, 0.9), 2))  # smtp_ip_asn
    record.append(round(random.uniform(0.05, 0.5), 2))  # smtp_ip_reputation_score
    record.append(random.choice([0, 0, 0, 1]))  # domain_known_malicious
    record.append(random.randint(1, 25))  # url_count
    record.append(random.choice([0, 0, 0, 1]))  # dns_morphing_detected
    record.append(round(random.uniform(0.1, 0.95), 2))  # domain_tech_stack_match_score
    record.append(random.choice([0, 0, 1]))  # is_high_risk_role_targeted
    record.append(round(random.uniform(0.0, 0.3), 2))  # sender_name_similarity_to_vip
    record.append(random.choice([0, 1, 1]))  # urgency_keywords_present
    record.append(random.choice(request_types))  # request_type
    record.append(content_spam_score)  # content_spam_score
    record.append(random.choice([0, 1, 1]))  # user_marked_as_spam_before
    record.append(bulk_indicator)  # bulk_message_indicator
    record.append(random.choice([0, 1, 1]))  # unsubscribe_link_present
    record.append(round(random.uniform(0.7, 0.98), 2))  # marketing_keywords_detected
    record.append(round(random.uniform(0.2, 0.9), 2))  # html_text_ratio
    record.append(random.choice([0, 0, 0, 1]))  # image_only_email
    record.append(random.choice(spf_results))  # spf_result
    record.append(random.choice(dkim_results))  # dkim_result
    record.append(random.choice(dmarc_results))  # dmarc_result
    record.append(random.choice([0, 1]))  # reverse_dns_valid
    record.append(random.choice(tls_versions))  # tls_version
    record.append(random.randint(1, 20))  # total_links_detected
    record.append(random.choice([0, 0, 1]))  # url_shortener_detected
    record.append(random.choice([0, 0, 1, 2, 3]))  # url_redirect_chain_length
    record.append(random.choice([0, 0, 0, 1]))  # final_url_known_malicious
    record.append(random.choice([0, 0, 0, 1]))  # url_decoded_spoof_detected
    record.append(round(random.uniform(0.1, 0.7), 2))  # url_reputation_score
    record.append(random.choice(ssl_statuses))  # ssl_validity_status
    record.append(round(random.uniform(0.0, 0.4), 2))  # site_visual_similarity_to_known_brand
    record.append(round(random.uniform(0.05, 0.5), 2))  # url_rendering_behavior_score
    record.append(random.choice([0, 0, 1]))  # link_rewritten_through_redirector
    record.append(random.choice([0, 1]))  # token_validation_success
    record.append(random.choice([1, 2]))  # Analysis_of_the_qrcode_if_present
    record.append('Spam')  # classification
    
    return record

# Generate records
all_records = []

# Create distribution for bulk_message_indicator
bulk_indicators = [1] * 170 + [0] * 80
random.shuffle(bulk_indicators)

# Generate 60 clear spam records
for i in range(60):
    all_records.append(generate_spam_record('clear', bulk_indicators[i]))

# Generate 140 moderate spam records
for i in range(60, 200):
    all_records.append(generate_spam_record('moderate', bulk_indicators[i]))

# Generate 50 borderline spam records
for i in range(200, 250):
    all_records.append(generate_spam_record('borderline', bulk_indicators[i]))

# Shuffle all records
random.shuffle(all_records)

# Write to CSV
with open('/home/u3/email_data/spam_data/spam_new_250_v2.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(all_records)

print("Successfully created spam_new_250_v2.csv with 250 unique spam records")