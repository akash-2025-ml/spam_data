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

# Define enum values for legitimate emails
spf_results = ['pass', 'pass', 'pass', 'pass', 'softfail', 'neutral']  # Mostly pass for legitimate
dkim_results = ['pass', 'pass', 'pass', 'none', 'neutral']  # Mostly pass for legitimate
dmarc_results = ['pass', 'pass', 'pass', 'none', 'softfail']  # Mostly pass for legitimate
tls_versions = ['TLS 1.3', 'TLS 1.2', 'TLS 1.3', 'TLS 1.2']  # Modern versions only
ssl_statuses = ['valid', 'valid', 'valid', 'valid']  # All valid for legitimate

def generate_no_action_record(is_border_case=False):
    """Generate a single No Action record"""
    record = []
    
    # Determine content_spam_score based on type
    if is_border_case:
        content_spam_score = round(random.uniform(0.15, 0.35), 2)  # Higher but still legitimate
        sender_reputation = random.choice([0, 0, 1])  # Mostly good, sometimes slightly lower
    else:
        content_spam_score = round(random.uniform(0.0, 0.1), 2)  # Very low
        sender_reputation = 0  # Always good reputation
    
    # Generate values for each field
    record.append(0)  # sender_known_malicious - always 0 for legitimate
    record.append(sender_reputation)  # sender_domain_reputation_score (0=good, 3=bad)
    record.append(0)  # sender_spoof_detected - always 0 for legitimate
    record.append(round(random.uniform(0.0, 0.05), 3) if not is_border_case else round(random.uniform(0.0, 0.1), 3))  # sender_temp_email_likelihood
    record.append(1)  # dmarc_enforced - always 1 for legitimate
    record.append(0)  # packer_detected
    record.append(0)  # any_file_hash_malicious
    record.append(round(random.uniform(0.0, 0.02), 3) if not is_border_case else round(random.uniform(0.0, 0.05), 3))  # max_metadata_suspicious_score
    record.append(0)  # malicious_attachment_count
    record.append(0)  # has_executable_attachment
    record.append(0)  # unscannable_attachment_present
    record.append(0)  # total_components_detected_malicious
    record.append(0)  # total_yara_match_count
    record.append(0)  # total_ioc_count
    record.append(0.0)  # max_behavioral_sandbox_score
    record.append(0.0)  # max_amsi_suspicion_score
    record.append(0)  # any_macro_enabled_document
    record.append(0)  # any_vbscript_javascript_detected
    record.append(0)  # any_active_x_objects_detected
    record.append(0)  # any_network_call_on_open
    record.append(0.0)  # max_exfiltration_behavior_score
    record.append(0)  # any_exploit_pattern_detected
    record.append(random.choice([0, 0, 0, 1, 1, 2]))  # total_embedded_file_count - low for legitimate
    record.append(round(random.uniform(0.0, 0.1), 2))  # max_suspicious_string_entropy_score
    record.append(0.0)  # max_sandbox_execution_time
    record.append('NULL')  # unique_parent_process_names
    record.append(0 if not is_border_case else random.choice([0, 0, 1]))  # return_path_mismatch_with_from
    record.append(0)  # return_path_known_malicious
    record.append(round(random.uniform(0.8, 0.99), 2) if not is_border_case else round(random.uniform(0.7, 0.9), 2))  # return_path_reputation_score
    record.append(0)  # reply_path_known_malicious
    record.append(0)  # reply_path_diff_from_sender
    record.append(round(random.uniform(0.85, 0.99), 2) if not is_border_case else round(random.uniform(0.75, 0.95), 2))  # reply_path_reputation_score
    record.append(0)  # smtp_ip_known_malicious
    record.append(round(random.uniform(0.0, 0.2), 2) if not is_border_case else round(random.uniform(0.1, 0.35), 2))  # smtp_ip_geo - low risk
    record.append(round(random.uniform(0.05, 0.25), 2))  # smtp_ip_asn
    record.append(round(random.uniform(0.85, 0.99), 2) if not is_border_case else round(random.uniform(0.7, 0.9), 2))  # smtp_ip_reputation_score
    record.append(0)  # domain_known_malicious
    record.append(random.randint(0, 5))  # url_count - low for legitimate
    record.append(0)  # dns_morphing_detected
    record.append(round(random.uniform(0.85, 1.0), 2) if not is_border_case else round(random.uniform(0.7, 0.95), 2))  # domain_tech_stack_match_score
    record.append(random.choice([0, 0, 0, 1]))  # is_high_risk_role_targeted - mostly 0
    record.append(0.0 if not is_border_case else round(random.uniform(0.0, 0.1), 2))  # sender_name_similarity_to_vip
    record.append(0 if not is_border_case else random.choice([0, 0, 1]))  # urgency_keywords_present
    record.append('none')  # request_type - always none for No Action
    record.append(content_spam_score)  # content_spam_score
    record.append(0)  # user_marked_as_spam_before
    record.append(0 if not is_border_case else random.choice([0, 0, 1]))  # bulk_message_indicator
    record.append(0 if not is_border_case else random.choice([0, 0, 1]))  # unsubscribe_link_present
    record.append(round(random.uniform(0.0, 0.3), 2) if not is_border_case else round(random.uniform(0.2, 0.5), 2))  # marketing_keywords_detected
    record.append(round(random.uniform(0.85, 0.99), 2))  # html_text_ratio - high for legitimate
    record.append(0)  # image_only_email
    record.append(random.choice(spf_results))  # spf_result
    record.append(random.choice(dkim_results))  # dkim_result
    record.append(random.choice(dmarc_results))  # dmarc_result
    record.append(1)  # reverse_dns_valid
    record.append(random.choice(tls_versions))  # tls_version
    record.append(random.randint(0, 5))  # total_links_detected
    record.append(0)  # url_shortener_detected
    record.append(0)  # url_redirect_chain_length
    record.append(0)  # final_url_known_malicious
    record.append(0)  # url_decoded_spoof_detected
    record.append(round(random.uniform(0.85, 0.99), 2) if not is_border_case else round(random.uniform(0.7, 0.95), 2))  # url_reputation_score
    record.append(random.choice(ssl_statuses))  # ssl_validity_status
    record.append(0.0 if not is_border_case else round(random.uniform(0.0, 0.1), 2))  # site_visual_similarity_to_known_brand
    record.append(round(random.uniform(0.0, 0.1), 2))  # url_rendering_behavior_score
    record.append(0 if not is_border_case else random.choice([0, 0, 1]))  # link_rewritten_through_redirector
    record.append(1)  # token_validation_success
    record.append(random.choice([1, 2]))  # Analysis_of_the_qrcode_if_present
    record.append('No Action')  # classification
    
    return record

# Generate records
all_records = []

# Generate 30 clear No Action records
for i in range(30):
    all_records.append(generate_no_action_record(is_border_case=False))

# Generate 20 border case No Action records
for i in range(20):
    all_records.append(generate_no_action_record(is_border_case=True))

# Shuffle all records
random.shuffle(all_records)

# Write to CSV
with open('/home/u3/email_data/spam_data/no_action_50.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(all_records)

print("Successfully created no_action_50.csv with 50 unique No Action records (30 clear + 20 border cases)")