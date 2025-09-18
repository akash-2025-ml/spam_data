#!/usr/bin/env python3
"""
Script to check for duplicate records across three CSV files.
"""

import pandas as pd
import hashlib

def get_record_hash(row):
    """Create a hash of a record (row) for comparison."""
    # Convert row to string and create hash
    row_str = '|'.join(str(val) for val in row)
    return hashlib.md5(row_str.encode()).hexdigest()

def check_duplicates_in_file(df, file_name):
    """Check for duplicates within a single file."""
    # Create hashes for all rows
    hashes = df.apply(get_record_hash, axis=1)
    
    # Find duplicates
    duplicated_mask = hashes.duplicated(keep=False)
    duplicate_count = duplicated_mask.sum()
    
    if duplicate_count > 0:
        print(f"\n{file_name} contains {duplicate_count} duplicate records:")
        # Show which records are duplicates
        duplicate_indices = df[duplicated_mask].index.tolist()
        print(f"  Duplicate record indices: {duplicate_indices}")
        
        # Show unique duplicate groups
        duplicate_hashes = hashes[duplicated_mask]
        unique_duplicate_hashes = duplicate_hashes.unique()
        print(f"  Number of unique duplicate groups: {len(unique_duplicate_hashes)}")
    else:
        print(f"\n{file_name}: No duplicates found within the file.")
    
    return hashes

def main():
    # File paths
    files = [
        '/home/u3/email_data/spam_data/No_Action_100_v1.csv',
        '/home/u3/email_data/spam_data/No_Action_100_v2.csv',
        '/home/u3/email_data/spam_data/No_Action_100_v3.csv'
    ]
    
    all_hashes = {}
    all_records = []
    file_record_counts = {}
    
    # Read and analyze each file
    for file_path in files:
        file_name = file_path.split('/')[-1]
        print(f"\n{'='*60}")
        print(f"Processing: {file_name}")
        
        # Read CSV
        df = pd.read_csv(file_path)
        record_count = len(df)
        file_record_counts[file_name] = record_count
        
        print(f"Total records (excluding header): {record_count}")
        
        # Check for duplicates within the file
        hashes = check_duplicates_in_file(df, file_name)
        
        # Store hashes with file information
        for idx, hash_val in enumerate(hashes):
            if hash_val not in all_hashes:
                all_hashes[hash_val] = []
            all_hashes[hash_val].append((file_name, idx + 2))  # +2 because row 1 is header, data starts at row 2
        
        # Store all records for cross-file comparison
        for idx, row in df.iterrows():
            all_records.append({
                'file': file_name,
                'row_number': idx + 2,  # +2 for 1-based indexing and header
                'hash': hashes.iloc[idx],
                'data': row.to_dict()
            })
    
    # Summary of file record counts
    print(f"\n{'='*60}")
    print("SUMMARY OF RECORD COUNTS:")
    total_records = sum(file_record_counts.values())
    for file_name, count in file_record_counts.items():
        print(f"  {file_name}: {count} records")
    print(f"  Total records across all files: {total_records}")
    
    # Check for duplicates across files
    print(f"\n{'='*60}")
    print("CHECKING FOR DUPLICATES ACROSS ALL FILES:")
    
    cross_file_duplicates = {hash_val: locations for hash_val, locations in all_hashes.items() if len(locations) > 1}
    
    if cross_file_duplicates:
        print(f"\nFound {len(cross_file_duplicates)} unique records that appear in multiple locations:")
        
        duplicate_count = 0
        for hash_val, locations in cross_file_duplicates.items():
            duplicate_count += len(locations)
            print(f"\n  Record appears {len(locations)} times:")
            for file_name, row_num in locations:
                print(f"    - {file_name}, row {row_num}")
        
        print(f"\nTotal duplicate records across all files: {duplicate_count}")
        print(f"Unique records across all files: {total_records - duplicate_count + len(cross_file_duplicates)}")
    else:
        print("\nNo duplicates found across files!")
        print(f"All {total_records} records are unique!")
    
    # Final verdict
    print(f"\n{'='*60}")
    print("FINAL VERDICT:")
    
    within_file_duplicates = False
    for file_path in files:
        file_name = file_path.split('/')[-1]
        df = pd.read_csv(file_path)
        hashes = df.apply(get_record_hash, axis=1)
        if hashes.duplicated().any():
            within_file_duplicates = True
            break
    
    if not within_file_duplicates and not cross_file_duplicates:
        print("✓ ALL RECORDS ARE UNIQUE!")
        print(f"  - No duplicates found within any individual file")
        print(f"  - No duplicates found across different files")
        print(f"  - Total unique records: {total_records}")
    else:
        print("✗ DUPLICATES FOUND!")
        if within_file_duplicates:
            print("  - Duplicates exist within individual files")
        if cross_file_duplicates:
            print("  - Duplicates exist across different files")

if __name__ == "__main__":
    main()