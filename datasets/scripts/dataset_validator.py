"""
Dataset Validator & Leakage Detection Utility
Author: Attack Scenarios & Dataset Engineer, VaultX NIDS Project
Enterprise: Bharat Electronics Components Pvt. Ltd. (BECPL), Pune
"""

import argparse
import csv
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vaultx.dataset_validator")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Standard expected columns for VaultX / CIC-IDS harmonized schema
STANDARD_EXPECTED_COLUMNS = [
    "flow_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "connection_duration",
    "packets_transferred",
    "bytes_transferred",
    "source_vlan",
    "destination_vlan",
    "identity_classification",
    "label",
]


class DatasetValidator:
    """
    Validates intrusion detection datasets, checks schema conformity,
    analyzes class distributions, identifies duplicate records, and detects
    potential train/test leakage (IP or feature overlap).
    """

    def __init__(self, expected_columns: Optional[List[str]] = None):
        self.expected_columns = expected_columns or STANDARD_EXPECTED_COLUMNS

    def validate_file(self, filepath: str) -> Dict[str, Any]:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Dataset file not found: {filepath}")

        logger.info("Starting validation of: %s", filepath)
        file_size_bytes = os.path.getsize(filepath)

        row_count = 0
        missing_values_per_col: Dict[str, int] = defaultdict(int)
        class_distribution: Counter = Counter()
        binary_distribution: Counter = Counter()
        seen_row_hashes: Set[int] = set()
        duplicate_count = 0
        headers: List[str] = []

        with open(filepath, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            try:
                headers = [col.strip() for col in next(reader)]
            except StopIteration:
                return {
                    "filepath": filepath,
                    "status": "FAILED",
                    "error": "File is empty",
                    "row_count": 0,
                }

            # Map header indices
            col_indices = {col: idx for idx, col in enumerate(headers)}
            label_idx = col_indices.get("label") or col_indices.get("Label") or col_indices.get("class")
            src_ip_idx = col_indices.get("source_ip") or col_indices.get("Source IP") or col_indices.get("src_ip")
            dst_ip_idx = col_indices.get("destination_ip") or col_indices.get("Destination IP") or col_indices.get("dst_ip")

            for row in reader:
                if not row:
                    continue
                row_count += 1

                # Check duplicate rows via hash of tuple
                row_hash = hash(tuple(row))
                if row_hash in seen_row_hashes:
                    duplicate_count += 1
                else:
                    seen_row_hashes.add(row_hash)

                # Check missing / null / nan values
                for col_name, idx in col_indices.items():
                    val = row[idx].strip() if idx < len(row) else ""
                    if val in ("", "nan", "NaN", "null", "NULL", "None", "-"):
                        missing_values_per_col[col_name] += 1

                # Class distribution
                if label_idx is not None and label_idx < len(row):
                    lbl = row[label_idx].strip()
                    class_distribution[lbl] += 1
                    is_benign = lbl.upper() in ("BENIGN", "NORMAL", "0")
                    binary_distribution["BENIGN" if is_benign else "ATTACK"] += 1

        # Check missing columns against expected
        missing_columns = [col for col in self.expected_columns if col not in headers]
        extra_columns = [col for col in headers if col not in self.expected_columns]

        # Calculate percentages
        class_dist_summary = {}
        for k, v in class_distribution.items():
            pct = round((v / row_count) * 100, 2) if row_count > 0 else 0.0
            class_dist_summary[k] = {"count": v, "percentage": pct}

        binary_dist_summary = {}
        for k, v in binary_distribution.items():
            pct = round((v / row_count) * 100, 2) if row_count > 0 else 0.0
            binary_dist_summary[k] = {"count": v, "percentage": pct}

        report = {
            "filepath": os.path.abspath(filepath),
            "file_size_mb": round(file_size_bytes / (1024 * 1024), 2),
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "status": "PASSED" if not missing_columns else "WARNING",
            "total_rows": row_count,
            "unique_rows": len(seen_row_hashes),
            "duplicate_rows": duplicate_count,
            "duplicate_percentage": round((duplicate_count / row_count) * 100, 2) if row_count > 0 else 0.0,
            "columns_found_count": len(headers),
            "columns_expected_count": len(self.expected_columns),
            "missing_expected_columns": missing_columns,
            "extra_columns": extra_columns,
            "class_distribution": class_dist_summary,
            "binary_distribution": binary_dist_summary,
            "missing_values_per_column": dict(missing_values_per_col),
        }
        return report

    def check_train_test_leakage(self, train_path: str, test_path: str) -> Dict[str, Any]:
        """
        Detects data leakage between separate training and test datasets.
        Checks for:
        1. Exact row overlaps (identical feature vectors in both train & test)
        2. Target IP memorization leakage (same target hosts with identical attack labels)
        """
        logger.info("Evaluating train/test leakage between:\n  Train: %s\n  Test:  %s", train_path, test_path)

        def extract_fingerprints(path: str) -> Tuple[Set[int], Set[str], Set[str], int]:
            row_hashes = set()
            src_ips = set()
            dst_ips = set()
            count = 0
            with open(path, mode="r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                headers = [col.strip() for col in next(reader)]
                col_indices = {col: idx for idx, col in enumerate(headers)}
                src_idx = col_indices.get("source_ip") or col_indices.get("Source IP")
                dst_idx = col_indices.get("destination_ip") or col_indices.get("Destination IP")

                for row in reader:
                    if not row:
                        continue
                    count += 1
                    row_hashes.add(hash(tuple(row)))
                    if src_idx is not None and src_idx < len(row):
                        src_ips.add(row[src_idx].strip())
                    if dst_idx is not None and dst_idx < len(row):
                        dst_ips.add(row[dst_idx].strip())
            return row_hashes, src_ips, dst_ips, count

        train_hashes, train_src, train_dst, train_count = extract_fingerprints(train_path)
        test_hashes, test_src, test_dst, test_count = extract_fingerprints(test_path)

        row_overlap = train_hashes.intersection(test_hashes)
        src_ip_overlap = train_src.intersection(test_src)
        dst_ip_overlap = train_dst.intersection(test_dst)

        leakage_detected = len(row_overlap) > 0
        severity = "HIGH" if len(row_overlap) > 0 else ("MEDIUM" if len(src_ip_overlap) > 10 else "NONE")

        return {
            "train_file": os.path.abspath(train_path),
            "test_file": os.path.abspath(test_path),
            "train_row_count": train_count,
            "test_row_count": test_count,
            "leakage_detected": leakage_detected,
            "leakage_severity": severity,
            "exact_duplicate_rows_in_test": len(row_overlap),
            "duplicate_row_percentage_in_test": round((len(row_overlap) / test_count) * 100, 2) if test_count > 0 else 0.0,
            "overlapping_source_ips_count": len(src_ip_overlap),
            "overlapping_destination_ips_count": len(dst_ip_overlap),
            "recommendation": (
                "CRITICAL: Exact duplicate records found across train and test partitions! "
                "De-duplicate or use time-series group splitting."
                if leakage_detected
                else "No exact row leakage detected. Partitions are cleanly disjoint."
            ),
        }


def main():
    parser = argparse.ArgumentParser(description="VaultX Dataset Validator & Leakage Detection Utility")
    parser.add_argument("--file", "-f", type=str, help="Path to single dataset CSV file to validate")
    parser.add_argument("--train", type=str, help="Path to training set CSV for leakage check")
    parser.add_argument("--test", type=str, help="Path to test set CSV for leakage check")
    parser.add_argument("--output-report", "-o", type=str, help="Path to write JSON validation report")

    args = parser.parse_args()
    validator = DatasetValidator()

    full_results: Dict[str, Any] = {}

    if args.file:
        report = validator.validate_file(args.file)
        full_results["file_validation"] = report
        print("\n" + "=" * 60)
        print(f" DATASET VALIDATION REPORT: {os.path.basename(args.file)}")
        print("=" * 60)
        print(f"Status:             {report['status']}")
        print(f"Total Records:      {report['total_rows']:,}")
        print(f"Unique Records:     {report['unique_rows']:,}")
        print(f"Duplicates:         {report['duplicate_rows']:,} ({report['duplicate_percentage']}%)")
        print("\nClass Distribution:")
        for cls_name, info in report["class_distribution"].items():
            print(f"  - {cls_name:<25}: {info['count']:>8,} ({info['percentage']:>5.2f}%)")
        print("=" * 60)

    if args.train and args.test:
        leakage_report = validator.check_train_test_leakage(args.train, args.test)
        full_results["leakage_check"] = leakage_report
        print("\n" + "=" * 60)
        print(" TRAIN / TEST LEAKAGE ANALYSIS")
        print("=" * 60)
        print(f"Leakage Detected:   {leakage_report['leakage_detected']}")
        print(f"Severity:           {leakage_report['leakage_severity']}")
        print(f"Exact Row Overlaps: {leakage_report['exact_duplicate_rows_in_test']:,}")
        print(f"Recommendation:     {leakage_report['recommendation']}")
        print("=" * 60)

    if args.output_report:
        with open(args.output_report, "w", encoding="utf-8") as out:
            json.dump(full_results, out, indent=2)
        print(f"\nWrote detailed report to: {args.output_report}")


if __name__ == "__main__":
    main()
