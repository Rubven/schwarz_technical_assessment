import os
import sys
from pyspark.sql import SparkSession
import pyspark.sql.functions as F

def run_dq_checks(**kwargs):
    """Standalone Airflow task to validate processed Parquet data."""
    print("[info] Initializing Spark Session for DQ Checks...")
    spark = SparkSession.builder \
        .appName("DataQualityValidation") \
        .master("local[*]") \
        .getOrCreate()
    
    spark.sparkContext.setLogLevel("ERROR")

    base_dir = os.getcwd()
    devices_path = os.path.join(base_dir, "data/processed/devices")
    scans_path = os.path.join(base_dir, "data/processed/scans")

    print(f"Reading processed data from {devices_path} and {scans_path}...")
    devices_df = spark.read.parquet(devices_path)
    scans_df = spark.read.parquet(scans_path)

    print("[info] Starting Data Quality validation checks...")
    
    # Schema Validation
    expected_cols = {"scan_date", "device_id", "cve_id", "severity", "score"}
    if not expected_cols.issubset(set(scans_df.columns)):
        print(f"[error] Schema Validation Failed! Missing columns.")
        sys.exit(1) # Fails the Airflow task
        
    # Completeness
    total_scans = scans_df.count()
    null_device_count = scans_df.filter(F.col("device_id").isNull()).count()
    completeness_pct = ((total_scans - null_device_count) / total_scans) * 100
    print(f"[info] Completeness for 'device_id' is {completeness_pct:.2f}%")
    if completeness_pct < 95.0:
        print("[error] Completeness dropped below 95%!")
        sys.exit(1)
        
    # Uniqueness
    total_devices = devices_df.count()
    unique_devices = devices_df.select("device_id").distinct().count()
    if total_devices != unique_devices:
        print(f"[error] Uniqueness Failed! Found {total_devices - unique_devices} duplicate devices.")
        sys.exit(1)

    # Range Checks (Warning only)
    invalid_scores = scans_df.filter((F.col("score") < 0.0) | (F.col("score") > 10.0)).count()
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    invalid_sevs = scans_df.filter(~F.col("severity").isin(valid_severities)).count()
    if invalid_scores > 0 or invalid_sevs > 0:
        print(f"[warning] Found {invalid_scores} invalid CVSS scores and {invalid_sevs} unrecognized severities.")

    # 5. Referential Integrity (Warning only)
    orphaned_scans = scans_df.join(devices_df, on="device_id", how="left_anti").count()
    if orphaned_scans > 0:
        print(f"[warning] Referential Integrity Warning: Found {orphaned_scans} scans with non-existent device_ids.")

    print("[info] All data quality checks completed successfully.")
    spark.stop()