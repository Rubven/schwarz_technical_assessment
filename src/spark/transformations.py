import os
import sys
import logging
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import col, try_to_date, current_date, datediff, coalesce, lit

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_data_quality_checks(
    scans_df: DataFrame, 
    devices_df: DataFrame, 
    divisions_df: DataFrame
) -> None:
    """
    Executes data quality controls required by the technical assessment.
    Logs results and forces pipeline failure if critical rules are violated.
    """
    print("2026-05-18T08:54:00Z [info     ] Starting Data Quality validation checks...")
    
    # Schema Validation: Verify expected columns exist in the scans dataset.
    expected_scan_cols = {"scan_date", "device_id", "cve_id", "severity", "score", "status"}
    actual_scan_cols = set(scans_df.columns)
    
    if not expected_scan_cols.issubset(actual_scan_cols):
        missing = expected_scan_cols - actual_scan_cols
        print(f"2026-05-18T08:54:01Z [error    ] Schema Validation Failed! Missing columns in scans: {missing}")
        sys.exit(1) # Critical failure
    print("2026-05-18T08:54:01Z [info     ] DQ Check 1/5: Schema Validation PASSED.")

    # Completeness: Ratio of non-null values in critical fields (over 95%).
    total_scans = scans_df.count()
    if total_scans > 0:
        # Validate that key fields like device_id are not empty
        null_device_count = scans_df.filter(col("device_id").isNull()).count()
        completeness_pct = ((total_scans - null_device_count) / total_scans) * 100
        
        print(f"2026-05-18T08:54:01Z [info     ] DQ Check 2/5: Completeness for 'device_id' is {completeness_pct:.2f}%")
        
        # If completeness drops below 95%, fail the pipeline
        if completeness_pct < 95.0:
            print("2026-05-18T08:54:01Z [error    ] Completeness dropped below safety threshold (95%)!")
            sys.exit(1)
    else:
        print("2026-05-18T08:54:01Z [warning  ] Scans DataFrame is empty. Skipping completeness percentages.")

    # Uniqueness
    total_devices = devices_df.count()
    unique_devices = devices_df.select("device_id").distinct().count()
    
    if total_devices != unique_devices:
        print(f"2026-05-18T08:54:02Z [error    ] Uniqueness Check Failed! Found {total_devices - unique_devices} duplicate device_ids in master data.")
        sys.exit(1)
    print("2026-05-18T08:54:02Z [info     ] DQ Check 3/5: Uniqueness in Master Keys PASSED.")

    # Range Checks: Valid severities and scores between 0-10.
    invalid_scores = scans_df.filter((col("score") < 0.0) | (col("score") > 10.0)).count()
    
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    invalid_severities = scans_df.filter(~col("severity").isin(valid_severities) & col("severity").isNotNull()).count()
    
    if invalid_scores > 0 or invalid_severities > 0:
        print(f"2026-05-18T08:54:02Z [warning  ] Range Check Warning: Found {invalid_scores} invalid CVSS scores and {invalid_severities} unrecognized severities.")
    else:
        print("2026-05-18T08:54:02Z [info     ] DQ Check 4/5: Range Checks PASSED.")

    # Referential Integrity: Check if device_id from scans exists in devices_master.
    orphaned_scans = scans_df.join(devices_df, on="device_id", how="left_anti").count()
    
    if orphaned_scans > 0:
        print(f"2026-05-18T08:54:02Z [warning  ] Referential Integrity Warning: Found {orphaned_scans} scan records mapping to non-existent device_ids.")
    else:
        print("2026-05-18T08:54:02Z [info     ] DQ Check 5/5: Referential Integrity PASSED.")

    print("2026-05-18T08:54:02Z [info     ] All data quality checks completed.")

def run_transformations(**kwargs):
    """Executes PySpark data cleaning and enrichment."""
    
    logger.info("Initializing Spark Session...")
    spark = SparkSession.builder \
        .appName("VulnerabilityTransformations") \
        .master("local[*]") \
        .getOrCreate()

    # Set log level
    spark.sparkContext.setLogLevel("ERROR")

    # Set paths
    base_dir = os.getcwd()
    raw_devices = os.path.join(base_dir, "data/raw/devices_master.csv")
    raw_scans = os.path.join(base_dir, "data/raw/device_scans.csv")
    raw_divisions = os.path.join(base_dir, "data/raw/divisions.csv")
    staging_cve = os.path.join(base_dir, "data/staging/cve_data.json")
    output_dir = os.path.join(base_dir, "data/processed")

    logger.info("Loading raw and staged data...")
    devices_df = spark.read.csv(raw_devices, header=True, inferSchema=True)
    scans_df = spark.read.csv(raw_scans, header=True, inferSchema=True)
    divisions_df = spark.read.csv(raw_divisions, header=True, inferSchema=True)
    cve_df = spark.read.option("multiline", "true").json(staging_cve)

    # --DATA CLEANING--
    logger.info("Cleaning data (deduplication, null handling, formatting)...")
    
    # Deduplicate
    devices_df = devices_df.dropDuplicates(["device_id"])
    scans_df = scans_df.dropDuplicates(["device_id", "cve_id", "scan_date"])
    
    # Normalize Dates
    date_formats = ["yyyy-MM-dd", "dd-MMM-yyyy", "MM/dd/yyyy", "yyyy/MM/dd"]
    
    scans_df = scans_df.withColumn(
        "scan_date", 
        coalesce(*[try_to_date(col("scan_date"), f) for f in date_formats])
    )
    
    devices_df = devices_df.withColumn(
        "last_seen", 
        coalesce(*[try_to_date(col("last_seen"), f) for f in date_formats])
    )
    
    # Handle Nulls
    scans_df = scans_df.fillna({"severity": "UNKNOWN", "score": 0.0})

    # --DATA QUALITY --
    run_data_quality_checks(scans_df, devices_df, divisions_df)
    logger.info("Applying data quality checks (Completeness, uniqueness, range checks, referential integrity)...")


    # --ENRICHMENT--
    logger.info("Enriching data (Joins and derived metrics)...")
    
    # Join Devices with Divisions
    enriched_devices = devices_df.join(divisions_df, on="division", how="left")
    
    # Join Scans with CVE Details
    enriched_scans = scans_df.join(cve_df, on="cve_id", how="left")
    
    # Derived Metric: Days since detection (using the scan_date)
    enriched_scans = enriched_scans.withColumn(
        "days_since_detection", 
        datediff(current_date(), col("scan_date"))
    )

    # --SAVE PROCESSED DATA--
    logger.info(f"Writing processed data to {output_dir}...")
    enriched_devices.write.mode("overwrite").parquet(f"{output_dir}/devices")
    enriched_scans.write.mode("overwrite").parquet(f"{output_dir}/scans")

    logger.info("Spark transformations completed successfully.")
    spark.stop()