import os
import sys
import logging
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql.functions import col, try_to_date, current_date, datediff, coalesce, lit

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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