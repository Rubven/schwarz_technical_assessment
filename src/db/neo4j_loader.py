import os
import pandas as pd
from neo4j import GraphDatabase

class Neo4jPipeline:
    def __init__(self, uri, user, password):
      self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def setup_schema(self):
        """Creates indexes and constraints for performance and uniqueness."""
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (d:Device) REQUIRE d.device_id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (div:Division) REQUIRE div.name IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE")

    def load_data(self, devices_path: str, scans_path: str):
        """Loads processed Parquet files into the graph database."""
        # Read the clean Parquet files
        print(f"Reading processed data from {devices_path} and {scans_path}...")
        devices_df = pd.read_parquet(devices_path)
        scans_df = pd.read_parquet(scans_path)

        # Convert dates to strings
        if 'last_seen' in devices_df.columns:
            devices_df['last_seen'] = devices_df['last_seen'].astype(str)
        if 'scan_date' in scans_df.columns:
            scans_df['scan_date'] = scans_df['scan_date'].astype(str)
            
        # Fill NaNs with None for Neo4j compatibility
        devices_df = devices_df.where(pd.notnull(devices_df), None)
        scans_df = scans_df.where(pd.notnull(scans_df), None)

        with self.driver.session() as session:
            # Load Devices and Divisions
            print("Loading Devices and Divisions...")
            device_query = """
            UNWIND $rows AS row
            MERGE (div:Division {name: coalesce(row.division, 'UNKNOWN')})
            
            MERGE (d:Device {device_id: row.device_id})
            SET d.hostname = row.hostname,
                d.os = row.OS,
                d.country = row.country,
                d.last_seen = row.last_seen
                
            MERGE (d)-[:BELONGS_TO]->(div)
            """
            session.run(device_query, rows=devices_df.to_dict('records'))

            # Load CVEs and Vulnerability Relationships
            print("Loading Vulnerabilities and CVEs...")
            scan_query = """
            UNWIND $rows AS row
            MERGE (c:CVE {cve_id: row.cve_id})
            SET c.description = row.description,
                c.cvss_score = row.cvss_score,
                c.published_date = row.published_date

            MERGE (d:Device {device_id: row.device_id})
            
            // Create or update the relationship
            MERGE (d)-[v:HAS_VULNERABILITY {cve_id: row.cve_id}]->(c)
            SET v.status = row.status,
                v.severity = row.severity,
                v.last_scan_date = row.scan_date,
                v.score = row.score
            """
            session.run(scan_query, rows=scans_df.to_dict('records'))
            print("Neo4j data load complete.")

def run_neo4j_load(**kwargs):
    """Airflow callable to execute the Neo4j load."""
    
    # Get credentials
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD")
    
    if not password:
        raise ValueError("Critical error: NEO4J_PASSWORD environment variable is missing.")
    
    base_dir = os.getcwd()
    devices_path = os.path.join(base_dir, "data/processed/devices")
    scans_path = os.path.join(base_dir, "data/processed/scans")
    
    loader = Neo4jPipeline(uri, user, password)    
    try:
        loader.setup_schema()
        loader.load_data(devices_path, scans_path)
    finally:
        loader.close()