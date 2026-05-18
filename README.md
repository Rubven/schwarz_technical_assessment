# Vulnerability Pipeline

## Overview
This project implements an ELT pipeline for vulnerability and exposure management.

The pipeline:
- Ingests device and vulnerability data from CSV and API
- Processes data using PySpark
- Stores results in Neo4j and PostgreSQL
- Runs daily using Apache Airflow

## Architecture

- Extract: CSV + CVE API
- Load (Staging): Raw partitioned storage
- Transform: PySpark jobs
- Load (Final): Neo4j + PostgreSQL

## Tech Stack

- Python 3.14
- Apache Airflow
- PySpark
- Neo4j
- PostgreSQL

## Project Structure

vulnerability-pipeline/
│
├── dags/                          # Airflow DAGs
│   └── vulnerability_dag.py
│
├── src/
│   ├── config/                   # Configs
│   │   └── settings.py
│   │
│   ├── ingestion/                # Extract logic
│   │   ├── csv_reader.py
│   │   └── cve_api.py
│   │
│   ├── staging/                  # Raw storage logic
│   │   └── writer.py
│   │
│   ├── transformations/          # PySpark logic
│   │
│   ├── loaders/                  # Final sinks
│   │   ├── neo4j_loader.py
│   │   └── postgres_loader.py
│   │
│   ├── quality/                  # Data quality checks
│   │
│   └── utils/                    # Shared utilities
│
├── data/
│   ├── raw/                      # raw input
│   ├── staging/                  # partitioned raw
│   └── curated/                  # processed data
│
├── tests/
│
├── main.py                       # local entrypoint
├── requirements.txt
├── README.md
└── .gitignore