# awsio

A small utilities library to simplify reading/writing and basic data workflows with AWS services (S3, Athena, SSO). Provides lightweight helpers for path handling, parallel reads, simple S3 IO and an SSO-based auth flow.

Key goals:
- Simplify common S3 and Athena interactions.
- Provide sensible defaults and support multiple auth methods (SSO, profiles, env, explicit keys).
- Small, dependency-light helpers for datalake style workflows.

## Features
- AWSio class for authenticated sessions and common actions:
  - read_s3_file, read_json_from_s3, download_file, read_athena_query
- SSO device-flow helper for short-lived role credentials (auth.py)
- Path helpers: split_bucket_key, date extraction helpers (path.py)
- Parallelized reading utilities using joblib (parallelism.py)
- Utilities to read versioned data sets from S3 including date filtering (versioned.py)

## Installation
Install from source (recommended during development):

1. Clone the repo
   git clone https://github.com/jotap123/awsio.git
2. Create a virtual env and install
   python -m venv .venv
   source .venv/bin/activate   # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   pip install -e .

Or install via pip when a package is published:
   pip install awsio

## Quickstart

1) Basic usage with default credential chain (env, shared credentials, IAM role):
   from awsio.io import AWSio
   reader = AWSio()
   bucket, key = 'my-bucket', 'path/to/file.txt'
   content = reader.read_s3_file(bucket, key)
   print(content)

2) Use a named profile from your AWS shared credentials:
   reader = AWSio(profile_name='dev')  # 'dev' uses SSO auth flow in this project
   df = reader.read_athena_query("SELECT * FROM my_db.my_table LIMIT 10", "s3://my-bucket/athena-results/")

3) Explicit credentials (not recommended for production):
   reader = AWSio(aws_secrets={
       'aws_access_key_id': 'AKIA...',
       'aws_secret_access_key': '...',
       'aws_session_token': '...'  # optional
   })

4) Read a JSON file from S3:
   obj = reader.read_json_from_s3('my-bucket', 'config/my.json')

## API Highlights

- AWSio(session selection)
  - __init__(aws_secrets=None, profile_name=None)
    - Picks authentication strategy: profile (SSO logic for `dev`), explicit keys, or default chain.
  - read_s3_file(bucket, key, encoding='utf-8')
    - Returns file contents (str) or bytes if encoding is None. Raises clear exceptions for common AWS errors.
  - read_json_from_s3(bucket, key)
    - Returns parsed JSON from S3.
  - download_file(bucket, key, local_path)
    - Downloads an object to local filesystem.
  - read_athena_query(query, s3_output)
    - Runs an Athena query and returns a pandas.DataFrame (reads result rows returned by Athena).

- auth.authentication(sso_oidc, use_cache=True)
  - Implements device code flow and caches short-lived access token to ~/.aws_sso_oidc_cache.json.

- path.split_bucket_key(s3_uri, type='file'|'folder')
  - Splits s3://bucket/key into (bucket, key) and optionally ensures folder trailing slash.

- versioned.parallel_read / load_history
  - Utilities to read many S3 files (parquet/csv/excel) with date filtering and parallel reads.

- parallelism.applyParallel
  - Run groupby apply-like functions in parallel using joblib.

## Configuration & Environment
- Region: set AWS_REGION environment variable to change default region (defaults to us-east-1).
- SSO config: START_URL, OIDC_APP_NAME, ACCOUNT_ID, ROLE_NAME environment variables are used by the SSO flow.
- Cache: token cache is saved to ~/.aws_sso_oidc_cache.json by default.

## Development
- Tests: Add tests under a tests/ folder and run using pytest.
- Formatting & linting: follow pyproject.toml and setup.cfg settings.
- Contributing: open issues and PRs on the repo. Keep changes small and document behavior changes.

## Troubleshooting
- No credentials found: ensure environment variables or credentials file are set, or run on an environment with an attached IAM role.
- SSO flow issues: check START_URL and OIDC_APP_NAME env vars; clear the cache file to force re-auth.

## License
See LICENSE in the repository root.

## Contact
Project: https://github.com/jotap123/awsio
Issues: https://github.com/jotap123/awsio/issues

