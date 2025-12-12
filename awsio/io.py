import json
import logging
import os
import time
from typing import Optional, Union

import boto3
import pandas as pd
from botocore.exceptions import ClientError, NoCredentialsError

from awsio.auth import authentication
from awsio.path import split_bucket_key

logger = logging.getLogger(__name__)


class AWSio:
    """
    High-level convenience wrapper for common AWS IO operations.

    The class centralizes session creation (supporting profiles, explicit credentials,
    environment defaults and an SSO device-flow for a 'dev' profile) and provides
    utility methods to read S3 objects, download files and run Athena queries.

    A flexible AWS file reader that supports multiple authentication methods:
    1. IAM Role (when running on EC2, ECS, Lambda, etc.)
    2. AWS credentials file (~/.aws/credentials)
    3. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    4. Explicit access keys (passed programmatically)

    Usage examples:
    Example 1: Use default credential chain (recommended for production)
    This will automatically use IAM role, environment variables, or credentials file
    reader = AWSio()

    Example 2: Use a specific AWS profile from credentials file
    reader = AWSio(profile_name='my-profile')

    Example 3: Use explicit credentials (not recommended for production)
    reader = AWSio(
        aws_access_key_id='YOUR_ACCESS_KEY',
        aws_secret_access_key='YOUR_SECRET_KEY',
        region_name='us-west-2'
    )

    Example 4: Use credentials from environment variables
    Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
    reader = AWSio()
    """

    def __init__(
        self,
        aws_secrets: Optional[dict] = None,
        profile_name: Optional[str] = os.getenv("AWS_PROFILE", None),
    ):
        """
        Initialize the AWS file reader with optional credentials.

        Args:
            aws_secrets (optional): Dictionary with keys 'aws_access_key_id',
                'aws_secret_access_key', and optionally 'aws_session_token'
            profile_name: AWS profile name from credentials file (optional)
        """
        self.region_name = os.getenv("AWS_REGION", "us-east-1")
        sso_oidc = boto3.client("sso-oidc", region_name=self.region_name)

        def authenticate(sso_oidc, use_cache=True):
            sso_oidc = boto3.client("sso-oidc", region_name=self.region_name)
            access_token = authentication(sso_oidc, use_cache)

            # Obter credenciais da role fixa
            sso = boto3.client("sso", region_name=self.region_name)
            try:
                creds = sso.get_role_credentials(
                    accountId=os.getenv("ACCOUNT_ID", ""),
                    roleName=os.getenv("ROLE_NAME", ""),
                    accessToken=access_token,
                )["roleCredentials"]
            except Exception as e:
                print(f"❌ Erro ao obter credenciais: {e}")
                return

            # Executar query no Athena
            session = boto3.Session(
                aws_access_key_id=creds["accessKeyId"],
                aws_secret_access_key=creds["secretAccessKey"],
                aws_session_token=creds["sessionToken"],
                region_name=self.region_name,
            )
            return session

        if profile_name:
            if profile_name == "dev":
                self.session = authenticate(sso_oidc)
            else:
                # Use named profile from credentials file
                self.session = boto3.Session(
                    profile_name=profile_name, region_name=self.region_name
                )
        elif aws_secrets:
            # Use explicit credentials
            self.session = boto3.Session(
                aws_access_key_id=aws_secrets["aws_access_key_id"],
                aws_secret_access_key=aws_secrets["aws_secret_access_key"],
                aws_session_token=aws_secrets["aws_session_token"],
                region_name=self.region_name,
            )
        else:
            # Use default credential chain (env vars, credentials file, IAM role, etc.)
            self.session = boto3.Session(region_name=self.region_name)

        self.s3_client = self.session.client("s3")
        self.athena_client = self.session.client("athena")

    @staticmethod
    def s3_file_exists(path, s3_client=None):
        """
        Check whether a file exists in S3.

        Args:
            path (str): S3 URI (e.g., 's3://bucket/key' or 'bucket/key' is allowed).
            s3_client (boto3.client, optional): S3 client to use. If None, a new client is created.

        Returns:
            bool: True if the object exists, False otherwise.
        """
        if s3_client is None:
            s3_client = boto3.client("s3")

        bucket, key = split_bucket_key(path, type="file")

        try:
            s3_client.head_object(Bucket=bucket, Key=key)
            return True
        except Exception:
            return False

    def read_s3_file(
        self, bucket: str, key: str, encoding: str = "utf-8"
    ) -> Union[str, bytes]:
        """
        Read an object from S3 and return its contents.

        Args:
            bucket (str): S3 bucket name.
            key (str): S3 object key (path inside bucket).
            encoding (str or None): If a string, decode bytes using this encoding and return str.
                If None, return raw bytes.

        Returns:
            str or bytes: File content.

        Raises:
            FileNotFoundError, ValueError, PermissionError, Exception on AWS-related errors.
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            content = response["Body"].read()

            if encoding:
                return content.decode(encoding)
            return content

        except NoCredentialsError:
            raise Exception(
                "No AWS credentials found. Please configure credentials using "
                "one of the supported methods (IAM role, credentials file, "
                "environment variables, or explicit keys)."
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchKey":
                raise FileNotFoundError(f"File not found: s3://{bucket}/{key}")
            elif error_code == "NoSuchBucket":
                raise ValueError(f"Bucket not found: {bucket}")
            elif error_code == "AccessDenied":
                raise PermissionError(f"Access denied to s3://{bucket}/{key}")
            else:
                raise Exception(f"AWS error: {e}")

    def read_json_from_s3(self, bucket: str, key: str) -> dict:
        """Read an S3 object and parse it as JSON."""
        content = self.read_s3_file(bucket, key)
        return json.loads(content)

    def download_file(self, bucket: str, key: str, local_path: str) -> None:
        """
        Download a file from S3 to local filesystem.

        Args:
            bucket: S3 bucket name
            key: S3 object key
            local_path: Local file path to save to
        """
        try:
            self.s3_client.download_file(bucket, key, local_path)
        except ClientError as e:
            raise Exception(f"Error downloading file: {e}")

    def read_athena_query(self, query: str, s3_output: str) -> pd.DataFrame:
        """
        Execute an Athena query and return results as a pandas DataFrame.

        The method starts the query, polls until completion and then reads the
        returned rows into a DataFrame. Note: for large result sets consider
        using the query ResultConfiguration and awswrangler for streaming reads.

        Args:
            query (str): SQL query to run.
            s3_output (str): S3 location for Athena query results (e.g. 's3://bucket/prefix/').

        Returns:
            pd.DataFrame: Query results as a DataFrame when the query succeeds.

        Raises:
            RuntimeError or logs errors when query fails or is cancelled.
        """
        execution = self.athena_client.start_query_execution(
            QueryString=query, ResultConfiguration={"OutputLocation": s3_output}
        )
        qid = execution["QueryExecutionId"]
        logger.info(f"🚀 Query sent! ExecutionId: {qid}. Running...")

        while True:
            execution = self.athena_client.get_query_execution(QueryExecutionId=qid)
            status = execution["QueryExecution"]["Status"]["State"]
            if status in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(5)

        if status == "SUCCEEDED":
            result = self.athena_client.get_query_results(QueryExecutionId=qid)
            meta = result["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
            headers = [col["Label"] for col in meta]
            data_rows = result["ResultSet"]["Rows"][1:]
            rows = [
                [col.get("VarCharValue", "") for col in r["Data"]] for r in data_rows
            ]
            df = pd.DataFrame(rows, columns=headers)

            return df

        else:
            logger.error(f"❌ Query finalizada com status: {status}")
            if status == "FAILED":
                error_info = execution["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Erro desconhecido"
                )
                logger.warning(f"Detalhes do erro: {error_info}")
