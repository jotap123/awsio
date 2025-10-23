import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import os
from typing import Optional, Union
import json


class AWSFileReader:
    """
    A flexible AWS file reader that supports multiple authentication methods:
    1. IAM Role (when running on EC2, ECS, Lambda, etc.)
    2. AWS credentials file (~/.aws/credentials)
    3. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    4. Explicit access keys (passed programmatically)
    """
    
    def __init__(
        self,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        region_name: Optional[str] = None,
        profile_name: Optional[str] = None
    ):
        """
        Initialize the AWS file reader with optional credentials.
        
        Args:
            aws_access_key_id: AWS access key ID (optional)
            aws_secret_access_key: AWS secret access key (optional)
            aws_session_token: AWS session token for temporary credentials (optional)
            region_name: AWS region (defaults to us-east-1)
            profile_name: AWS profile name from credentials file (optional)
        """
        self.region_name = region_name or os.getenv('AWS_REGION', 'us-east-1')
        
        # Create session based on available credentials
        if profile_name:
            # Use named profile from credentials file
            self.session = boto3.Session(
                profile_name=profile_name,
                region_name=self.region_name
            )
        elif aws_access_key_id and aws_secret_access_key:
            # Use explicit credentials
            self.session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                region_name=self.region_name
            )
        else:
            # Use default credential chain (env vars, credentials file, IAM role, etc.)
            self.session = boto3.Session(region_name=self.region_name)
        
        self.s3_client = self.session.client('s3')
    
    def read_s3_file(
        self,
        bucket: str,
        key: str,
        encoding: str = 'utf-8'
    ) -> Union[str, bytes]:
        """
        Read a file from S3.
        
        Args:
            bucket: S3 bucket name
            key: S3 object key (file path)
            encoding: Text encoding (use None for binary data)
        
        Returns:
            File contents as string (if encoding specified) or bytes
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read()
            
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
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchKey':
                raise FileNotFoundError(f"File not found: s3://{bucket}/{key}")
            elif error_code == 'NoSuchBucket':
                raise ValueError(f"Bucket not found: {bucket}")
            elif error_code == 'AccessDenied':
                raise PermissionError(f"Access denied to s3://{bucket}/{key}")
            else:
                raise Exception(f"AWS error: {e}")
    
    def read_json_from_s3(self, bucket: str, key: str) -> dict:
        """Read and parse a JSON file from S3."""
        content = self.read_s3_file(bucket, key)
        return json.loads(content)
    
    def list_s3_files(
        self,
        bucket: str,
        prefix: str = '',
        max_keys: int = 1000
    ) -> list:
        """
        List files in an S3 bucket with optional prefix.
        
        Args:
            bucket: S3 bucket name
            prefix: Prefix to filter objects (e.g., 'data/')
            max_keys: Maximum number of keys to return
        
        Returns:
            List of object keys
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=bucket,
                Prefix=prefix,
                MaxKeys=max_keys
            )
            
            if 'Contents' not in response:
                return []
            
            return [obj['Key'] for obj in response['Contents']]
            
        except ClientError as e:
            raise Exception(f"Error listing S3 files: {e}")
    
    def download_file(
        self,
        bucket: str,
        key: str,
        local_path: str
    ) -> None:
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


# Usage Examples
if __name__ == "__main__":
    # Example 1: Use default credential chain (recommended for production)
    # This will automatically use IAM role, environment variables, or credentials file
    reader = AWSFileReader()
    
    # Example 2: Use a specific AWS profile from credentials file
    # reader = AWSFileReader(profile_name='my-profile')
    
    # Example 3: Use explicit credentials (not recommended for production)
    # reader = AWSFileReader(
    #     aws_access_key_id='YOUR_ACCESS_KEY',
    #     aws_secret_access_key='YOUR_SECRET_KEY',
    #     region_name='us-west-2'
    # )
    
    # Example 4: Use credentials from environment variables
    # Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
    # reader = AWSFileReader()
    
    try:
        # Read a text file
        content = reader.read_s3_file(
            bucket='my-bucket',
            key='data/file.txt'
        )
        print(f"File content: {content[:100]}...")
        
        # Read a JSON file
        json_data = reader.read_json_from_s3(
            bucket='my-bucket',
            key='config/settings.json'
        )
        print(f"JSON data: {json_data}")
        
        # List files in a bucket
        files = reader.list_s3_files(
            bucket='my-bucket',
            prefix='data/'
        )
        print(f"Found {len(files)} files")
        
        # Download a file
        reader.download_file(
            bucket='my-bucket',
            key='data/large-file.csv',
            local_path='/tmp/large-file.csv'
        )
        print("File downloaded successfully")
        
    except Exception as e:
        print(f"Error: {e}")