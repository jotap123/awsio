"""Path and filename helpers used to extract dates and split S3 URIs.

Provides simple utilities to:
 - join path segments,
 - extract year/month/day tokens from filenames or paths,
 - split s3:// URIs into bucket and key,
 - list files under a prefix using a boto3 client.
"""

import re
import pandas as pd


def path_join(*args, sep="/"):
    """Concatenate path segments using the provided separator and return the joined string."""
    return f"{sep}".join([*args])


def get_year_month_from_names(names_list, sep="", occ=-1):
    """
    Parse year-month tokens from a list of path/filenames.

    Args:
        names_list (Iterable[str]): List of filenames or paths.
        sep (str): Token separator used between year and month ('', '-', '/', '_').
        occ (int): When splitting path by '/', index to inspect for the filename (default -1).

    Returns:
        pd.DatetimeIndex: Parsed year-month timestamps.
    """
    result_list = []
    for item in names_list:
        if sep == "_":
            match = re.search(r"\d{4}_\d{2}", item.split("/")[occ])
        elif sep == "-":
            match = re.search(r"\d{4}-\d{2}", item.split("/")[occ])
        elif sep == "/":
            match = re.search(r"\d{4}/\d{2}", item)
        elif sep == "":
            match = re.search(r"\d{4}\d{2}", item.split("/")[occ])
        else:
            raise "Date format not supported"

        result_list.append(str(match.group()))

    if sep == "-":
        return pd.to_datetime(result_list, format="%Y-%m")
    elif sep == "/":
        return pd.to_datetime(result_list, format="%Y/%m")
    elif sep == "_":
        return pd.to_datetime(result_list, format="%Y_%m")
    elif sep == "":
        return pd.to_datetime(result_list, format="%Y%m")
    else:
        raise "Date format not supported"


def get_date_from_names(names_list, sep="_", occ=-1):
    """
    Parse full dates (YYYYMMDD) from a list of path/filenames.

    Args:
        names_list (Iterable[str]): List of filenames or paths.
        sep (str): Separator used in the filename date token (default '_').
        occ (int): When splitting path by '/', index to inspect for the filename.

    Returns:
        pd.DatetimeIndex: Parsed dates.
    """
    result_list = []
    for item in names_list:
        if sep == "_":
            match = re.search(r"\d{4}_\d{2}_\d{2}", item.split("/")[occ])
        elif sep == "-":
            match = re.search(r"\d{4}-\d{2}-\d{2}", item.split("/")[occ])
        elif sep == "/":
            match = re.search(r"\d{4}/\d{2}/\d{2}", item)
        elif sep == "":
            match = re.search(r"\d{4}\d{2}\d{2}", item.split("/")[occ])

        result_list.append(str(match.group()))

    if sep == "-":
        return pd.to_datetime(result_list, format="%Y-%m-%d")
    elif sep == "/":
        return pd.to_datetime(result_list, format="%Y/%m/%d")
    elif sep == "_":
        return pd.to_datetime(result_list, format="%Y_%m_%d")
    elif sep == "":
        return pd.to_datetime(result_list, format="%Y%m%d")
    else:
        raise "Date format not supported"


def split_bucket_key(s3_uri: str, type: str) -> tuple:
    """
    Split S3 URI into (bucket, key) tuple.

    Args:
        s3_uri (str): S3 URI like 's3://bucket/key' or 'bucket/key'.
        type (str): 'file' to return the exact key, 'folder' to ensure trailing slash.

    Returns:
        tuple: (bucket, key or key+'/').

    Raises:
        ValueError: If type is not 'file' or 'folder'.
    """
    path = s3_uri.strip("s3://")  

    bucket, key = path.split('/', 1)

    if type == "file":
        return bucket, key
    elif type == "folder":
        return bucket, key + "/"
    else:
        raise ValueError("type must be either 'file' or 'folder'")


def list_s3_files(path, s3_client):
    """
    List object keys under a given S3 prefix.

    Args:
        path (str): S3 folder path (e.g., 's3://bucket/prefix/').
        s3_client (boto3.client): Initialized boto3 S3 client.

    Returns:
        list[str]: List of object keys (not full s3:// URIs). Empty list when no objects found.
    """
    if re.search("[*]", path):
        suffix = path.split("*")[-1]
        path = "/".join(path.split("/")[:-1])
    else:
        suffix = None

    bucket, key = split_bucket_key(path, type="folder")
    files = s3_client.list_objects_v2(
        Bucket=bucket,
        Prefix=key,
        Delimiter="/"
    )

    list_files = []
    try:
        for content in files['Contents']:
            list_files.append(content['Key'])

        if suffix:
            final_files = [file for file in list_files if re.search(suffix, file) is not None]
            return final_files

    except KeyError:
        print(f"No files found in {path}")

    return list_files