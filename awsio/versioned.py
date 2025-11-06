import re
import boto3
import pandas as pd
import awswrangler as wr

from awsio.path import get_date_from_filenames, path_join, list_s3_files, split_bucket_key
from awsio.parallelism import applyParallel


def load_history(path: str, min_date="2020-01-01", s3_client=None, **kwargs):
    """
    Load and concatenate historical files from an S3 path filtered by date token.

    The function scans files under `path`, looks for a YYYYMM token inside each filename,
    filters files with token >= min_date, then reads and concatenates them (using awswrangler).

    Args:
        path (str): S3 path to scan (file or folder).
        min_date (str or datetime-like): Minimum date threshold (inclusive). Files whose
            embedded YYYYMM token is earlier than this will be ignored.
        path_type (str): 'file' or 'folder' passed to split_bucket_key.
        s3_client (boto3.client or None): S3 client to use. A client is created if None.
        **kwargs: Additional kwargs forwarded to wr.s3.read_parquet.

    Returns:
        pd.DataFrame: Concatenated DataFrame of selected parquet files. Empty DataFrame
        is returned if no files match.
    """
    if s3_client is None:
        s3_client = boto3.client('s3')

    # list all file keys under the provided path
    all_files = list_s3_files(path, s3_client)

    selected_files = []
    for key in all_files:
        # extract filename and YYYYMM token (e.g. file_202501.parquet -> 202501)
        filename = key.split("/")[-1]
        ym = re.search(r'(\d{6})', filename)
        y = re.search(r'(\d{4})', filename)
        if not ym and not y:
            # skip files without a YYYYMM token
            continue

        if ym:
            file_date = pd.to_datetime(ym.group(1), format="%Y%m")
        elif y:
            file_date = pd.to_datetime(y.group(1), format="%Y")

        if file_date >= pd.to_datetime(min_date):
            selected_files.append(key)

    # if no files selected return empty dataframe
    if not selected_files:
        return pd.DataFrame()

    df = pd.concat([
        wr.s3.read_parquet(file, **kwargs)
        for file in selected_files
    ], ignore_index=True)

    return df


def extract_file(
    x,
    file_format,
    verbose=0,
    file_func=lambda x: x,
    keep_origin_col=False,
    errors="raise",
    **kwargs,
):
    """
    Read a single file (or apply a custom reader) and optionally add an origin column.

    Args:
        x (pd.DataFrame or Series): A one-row structure with column 'directory' containing
            the file path to read.
        file_format (str): Expected format key: 'parquet', 'csv', 'excel', or any custom.
        verbose (int): Verbosity (>0 prints what is being read).
        file_func (callable): Post-read transformation function applied to the DataFrame
            or alternative custom loader when file_format is not one of the known types.
        keep_origin_col (bool): If True, adds an 'origin' column with the source path.
        errors (str): 'raise' to re-raise exceptions, 'ignore' to return empty DataFrame on error.
        **kwargs: Forwarded to the selected reading function (e.g. read_csv sep).

    Returns:
        pd.DataFrame: The read (and transformed) DataFrame or an empty DataFrame when errors='ignore'.
    """

    if verbose > 0:
        print(f"Reading {x['directory'].values[0]}")

    dict = {"parquet": wr.s3.read_parquet, "excel": wr.s3.read_excel, "csv": wr.s3.read_csv}

    if file_format in list(dict.keys()):
        func = dict[file_format]
        try:
            df = func(x["directory"].values[0], **kwargs)

            if keep_origin_col:
                df["origin"] = x["directory"].values[0]

            df = file_func(df)

        except Exception as e:
            if errors == "raise":
                raise e
            elif errors == "ignore":
                return pd.DataFrame()

    else:
        try:
            df = file_func(x["directory"].values[0], **kwargs)

        except Exception as e:
            if errors == "raise":
                raise e
            elif errors == "ignore":
                return pd.DataFrame()

    return df


def parallel_read(
    base_folder,
    file_format="parquet",
    min_date="2020-01-01",
    last_layer="folder",
    max_date="2099-12-31",
    verbose=0,
    n_jobs=-1,
    file_func=lambda x: x,
    date_sep="",
    occ=-1,
    keep_origin_col=False,
    errors="raise",
    **kwargs,
):
    """
    Recursively find files under a base folder and read them in parallel.

    This helper navigates folder systems (year/month/day or encoded dates in filenames),
    filters files between min_date and max_date, and reads them in parallel using applyParallel.

    Args:
        base_folder (str): S3 base path where files live (can include s3://).
        file_format (str): File type to read, e.g. 'parquet', 'csv', 'excel'.
        min_date, max_date (str/datetime-like): Date window to include.
        last_layer (str): 'folder', 'month', or 'day' indicating how to extract dates.
        verbose (int): Verbosity level.
        n_jobs (int): Number of parallel jobs for reading.
        file_func (callable): Transformation function applied to each read DataFrame.
        date_sep (str): Separator used when extracting dates from filenames.
        occ (int): Index for path segment when extracting dates from filename.
        keep_origin_col (bool): If True, keep a column indicating source directory.
        errors (str): Error behaviour ('raise' or 'ignore').
        **kwargs: Additional kwargs forwarded to file readers.

    Returns:
        pd.DataFrame or None: Concatenated DataFrame of all read files (or None if none found).
    """
    min_date = pd.to_datetime(min_date)
    max_date = pd.to_datetime(max_date)

    extension = file_format if file_format != "excel" else "xls"

    list_folders = [col for col in list_s3_files(base_folder) if f".{extension}" in col]

    start = -2
    date_format = "%Y"

    if last_layer == "day":
        start = -4
        date_format = "%Y/%m/%d"
    elif last_layer == "month":
        start = -3
        date_format = "%Y/%m"

    df_folders = pd.DataFrame(list_folders, columns=["directory"])
    df_folders["file_name"] = df_folders["directory"].str.split("/").str.get(-1)

    if last_layer != "folder":
        df_folders["date"] = pd.to_datetime(
            df_folders["directory"]
            .str.split("/")
            .str.slice(start=start, stop=-1)
            .str.join("/"),
            format=date_format,
        )
        df_folders = df_folders.loc[df_folders["date"].between(min_date, max_date)]

    else:
        try:
            df_folders["date"] = get_date_from_filenames(
                df_folders["directory"], sep=date_sep, occ=occ
            )
            df_folders = df_folders.loc[df_folders["date"].between(min_date, max_date)]
        except:
            pass

    df = None

    if len(df_folders) == 1:
        df = extract_file(
            df_folders,
            file_format=file_format,
            verbose=verbose,
            file_func=file_func,
            keep_origin_col=keep_origin_col,
            errors=errors,
            **kwargs,
        )
    elif len(df_folders) > 1:
        df = applyParallel(
            df_folders.groupby(["directory"]),
            extract_file,
            keep_origin_col=keep_origin_col,
            file_format=file_format,
            file_func=file_func,
            verbose=verbose,
            errors=errors,
            n_jobs=n_jobs,
            **kwargs,
        ).reset_index(drop=True)

    return df