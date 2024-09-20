import boto3
import os

def download_s3_files(bucket_name, prefix, local_directory):
    s3 = boto3.client('s3', region_name='eu-central-1')

    # Ensure the local directory exists
    os.makedirs(local_directory, exist_ok=True)

    # List objects in the specified S3 bucket and prefix
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    if 'Contents' in response:
        for obj in response['Contents']:
            file_key = obj['Key']
            if file_key.endswith('/'):
                continue  # Skip directories

            local_file_path = os.path.join(local_directory, os.path.basename(file_key))

            print(f"Downloading {file_key} to {local_file_path}...")
            s3.download_file(bucket_name, file_key, local_file_path)
    else:
        print("No files found in the specified directory.")

if __name__ == '__main__':
    BUCKET_NAME = 's3-nord-challenge-data'
    PREFIX = '0/'  # Specify the directory to download files from
    LOCAL_DIRECTORY = './downloads/files'  # Local directory to save files

    download_s3_files(BUCKET_NAME, PREFIX, LOCAL_DIRECTORY)