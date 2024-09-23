import os
from multiprocessing import cpu_count


def list_files_from_s3(session, number_of_files, excluded_paths: list[str]):
    bucket_name = os.environ.get("BUCKET_NAME", "s3-nord-challenge-data")
    directories = os.environ.get("DIRECTORIES", ["0", "1"])

    file_amount = int(number_of_files / len(directories))

    dataframes = []
    for path in directories:
        s3_path = f"s3a://{bucket_name}/{path}/"
        files_df = session.read.format("binaryFile").load(s3_path).coalesce(cpu_count())

        filtered_df = files_df.filter(~files_df.path.isin(excluded_paths)).limit(
            file_amount
        )
        dataframes.append(filtered_df)

    if dataframes:
        combined_df = dataframes[0]
        for df in dataframes[1:]:
            combined_df = combined_df.union(df)
        return combined_df

    return session.createDataFrame([], schema=files_df.schema)
