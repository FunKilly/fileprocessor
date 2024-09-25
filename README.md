# File processing application

## Application purpose
This project implements a pe files processing to search for metadata in these files. \
Whole solution uses pefile for downloading, processing and sending the results \
to the database. 

## Future improvements
- After deploying stable version of pyspark, standard udfs can be replaced with pandas udfs
- Downloading files via pyspark could be replaced by native s3 sdk
- Consider using dataframe for already existing file paths, At this moment I didn't see performance improvements.
- If there wouldn't be a constraint on using pefile for downloading files, consider \
using different method for filtering files. Like predownloading paths from s3 with aws sdk and then downloading 
only necessary files.


