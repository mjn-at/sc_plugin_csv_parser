# sc_plugin_csv_parser
parse csv-exports for various plugins from tenable securitycenter/nessus 

---

```
usage: parse_sc_csv.py [-h] [--output-file OUTPUT_FILE]
                       [--output-format {csv}] [--print-errors {True,False}]
                       [-v]
                       INPUT_FILE PLUGIN_ID

Converts multi-line Plugin-Text/-Output csv export from Tenable SecurityCenter
into single-line format

positional arguments:
  INPUT_FILE            Path to csv file
  PLUGIN_ID             The Nessus Plugin-ID which data the csv file contains

optional arguments:
  -h, --help            show this help message and exit
  --output-file OUTPUT_FILE
                        Path to output file
  --output-format {csv}
                        Format for output file
  --print-errors {True,False}
                        prints the errors to stdout
  -v, --version         Display script version information
  ```
