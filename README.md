# C2_hunter
Python conversion for RITA from ActiveCM/BHIS that does not require Zeek.

https://github.com/activecm/rita

## Config

It uses an exported CSV from a SIEM tool that has the available data outlined in config/log.json
The string values in this file need to match the relevant column headers of your output data.
The values can either be changed in the file or via the CLI options.

I have also opened up some variables, found in the CLI config section, for the HTTP/S analysis that will allow for fine tuning of beacon results after initial runs have been made.

## Usage examples

From the c2_hunter directory call main with python and select the relevant options you want.

### HTTP analysis

python.exe .\__main__.py cli http -f .\test_data\LR_HTTP_S_data.csv

## TODO

* Add API Wrapper to allow for centralisation and automation of use
* Expose average time Delta between polls to results screeen
