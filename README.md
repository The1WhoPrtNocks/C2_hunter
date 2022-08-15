# C2_hunter
Python conversion for RITA from BHIS that does not require Zeek.

It uses an exported CSV from a SIEM tool that has the available data outlined in config/log.json
The string values in this file need to match the relevant column headers of your output data.
The values can either be changed in the file or via the CLI options.

I have also opened up some variables, found in the CLI config section, for the HTTP/S analysis that will all.
This will allow for fine tuning of beacon results after initial runs have been made.

https://github.com/activecm/rita

