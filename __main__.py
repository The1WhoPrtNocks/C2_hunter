import argparse
import os

import pandas as pd
import json
from tabulate import tabulate
from analysis import http_analyser, dns_analyser
from pprint import pprint

# Top Level Parser
parser = argparse.ArgumentParser()
# Top level subparsers
subparsers = parser.add_subparsers()
# three options available
cli_parser = subparsers.add_parser('cli', help="use c2_hunter in cli mode")
api_parser = subparsers.add_parser('api', help="use c2_hunter in API mode")
conf_parser = subparsers.add_parser('conf', help="change configuration options for c2_hunter")


# cli options
cli_subparser = cli_parser.add_subparsers()
# http analysis
http_s_parser = cli_subparser.add_parser("http", help="Use http based analysis")
http_file = http_s_parser.add_argument("-f", dest="http_file", required=True, help="Select log file to be analysied")
http_allow = http_s_parser.add_argument("-a", dest="http_allow", required=False, help="Select allow list to be used")
# DNS analysis
dns_parser = cli_subparser.add_parser("dns", help="Use dns based analysis")
dns_file = dns_parser.add_argument("-f", dest="dns_file", required=True, help="Select log file to be analysied")
dns_allow = dns_parser.add_argument("-a", dest="dns_allow", required=False, help="Select allow list to be used")

# api options
# TODO: write similar to Conf Options

# Conf options
conf_subparsers = conf_parser.add_subparsers()
# change log based settings
log_parser = conf_subparsers.add_parser('log', help="change configuration relating to log sources")
list_options = log_parser.add_argument("-l", dest="list_option",  action="store_true", help="list current options")
with open("config/log.json") as f:
    log_settings = json.load(f)
    options = []
    for key,value in log_settings.items():
        options.append(key)
option = log_parser.add_argument("-o", dest="conf_option", required=False, choices=options,
                                 help="select which option you want to change")
value = log_parser.add_argument("-v", dest="conf_variable", required=False, help="provide value for the option")
# change http analysis settings
http_parser = conf_subparsers.add_parser("http", help="Change configuration relating to http/s analysis")
list_options = http_parser.add_argument("-l", dest="list_http",  action="store_true", help="list current options")
with open("config/http_analysis.json") as f:
    log_settings = json.load(f)
    options = []
    for key,value in log_settings.items():
        options.append(key)
option = http_parser.add_argument("-o", dest="http_option", required=False, choices=options,
                                 help="select which option you want to change")
value = http_parser.add_argument("-v", dest="http_variable", required=False, help="provide value for the option")



args, unparsed = parser.parse_known_args()


def main():
    # response to conf log based options
    if "list_option" in args:
        data = {
            "Setting": [],
            "Variable": []
        }
        if args.list_option:
            with open("config/log.json") as f:
                log_settings = json.load(f)
                for key, value in log_settings.items():
                    data["Setting"].append(key)
                    data["Variable"].append(value)
            log_df = pd.DataFrame(data)
            pdtabulate = lambda df: tabulate(df, headers='keys', tablefmt='psql', showindex=False)
            print(pdtabulate(log_df))
    if "conf_option" and "conf_variable" in args:
        if args.conf_option:
            with open("config/log.json") as f:
                current_log_settings = json.load(f)
                print("The previous setting for " + args.conf_option + " is " + str(current_log_settings[args.conf_option]))
                current_log_settings[args.conf_option] = args.conf_variable
            os.remove("config/log.json")
            with open("config/log.json", 'w') as f:
                json.dump(current_log_settings, f, indent=4)
            print(args.conf_option + " has now been changed to " + str(args.conf_variable))
    # response to http log based options
    if "list_http" in args:
        data = {
            "Setting": [],
            "Variable": []
        }
        if args.list_http:
            with open("config/http_analysis.json") as f:
                log_settings = json.load(f)
                for key, value in log_settings.items():
                    data["Setting"].append(key)
                    data["Variable"].append(value)
            log_df = pd.DataFrame(data)
            pdtabulate = lambda df: tabulate(df, headers='keys', tablefmt='psql', showindex=False)
            print(pdtabulate(log_df))
    if "http_option" and "http_variable" in args:
        if args.http_option:
            with open("config/http_analysis.json") as f:
                current_log_settings = json.load(f)
                print("The previous setting for " + args.http_option + " is " + str(current_log_settings[args.http_option]))
                current_log_settings[args.http_option] = args.http_variable
            os.remove("config/http_analysis.json")
            with open("config/http_analysis.json", 'w') as f:
                json.dump(current_log_settings, f, indent=4)
            print(args.http_option + " has now been changed to " + str(args.http_variable))

    # HTTP Analysis
    # example
    # python.exe .\__main__.py cli http -f .\test_data\LR_HTTP_S_data.csv
    print(args)
    if "http_file" in args:
        allow_list = []
        if args.http_allow:
            with open(args.http_allow) as f:
                allow_list = json.load(f)
        with open("config/log.json") as f:
            log_settings = json.load(f)
            http_df = http_analyser.build_df(args.http_file, log_settings["timestamp"], log_settings["direction"],
                                             log_settings["src_ip"], log_settings["dst_ip"], log_settings["dst_host"],
                                             log_settings["dst_port"], log_settings["sent_bytes"],
                                             log_settings["delimiter"], allow_list)

            http_df = http_analyser.analyse_time(http_df, log_settings["timestamp"])
            http_df = http_analyser.analyse_transfer(http_df, log_settings["timestamp"], log_settings["sent_bytes"])
            http_analyser.calculate_score(http_df)

    # DNS Analysis
    # example
    # python.exe .\__main__.py cli dns -f .\test_data\LR_DNS_data.csv
    if "dns_file" in args:
        allow_list = []
        if args.dns_allow:
            with open(args.dns_allow) as f:
                allow_list = json.load(f)
        with open("config/log.json") as f:
            log_settings = json.load(f)
            dns_df = dns_analyser.build_df(args.dns_file, log_settings["url"], log_settings["delimiter"])
            dns_analyser.analyse_subdomains(dns_df, log_settings["url"], allow_list)

    # SMB Analysis
    # TODO: add internal to internal for SMB traffic
main()
