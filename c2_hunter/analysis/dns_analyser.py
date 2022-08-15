import pandas as pd
from tabulate import tabulate
import json

pd.set_option('display.max_rows', 500)
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 1000)

# built using https://github.com/activecm/rita/blob/master/pkg/explodeddns/analyzer.go


def build_df(file, url_var, delimiter_var):
    columns_to_filter = [url_var]
    dns_df = pd.read_csv(file, sep=delimiter_var)

    # change domain column to string
    dns_df[url_var] = dns_df[url_var].astype(str)

    # get all rows and only the required columns
    dns_df = dns_df.loc[:, columns_to_filter]

    return dns_df


def analyse_subdomains(dns_df, url_var, allow_list):
    pd.set_option('display.max_columns', None)
    pd.options.mode.chained_assignment = None  # default='warn'
    # get the unique values for the domains
    dns_df = dns_df.drop_duplicates(url_var)
    dns_df = dns_df.reset_index(drop=True)
    # split domains into subdomains, dropping the top level domain to clean up data
    dns_df["Super Domain"] = dns_df[url_var].apply(lambda x: x.split(".")[-2]
                             if len(x.split(".")) > 1 else x)
    dns_df["Sub Domains"] = dns_df[url_var].apply(lambda x: x.split(".")[:-1])
    dns_df = dns_df.sort_values("Super Domain", ascending=True)
    dns_df = dns_df.reset_index(drop=True)
    # aggregate duplicate Super Domains and count
    dns_df["Sub Domain count"] = dns_df.groupby(["Super Domain"])["Super Domain"].transform("count")
    dns_df = dns_df.sort_values("Sub Domain count", ascending=False)
    dns_df = dns_df.reset_index(drop=True)
    # transfer final results to final dataframe
    dns_final_df = dns_df.groupby(by=["Super Domain", "Sub Domain count"], as_index=False).first()
    dns_final_df = dns_final_df.sort_values("Sub Domain count", ascending=False)
    while not dns_df.empty:
        # join previous super domain with next sudomain
        def join_super_and_sub(super, sub):
            if type(sub):
                if len(sub) > 1:
                    return sub[-2] + "." + super
                else:
                    return super
        dns_df["Super Domain Temp"] = dns_df.apply(lambda x: join_super_and_sub(x["Super Domain"], x["Sub Domains"]), axis=1)
        # aggregate unique and count occurances of new super domains
        dns_df["count temp"] =  dns_df.groupby(["Super Domain Temp"])["Super Domain Temp"].transform("count")
        # replace perm columns with temp
        dns_df["Super Domain"] = dns_df["Super Domain Temp"].values
        dns_df["Sub Domain count"] = dns_df["count temp"].values
        # remove joined element from sub domains
        dns_df["Sub Domains"] = dns_df["Sub Domains"].apply(lambda x: x[:-1])
        # transfer final results to final dataframe
        dns_temp_df = dns_df.groupby(by=["Super Domain", "Sub Domain count"], as_index=False).first()
        dns_final_df = dns_final_df.append(dns_temp_df)
        dns_final_df = dns_final_df.sort_values("Sub Domain count", ascending=False)
        # remove line if Sub Domains list is empty
        dns_df = dns_df[dns_df["Sub Domains"].astype(bool)]

    # clean up final df
    dns_final_df = dns_final_df.drop(columns=['Domain (Impacted)', 'Sub Domains', 'Super Domain Temp', 'count temp'])
    dns_final_df.rename(columns={'Super Domain': 'Domain'}, inplace=True)

    # remove allow listed domains
    # remove allow list items
    for i in allow_list:
        dns_final_df = dns_final_df[dns_final_df["Domain"] != i]

    dns_final_df.reset_index(drop=True, inplace=True)
    pdtabulate = lambda df: tabulate(df, headers='keys', tablefmt='psql', showindex=False)
    # adjust the floor value for displaying results
    # default 100
    with open("config/dns_analysis.json") as f:
        settings = json.load(f)
        print(pdtabulate(dns_final_df.loc[dns_final_df["Sub Domain count"] > int(settings["Score Floor"])]))
    return dns_final_df


