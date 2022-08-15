import pandas as pd
import numpy as np
import json

from tabulate import tabulate
from pprint import pprint

pd.set_option('display.max_rows', 500)
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 1000)



# built using https://github.com/activecm/rita/blob/master/pkg/beacon/analyzer.go

# assign field/column names to variables


def build_df(file, timestamp_var, direction_var, src_ip_var, dst_ip_var, dst_host_var, dst_port_var,
             sent_bytes_var, delimiter_var, allow_list):
    timestamp = timestamp_var
    # The given time stamp in Log Date is not very specific, only going to the second
    direction = direction_var
    src_ip = src_ip_var
    dst_ip = dst_ip_var
    dst_host = dst_host_var
    dst_port = dst_port_var
    sent_bytes = sent_bytes_var
    delimiter = delimiter_var

    columns_to_filter = [timestamp, src_ip, dst_ip, dst_host, dst_port, sent_bytes, direction]
    columns_to_groupby = [src_ip, dst_ip, dst_host, dst_port]
    http_df = pd.read_csv(file, sep=delimiter)
    http_df.info()


    # get all rows and only the required columns
    http_df = http_df.loc[:, columns_to_filter]

    # remove all none Outbound connections
    http_df = http_df[http_df["Direction"] == "Outbound"]

    # re-classigy time stamp
    http_df[timestamp] = pd.to_datetime(http_df[timestamp])

    # Group connections for Analysis
    http_df = http_df.groupby(columns_to_groupby).agg(list)
    http_df.reset_index(inplace=True)

    # calculate the connection Count by counting the length of the aggregated timestamp collumn
    http_df['conn_count'] = http_df[timestamp].apply(lambda x: len(x))

    # Remove short sessions
    # the lower the "Short Connections" setting the more connections included in the analysis
    # default 20s
    with open("config/http_analysis.json") as f:
        settings = json.load(f)
        http_df = http_df.loc[http_df['conn_count'] > int(settings["Short Connections"])]

    # remove allow list items
    for i in allow_list:
        http_df = http_df[http_df[dst_ip] != i]

    # Sort by timestamp
    http_df[timestamp] = http_df[timestamp].apply(lambda x: sorted(x))
    return http_df


def analyse_time(http_df, timestamp_var):
    # Calculate the time delta

    # Convert timestamp list into a Series object, get time delta between each timestamp,
    # convert the result back into a list and assign it to the 'deltas' column
    http_df['deltas'] = http_df[timestamp_var].apply(lambda x: pd.Series(x).diff().dt.seconds.dropna().tolist())


    # variables for time delta dispersion
    # both calculations are assessing the spread of the data

    # For the first of the calculations we use Bowley Skewness
    # https://www.statisticshowto.com/bowley-skewness/
    # User traffic will have a high level of skewness, whilst beacons will have a lower level of skewness (uniform).

    # calculate the the lower, mid and upper quartiles
    http_df['tsLow'] = http_df['deltas'].apply(lambda x: np.percentile(np.array(x), 25))
    http_df['tsMid'] = http_df['deltas'].apply(lambda x: np.percentile(np.array(x), 50))
    http_df['tsHigh'] = http_df['deltas'].apply(lambda x: np.percentile(np.array(x), 75))
    # calculate the left and right hand expression in step 3
    http_df['tsBowleyNum'] = http_df['tsLow'] + http_df['tsHigh'] - 2*http_df['tsMid']
    http_df['tsBowleyDen'] = http_df['tsHigh'] - http_df['tsLow']
    # apply the BowleyNumber and Bowley Density to calculate the skewness
    # We are less concerned about whether it is positive or negative more the magnitude of the skew.
    http_df['tsSkew'] = http_df[['tsLow', 'tsMid', 'tsHigh', 'tsBowleyNum', 'tsBowleyDen']].apply(
        lambda x: x['tsBowleyNum'] / x['tsBowleyDen']
        # add a check to ensure the denominator is not 0 if it is skewness if given a value of 0.0
        if x['tsBowleyDen'] != 0 and x['tsMid'] != x['tsLow'] and x['tsMid'] != x['tsHigh'] else 0.0, axis=1
        )
    return http_df

def analyse_transfer(http_df, timestamp_var, sent_bytes_var):
    # For the second calculation we calculate the Median Absolute Deviation (MAD)
    # https://www.statisticshowto.com/median-absolute-deviation/
    # User traffic will have a large MAD value, whilst beacons will have a small mad Value (close to 0)
    http_df['tsMadm'] = http_df['deltas'].apply(lambda x: np.median(np.absolute(np.array(x) - np.median(np.array(x)))))

    # we calculate the total time between the first and last connection in the data
    http_df['tsConnDiv'] = http_df[timestamp_var].apply(lambda x: (x[-1].to_pydatetime() - x[0].to_pydatetime()).seconds)


    # variables for data size dispersion
    # We do the same calculations for data size, refer to time stamp notes for info
    http_df['dsLow'] = http_df[sent_bytes_var].apply(lambda x: np.percentile(np.array(x), 25))
    http_df['dsMid'] = http_df[sent_bytes_var].apply(lambda x: np.percentile(np.array(x), 50))
    http_df['dsHigh'] = http_df[sent_bytes_var].apply(lambda x: np.percentile(np.array(x), 75))
    http_df['dsBowleyNum'] = http_df['dsLow'] + http_df['dsHigh'] - 2*http_df['dsMid']
    http_df['dsBowleyDen'] = http_df['dsHigh'] - http_df['dsLow']
    http_df['dsSkew'] = http_df[['dsLow', 'dsMid', 'dsHigh', 'dsBowleyNum', 'dsBowleyDen']].apply(
        lambda x: x['dsBowleyNum'] / x['dsBowleyDen']
        if x['dsBowleyDen'] != 0 and x['dsMid'] != x['dsLow'] and x['dsMid'] != x['dsHigh'] else 0.0, axis=1
        )
    http_df['dsMadm'] = http_df[sent_bytes_var].apply(lambda x: np.median(np.absolute(np.array(x) - np.median(np.array(x)))))
    return http_df

def calculate_score(http_df):
    # Score calculation

    # all the variables in the calculation will trend towards 1.0 with the closer to 1.0 being more beacon like behaviour.

    # Time delta score calculation
    http_df['tsSkewScore'] = 1.0 - abs(http_df['tsSkew'])
    # If jitter is greater than 30 seconds, say 90 seconds, MadmScore might be zero
    # It depends on how the jitter is implemented.
    # Increase time Jitter adjust to increase sensitivity for larger jitter
    # default 30s
    with open("config/http_analysis.json") as f:
        settings = json.load(f)
        http_df['tsMadmScore'] = 1.0 - (http_df['tsMadm'] / int(settings["Jitter Seconds"]))
    http_df['tsMadmScore'] = http_df['tsMadmScore'].apply(lambda x: 0 if x < 0 else x)
    http_df['tsConnCountScore'] = (http_df['conn_count']) / http_df['tsConnDiv']
    http_df['tsConnCountScore'] = http_df['tsConnCountScore'].apply(lambda x: 1.0 if x > 1.0 else x)
    http_df['tsScore'] = (((http_df['tsSkewScore'] + http_df['tsMadmScore'] +
                            http_df['tsConnCountScore']) / 3.0) * 1000) / 1000

    # Data size score calculation of sent bytes
    http_df['dsSkewScore'] = 1.0 - abs(http_df['dsSkew'])
    # If data jitter is greater than 128 bytes, say 300 bytes, MadmScore might be zero
    # Depends on how the jitter is implemented.
    # Increase data Jitter adjust to increase sensitivity for larger jitter
    # default 32 bytes
    with open("config/http_analysis.json") as f:
        settings = json.load(f)
        http_df['dsMadmScore'] = 1.0 - (http_df['dsMadm'] / int(settings["Jitter Data"]))
    http_df['dsMadmScore'] = http_df['dsMadmScore'].apply(lambda x: 0 if x < 0 else x)
    # Perfect beacons don't send to much data since they are idle and just checking in,
    # division by high number makes the score less sensitive.
    # default 65535
    with open("config/http_analysis.json") as f:
        settings = json.load(f)
        http_df['dsSmallnessScore'] = 1.0 - (http_df['dsMid'] / int(settings["Data Transfer"]))
    http_df['dsSmallnessScore'] = http_df['dsSmallnessScore'].apply(lambda x: 0 if x < 0 else x)
    http_df['dsScore'] = (((http_df['dsSkewScore'] + http_df['dsMadmScore'] + http_df['dsSmallnessScore']) / 3.0)
                          * 1000) / 1000

    # Overal Score calculation
    http_df['Score'] = (http_df['dsScore'] + http_df['tsScore']) / 2

    http_df.sort_values(by='Score', ascending=False, inplace=True, ignore_index=True)

    # clean up dataframe
    http_df.rename(columns={'IP Address (Origin)': 'Source', "IP Address (Impacted)": "Destination",
                            "TCP/UDP Port (Impacted)": "Port", "conn_count": "Connections",
                            "Host (Impacted) KBytes Rcvd": "KBs Sent", "tsConnDiv": "Total Time (s)"}, inplace=True)
    collumns_to_display = ['Score', 'Source', "Destination", "Port", "Connections", "Total Time (s)"]

    # show highish scoring traffic
    pdtabulate = lambda df: tabulate(df, headers='keys', tablefmt='psql', showindex=False)
    # adjust the floor value for displaying results
    # default 0.8 (must be < 1)
    with open("config/http_analysis.json") as f:
        settings = json.load(f)
        print(pdtabulate(http_df.loc[http_df['Score'] > float(settings["Score Floor"]), collumns_to_display]))
    return

