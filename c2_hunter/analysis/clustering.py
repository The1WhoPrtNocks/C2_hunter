import pandas as pd
import numpy as np
from zat import dataframe_to_matrix
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

df = pd.read_csv("test_data\HTTP_Demo.csv")


features = ["Object", "Command", "Duration", "Host (Impacted) KBytes Sent", "IP Address (Origin)",
            "IP Address (Impacted)", "Hostname (Impacted)", "Log Date", "Malicious Tag", "TCP/UDP Port (Impacted)"]
feature_df = df[features]



def fit_transform(self, input_df, normalize=True, nan_replace=-999, copy=True):
    """Convert the dataframe to a matrix (numpy ndarray)
    Args:
        input_df (dataframe): The dataframe to convert
        normalize (bool): Boolean flag to normalize numeric columns (default=True)
    """
    self.nan_replace = nan_replace

    # Copy the dataframe (if wanted)
    _internal_df = input_df.copy() if copy else input_df

    # Convert object columns to categorical
    self.object_to_categorical(_internal_df)

    # Convert categorical NaNs
    self.fit_category_nans(_internal_df)

    # Lock categories to specific values (important for train/predict consistency)
    self.lock_categorical(_internal_df)

    # Sanity Check
    self.sanity_check_categorical(_internal_df)

    # Normalize numeric columns (mean normalize, sometimes called 'standardizing')
    if normalize:
        self.normalize_numeric(_internal_df)

    # Remove any numerical NaNs (categorical NaNs were removed above)
    for column in _internal_df.select_dtypes(include='number').columns:
        _internal_df[column].fillna(self.nan_replace, inplace=True)

    # Drop any columns that aren't numeric or categorical
    for column in list(_internal_df.select_dtypes(exclude=['number', 'category']).columns):
        print('Dropping {:s} column...'.format(column))
    _internal_df = _internal_df.select_dtypes(include=['number', 'category'])

    # Capture all the column/dtype information from the dataframe
    self.column_names = _internal_df.columns.to_list()
    for column in _internal_df.columns:
        self.dtype_map[column] = _internal_df[column].dtype

    # Now with every thing setup, call the dummy_encoder, convert to ndarray and return
    return pd.get_dummies(_internal_df).to_numpy(dtype=np.float32)


df_matrix = dataframe_to_matrix.DataFrameToMatrix().fit_transform(feature_df)
pca = PCA(n_components=2).fit_transform(df_matrix)


# Helper method for scatter/beeswarm plot
def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev

kmeans = KMeans(n_clusters=24).fit_predict(df_matrix)

df['x'] = jitter(pca[:, 0]) # PCA X Column
df['y'] = jitter(pca[:, 1]) # PCA Y Column
df['cluster'] = kmeans

show_fields = [ "Log Date", "IP Address (Origin)", "IP Address (Impacted)", "Hostname (Impacted)",
                "Host (Impacted) KBytes Sent", "TCP/UDP Port (Impacted)", "Malicious Tag", "cluster"]

selector = df["Malicious Tag"] == True
df.to_csv("All_cluster.csv", index=False)
df[selector].to_csv("TP_Clusters.csv", index=False)


cluster_groups = df[show_fields].groupby('cluster')

pd.set_option('display.width', 1000)
for key, group in cluster_groups:
    print(group.head(), '\n')
    print('Rows in Cluster: {:d}'.format(len(group)))


