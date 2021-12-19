import json
import pandas as pd
filename = 'test4'
with open (filename + '.json') as f:
    data = json.load(f)
    
df = pd.json_normalize(data, record_path=['signals'],meta=['distance','trail'])
df = df.drop_duplicates()
pd.set_option("max_rows", None)
print(df.groupby(['mac','trail','dataRate']).agg({'rssi': ['median','count','std']}))
df.to_csv( filename + '.csv')

