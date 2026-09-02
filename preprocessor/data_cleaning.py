import pandas as pd 
import numpy as np

df = pd.read_csv('combined_flows_labeled.csv')

print('Before cleaning:', df.shape)

# 1. Drop rows with NaN or infinity (common from zero-duration flows / division errors)
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

print("After dropping NaN/Inf:", df.shape)

# 2. Narrow to features + label 
selected_columns = [
    'Flow Duration',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd IAT Std',
    'Bwd IAT Std',
    'SYN Flag Count',
    'ACK Flag Count',
    'Label'
]

df_narrowed = df[selected_columns]

print('After narrowing to state features:', df_narrowed.shape)

df_narrowed.to_csv('cleaned_narrow_flows.csv', index=False)
print("Saved cleaned_narrow_flows.csv")