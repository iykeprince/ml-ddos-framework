import pandas as pd 

benign = pd.read_csv('baseline_flows.csv')
benign['Label'] = 0

malicious = pd.read_csv('attack_flows.csv')
malicious['Label'] = 1

combined = pd.concat([benign, malicious], ignore_index=True)
combined.to_csv('combined_flows_labeled.csv', index=False)

print(benign.shape, malicious.shape, combined.shape)
