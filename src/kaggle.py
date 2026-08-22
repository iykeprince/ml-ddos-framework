import os

def download_sample_dataset():
    print("Fetching the 21MB CIC-DDoS2019 evaluation dataset from Kaggle...")
    # This uses the Kaggle API to download the specific small dataset
    os.system("kaggle datasets download -d aymen/ddos-evaluation-dataset-cic-ddos2019 -p ../data/raw/ --unzip")
    print("Download complete! File saved in data/raw/")

if __name__ == "__main__":
    download_sample_dataset()