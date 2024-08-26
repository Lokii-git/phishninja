import pandas as pd
import ast
import argparse
import sys
import os
import logging
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Banner
def print_banner():

    version = 'v1.0.0'
    creator = '@lokii-git'
    banner = f"""

  ___ _    _    _      _  _ _       _      
 | _ \ |_ (_)__| |_   | \| (_)_ _  (_)__ _ 
 |  _/ ' \| (_-< ' \  | .` | | ' \ | / _` | {creator}
 |_| |_||_|_/__/_||_| |_|\_|_|_||_|/ \__,_| {version}
                                 |__/      
                                                                                                         
    Extracting Data from Phishing Test Results
    ===================================
    Instructions:
    1. Use the --file or -f flag to specify the path to the phishing test results CSV file. 
    2. Optionally, use --output or -o to specify the output file name. 
    3. Use --verbose or -v for detailed output.

    Usage:
    python3 phishninja.py --file phishing_results.csv --output filtered_results.csv --verbose

    """
    print(banner)

# List of additional Microsoft IPs to be excluded
microsoft_ips = set([
    '40.94.35.51', '20.29.104.211', '20.29.217.202', '20.41.15.125',
    '20.69.122.32', '20.7.159.167', '20.245.197.116', '20.245.23.33',
    '20.245.235.33', '20.242.28.84', '23.99.227.98', '23.101.122.145',
    '23.101.201.52', '4.154.11.187', '4.155.104.111', '4.155.105.193',
    '52.136.118.207', '52.143.122.98', '52.149.182.255', '52.151.52.78',
    '52.152.128.128', '52.176.50.116', '52.191.199.168', '172.203.124.33',
    '13.88.21.140', '13.92.186.145', '40.71.125.77', '20.230.224.3',
    '20.119.242.15', '172.174.39.181', '104.42.169.232', '13.91.127.81',
    '40.78.42.207', '40.84.39.216', '20.236.59.68', '172.202.88.108',
    '172.172.71.142', '20.12.213.197', '20.169.253.245', '40.77.111.31',
    '20.22.207.237', '137.117.86.228', '172.172.8.186', '168.61.170.4',
    '172.172.53.23', '40.83.213.64', '13.93.221.37', '40.83.38.140',
    '172.176.114.168', '20.169.128.221', '20.232.147.16', '137.135.50.44',
    '172.172.71.29', '20.125.60.209', '172.173.164.206', '20.231.19.87',
    '23.101.197.87', '20.124.252.33', '20.12.213.244', '13.67.128.227',
    '20.109.170.252', '20.109.112.126', '40.77.57.90', '13.86.29.63',
    '172.176.117.104', '13.89.233.158', '172.173.214.111', '20.112.16.235',
    '40.83.148.99', '13.87.247.220', '20.109.170.252', '20.124.252.33',
    '74.235.70.86', '20.228.107.36', '23.99.8.58', '104.43.232.151',
    '13.89.233.158', '20.36.19.251', '20.230.31.128', '20.12.213.244',
    '13.87.247.220', '13.67.128.227', '172.173.175.203', '20.230.31.128',
    '40.83.148.99', '20.12.213.244', '20.124.252.33', '172.212.146.7',
    '172.173.214.111', '23.99.8.58'
])

def load_configuration(file_path):
    try:
        with open(file_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.error("Configuration file not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error("Error decoding configuration file.")
        sys.exit(1)

# Function to parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='PhishNinja: Extract data from phishing test results files.')
    parser.add_argument('--file', '-f', help='Path to the phishing test results CSV file.')
    parser.add_argument('--output', '-o', default='filtered_phishing_results.csv', help='Path to the output CSV file.')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output.')
    parser.add_argument('--config', '-c', help='Path to the configuration JSON file.')
    return parser.parse_args()

# Parse arguments
args = parse_args()

# Print banner
print_banner()

# Interactive mode if file is not provided
if not args.file:
    args.file = input("Please enter the path to the phishing test results CSV file: ")

if not os.path.isfile(args.file):
    logging.error("File does not exist or cannot be accessed.")
    sys.exit(1)

# Set logging level based on verbose flag
if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)

# Load configuration if provided
if args.config:
    config = load_configuration(args.config)
    microsoft_ips.update(config.get('additional_ips', []))

# Validate input file
try:
    data = pd.read_csv(args.file)
    required_columns = ['message', 'details', 'time']
    if not all(col in data.columns for col in required_columns):
        logging.error(f"Input file must contain the following columns: {', '.join(required_columns)}")
        sys.exit(1)
except pd.errors.EmptyDataError:
    logging.error("The file is empty.")
    sys.exit(1)
except pd.errors.ParserError:
    logging.error("Error parsing the file. Please ensure it is in CSV format.")
    sys.exit(1)
except Exception as e:
    logging.error(f"Unexpected error while loading file: {e}")
    sys.exit(1)

# Filter the data to keep only rows where the message is 'Clicked Link'
data = data[data['message'] == 'Clicked Link']

# Extract IP address from details
def extract_ip(details):
    try:
        if isinstance(details, str):
            return ast.literal_eval(details).get('browser', {}).get('address', None)
    except (ValueError, SyntaxError, KeyError) as e:
        logging.error(f"Error processing row: {e}")
        return None

data['ip'] = data['details'].apply(extract_ip)
data = data.dropna(subset=['ip'])  # Drop rows where IP couldn't be extracted

# Convert timestamp to datetime
data['timestamp'] = pd.to_datetime(data['time'])

# Round timestamp to nearest minute to handle close clicks
data['timestamp_rounded'] = data['timestamp'].dt.round('T')

# Remove entries with IPs starting with 40.94 or in the list of additional Microsoft IPs
data = data[~data['ip'].str.startswith('40.94')]
data = data[~data['ip'].isin(microsoft_ips)]

# Remove exact duplicate rows based on email, rounded timestamp, and IP
data_unique = data.drop_duplicates(subset=['email', 'timestamp_rounded', 'ip'])

# Further remove duplicates within a 5-minute window
data_unique = data_unique.sort_values(by=['email', 'ip', 'timestamp'])
data_unique = data_unique.groupby(['email', 'ip', pd.Grouper(key='timestamp', freq='5T')]).first().reset_index()

# Sort by email
data_unique_sorted = data_unique.sort_values(by='email')

# Save the filtered and sorted data
try:
    data_unique_sorted.to_csv(args.output, index=False)
    logging.info(f"Filtered data saved to {args.output}")
except IOError:
    logging.error("Error writing to the output file.")
    sys.exit(1)
except Exception as e:
    logging.error(f"Unexpected error while saving file: {e}")
    sys.exit(1)
