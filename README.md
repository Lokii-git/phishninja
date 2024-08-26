# PhishNinja

**PhishNinja** is a powerful Python script designed to extract and filter data from phishing test results. Whether you're analyzing large datasets or simply looking to clean up your test results, PhishNinja helps you identify and isolate meaningful interactions, such as when a user clicks on a phishing link. It also filters out noise, such as interactions from known Microsoft IP addresses, ensuring you get the most relevant insights.

## Features

- **Click Event Filtering**: Extracts rows where users clicked on phishing links.
- **IP Address Extraction**: Extracts IP addresses from JSON-encoded fields within the phishing test data.
- **Microsoft IP Filtering**: Excludes known Microsoft IP addresses, with an option to add more via configuration.
- **Timestamp Rounding**: Rounds timestamps to the nearest minute to group close-click events.
- **Duplicate Removal**: Removes duplicate entries within a 5-minute window to ensure clean data.
- **CSV Output**: Saves filtered results to a CSV file, making further analysis straightforward.

## Requirements

- Python 3.6+
- Pandas library (`pip install pandas`)

## Installation

1. **Clone the repository**:

    ```sh
    git clone https://github.com/yourusername/phishninja.git
    cd phishninja
    ```

2. **Install dependencies**:

    ```sh
    pip install pandas
    ```

## Usage

You can run PhishNinja directly from the command line. The script offers several options to customize its behavior:

```sh
python phishninja.py --file <phishing_test_results.csv> [--output <filtered_results.csv>] [--verbose] [--config <config.json>]
```
Options
--file, -f: Path to the phishing test results CSV file (required).
--output, -o: Path to the output CSV file. Defaults to filtered_phishing_results.csv.
--verbose, -v: Enables detailed output.
--config, -c: Path to a configuration JSON file to add more IPs to be filtered.
Examples
Basic usage:

```sh
python phishninja.py --file phishing_results.csv
```
Specify output file:

```sh
python phishninja.py --file phishing_results.csv --output cleaned_results.csv
```
Enable verbose mode:
```sh
python phishninja.py --file phishing_results.csv --verbose
```
Use a configuration file:
```sh
python phishninja.py --file phishing_results.csv --config additional_ips.json
```
Configuration
You can use a configuration file to add additional IPs to filter out. The file should be in JSON format:

```json
{
    "additional_ips": [
        "192.168.1.1",
        "10.0.0.1"
    ]
}
```

Contributing
Feel free to fork the repository, submit issues, or open pull requests. Contributions are welcome!

License
This project is licensed under the MIT License - see the LICENSE file for details.
