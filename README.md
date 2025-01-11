# Usage Instructions

## Overview
This script processes data for a specified number of days. You can customize the number of days to process using the `--days` argument or use the default value of 7 days.

## Prerequisites
- Python version: **3.10.10**

## Usage

Run the script with the following commands:

1. Process the last 30 days:
   ```bash
   python main.py --days 30
   ```

2. Process only the last day:
   ```bash
   python main.py --days 1
   ```

3. Use the default value (7 days):
   ```bash
   python main.py
   ```

## Notes
- Ensure all dependencies are installed before running the script.
- For more information, refer to the script's documentation or `help` flag:
  ```bash
  python main.py --help
  ```