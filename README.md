# Python Port Scanner
A port scanner written in Python using multi-threaded scanning. This tool is able to scan target IPs or domains
for open ports while attempting to grab service banners, and export the results to JSON or CSV formats.

## Features:
- Multithreaded scanning.
- Banner grabbing to identify services (e.g., HTTP headers).
- Data export to .json or .csv.
- Just python's standard library.

## Prerequisites:
Python 3.6 or higher.

## Usage:
Run the script from the command line

### Command Line Arguements:
- `-d` or `--domain`: Target IP or domain   |   REQUIRED   |   None default
- `-p` or `--ports`: Port range (e.g. 80 or 1-1000)     |   Default: 1-1024
- `-t` or `--threads`: Maximum number of concurrent threads |   Default: 100
- `-b` or `--banner`: Enable banner grabbing    |   Default: False
- `--timeout`: Socket connection timeout (in seconds)   |   Default: 1.0
- `-o` or `--output`: Filename to save results  |   None default

### Examples:
- python port_scanner.py -d scanme.nmap.org
- python port_scanner.py -d scanme.nmap.org -b
- python port_scanner.py -d 192.168.1.1 -p 1-500 -b
- python port_scanner.py -d 192.168.1.1 -p 1-500 -b -t 200
- python port_scanner.py -d scanme.nmap.org -p 1-100 -t 200 --timeout 0.5 -b -o results.json