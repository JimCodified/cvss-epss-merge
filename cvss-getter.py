# open the CSV file ~/Downloads/epss_scores-2023-06-29.csv
# then connect to the API endpoint https://services.nvd.nist.gov/rest/json/cves/2.0
# and for each CVE ID in the CSV file, retrieve the CVSS V3 score from the API using the ?cveId= parameter


import csv
import requests
import json
import sys
import os
import time
import datetime
import argparse
import logging
import logging.handlers
import re
import urllib3
import urllib.parse
import urllib.request
import urllib.error


# set up logging
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
# handler = logging.handlers.SysLogHandler(address = '/dev/log')
# formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
# handler.setFormatter(formatter)
# logger.addHandler(handler)


# set up command line argument parsing
parser = argparse.ArgumentParser(description='Retrieve CVSS V3 scores from the NVD API for a list of CVE IDs.')
#parser.add_argument('-f', '--file', help='CSV file containing CVE IDs', required=True)
parser.add_argument('-o', '--output', help='Output file for CVSS V3 scores', required=True)
#parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
# args = parser.parse_args()


# set up variables
csv_file = "/Users/jimarmstrong/Downloads/epss_scores-2023-06-29-short.csv"
output_file = "/Users/jimarmstrong/Downloads/cvss_map.csv"
# output_file = args.output
#verbose = args.verbose
cve_ids = []
cve_scores = []




# disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# read the CSV file
with open(csv_file, newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',', quotechar='"')
    for row in reader:
        cve_ids.append(row[0])


# connect to the NVD API and retrieve the CVSS V3 scores for each CVE ID
start_date = datetime.datetime(2021, 1, 1, 0, 0, 0, 0)
format = ("%Y-%m-%dT%H:%M:%S.%f")
max_days = datetime.timedelta(days=120)
start_idx = 0
more_cves = True
while more_cves:
    end_date = start_date + max_days
    print('start_date: ' + start_date.strftime(format) + ' end_date: ' + end_date.strftime(format))
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=' + start_date.strftime(format) + '&pubEndDate=' + end_date.strftime(format) + '&resultsPerPage=2000&startIndex=' + str(start_idx)
    #    logger.debug('url: ' + url)
    response = requests.get(url, verify=False)
    if response.status_code == 200:
#        logger.debug('response: ' + str(response.status_code))
        data = response.json()
    res_per_pg = 2000
    res_start = data['startIndex']
    res_total = data['totalResults']
    for vuln in data['vulnerabilities']:
        cve = vuln['cve']['id']
        if 'cvssMetricV31' in vuln['cve']['metrics']:
            score = vuln['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        else:
            score = 'N/A'
        cve_scores.append([cve, score])
        res_start += 1
    if res_start >= res_total and end_date >= datetime.datetime.now():
        more_cves = False
    elif res_start >= res_total and end_date < datetime.datetime.now():   
        start_idx = 0
        start_date = end_date + datetime.timedelta(days=1)
    else:
        start_idx += res_per_pg


# write the CVSS V3 scores to the output file
with open(output_file, 'w') as f:
    for item in cve_scores:
        f.write(item[0] + ',' + str(item[1]) + '\n')


