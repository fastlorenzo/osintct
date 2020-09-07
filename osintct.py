#!/usr/bin/env python3
'''
Module Docstring
'''

__author__ = 'Lorenzo Bernardi'
__version__ = '0.1.0'
__license__ = 'MIT'

import sys
import os
import getopt
import requests
import datetime
import csv
import traceback
import socket
import psycopg2
import psycopg2.extras

from pprint import pprint

def print_usage():
    print('Usage: ./osintct.py -d|--domain DOMAIN [-r|--resolve] [-o|--output FILENAME]')
    print('--domain: domain name to check for (use TLD)')
    print('--resolve: try resolving IP addresses for subdomains found (can take some time)')
    print('--output: output file (CSV format) - default: output.csv')

def check_domain(domain, resolve, output):
    print('Checking domain: %s' % domain)
    results_crtsh = check_domain_crtsh(domain)
    results_fb = check_domain_fb(domain)

    results_all = {
        'crt.sh': results_crtsh,
        'Facebook CT': results_fb['data']
    }
    results = parse_results(results_all)
    if resolve:
        print('Resolving domain names to IP addresses')
    for d in results:
        if resolve:
            try:
                ips = '\n'.join(list({addr[-1][0] for addr in socket.getaddrinfo(d, 0, 0, 0, 0)}))
            except Exception as e:
                ips = 'not found'
        else:
            ips = 'not checked'
        results[d]['resolved_ips'] = ips

    export_results(results, output)

def check_domain_crtsh(domain):
    print('Checking domain [%s] on crt.sh' % domain)

    conn_string = "host='crt.sh' dbname='certwatch' user='guest'"

    conn = psycopg2.connect(conn_string)
    conn.set_session(autocommit=True)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor)

    query = '''
    WITH ci AS (
    SELECT min(sub.CERTIFICATE_ID) ID,
           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
           x509_commonName(sub.CERTIFICATE) COMMON_NAME,
           x509_notBefore(sub.CERTIFICATE) NOT_VALID_BEFORE,
           x509_notAfter(sub.CERTIFICATE) NOT_VALID_AFTER,
           digest(sub.CERTIFICATE, 'sha256'::text) CERT_HASH_SHA256
        FROM (SELECT *
                  FROM certificate_and_identities cai
                  WHERE plainto_tsquery('certwatch', '{0}') @@ identities(cai.CERTIFICATE)
                      AND cai.NAME_VALUE ILIKE ('%' || '{0}' || '%')
                  LIMIT 10000
             ) sub
        GROUP BY sub.CERTIFICATE
    )
    SELECT ci.ISSUER_CA_ID,
        ca.NAME ISSUER_NAME,
        ci.COMMON_NAME,
        array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,
        ci.ID ID,
        le.ENTRY_TIMESTAMP,
        ci.NOT_VALID_BEFORE,
        ci.NOT_VALID_AFTER,
        ci.CERT_HASH_SHA256
    FROM ci
            LEFT JOIN LATERAL (
                SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
                    FROM ct_log_entry ctle
                    WHERE ctle.CERTIFICATE_ID = ci.ID
            ) le ON TRUE,
         ca
    WHERE ci.ISSUER_CA_ID = ca.ID
    ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;
    '''

    cursor.execute(query.format(domain))

    domains = []
    for r in cursor:
        domains.append({
            'domains': [ r.common_name ],
            'not_valid_after': r.not_valid_after.replace(tzinfo=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z'),
            'not_valid_before': r.not_valid_before.replace(tzinfo=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z'),
            'cert_hash_sha256': r.cert_hash_sha256.hex(),
            'issuer_name': r.issuer_name,
        })

    return domains

def check_domain_fb(domain):
    print('Checking domain [%s] on Facebook CT' % domain)
    access_token = os.getenv('FB_ACCESS_TOKEN')
    limit = 20000
    try:
        res = requests.get('https://graph.facebook.com/certificates?query=%s&access_token=%s&limit=%d&fields=cert_hash_sha256,domains,issuer_name,not_valid_after,not_valid_before' % (domain, access_token, limit))

        if res.status_code != 200:
            print('Error getting certificates from Facebook CT: %s' % res.text)
        else:
            return res.json()
            # fb_results = parse_fb_results(res.json())
            # return fb_results
    except Exception as e:
        print('Error getting certificates from Facebook CT: %s' % e)
        traceback.print_exc()

def export_results(results, output):
    csv_columns = ['domain','first_time_seen','not_valid_before','not_valid_after','last_issuer', 'is_expired', 'resolved_ips', 'found_in']
    to_print = []
    for d in results:
        tmp = results[d]
        del tmp['first_issuer']
        del tmp['issuers']
        del tmp['hash_history']
        del tmp['current_hash']
        tmp['first_time_seen'] = tmp['first_time_seen'].strftime("%Y-%m-%d %H:%M")
        tmp['not_valid_before'] = tmp['not_valid_before'].strftime("%Y-%m-%d %H:%M")
        tmp['not_valid_after'] = tmp['not_valid_after'].strftime("%Y-%m-%d %H:%M")
        tmp['domain'] = d
        tmp['found_in'] = '/'.join(tmp['found_in'])
        to_print.append(tmp)

    try:
        with open(output, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns, delimiter=';')
            writer.writeheader()
            for data in to_print:
                writer.writerow(data)
        print('Results saved to %s' % output)
    except IOError:
        print('I/O error')

def parse_results(results):
    domains = {}
    for provider in results:
        print('Parsing results from %s: %d' % (provider, len(results[provider])))
        for res in results[provider]:
            not_valid_after = datetime.datetime.strptime(res['not_valid_after'], '%Y-%m-%dT%H:%M:%S%z')
            not_valid_before = datetime.datetime.strptime(res['not_valid_before'], '%Y-%m-%dT%H:%M:%S%z')

            for d in res['domains']:
                if d in domains:
                    if domains[d]['first_time_seen'] > not_valid_before:
                        domains[d]['first_time_seen'] = not_valid_before
                        domains[d]['first_issuer'] = res['issuer_name']

                    if domains[d]['not_valid_after'] < not_valid_after:
                        domains[d]['not_valid_after'] = not_valid_after
                        domains[d]['not_valid_before'] = not_valid_before
                        domains[d]['last_issuer'] = res['issuer_name']
                        domains[d]['current_hash'] = res['cert_hash_sha256']
                        domains[d]['is_expired'] = not_valid_after < datetime.datetime.now(not_valid_after.tzinfo)

                    if res['issuer_name'] not in domains[d]['issuers']:
                        domains[d]['issuers'].append(res['issuer_name'])

                    if res['cert_hash_sha256'] not in domains[d]['hash_history']:
                        domains[d]['hash_history'].append(res['cert_hash_sha256'])

                    if provider not in domains[d]['found_in']:
                        domains[d]['found_in'].append(provider)

                else:
                    domains[d] = {
                        'first_time_seen': not_valid_before,
                        'not_valid_after': not_valid_after,
                        'not_valid_before': not_valid_before,
                        'hash_history': [ res['cert_hash_sha256'] ],
                        'current_hash': res['cert_hash_sha256'],
                        'first_issuer': res['issuer_name'],
                        'last_issuer': res['issuer_name'],
                        'issuers': [ res['issuer_name'] ],
                        'is_expired': not_valid_after < datetime.datetime.now(not_valid_after.tzinfo),
                        'found_in': [ provider ]
                    }
    print('Identified %d unique sub-domains' % len(domains))
    return domains


if __name__ == '__main__':

    domain = None
    resolve = False
    output = 'output.csv'

    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, 'd:ro:', ['domain=', 'resolve', 'output='])
    except:
        print('Error parsing arguments')

    for opt, arg in opts:
        if opt in ['-d', '--domain']:
            domain = arg
        elif opt in ['-r', '--resolve']:
            resolve = True
        elif opt in ['-o', '--output']:
            output = arg

    if not domain:
        print_usage()
        sys.exit(2)

    check_domain(domain, resolve, output)
