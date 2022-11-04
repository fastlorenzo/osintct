#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Lorenzo Bernardi"
__version__ = "0.1.0"
__license__ = "MIT"

import csv
import datetime
import getopt
import os
import socket
import sys
import traceback

import psycopg2
import psycopg2.extras
import requests


def print_usage():
    """Print usage"""
    print(
        "Usage: ./osintct.py -d|--domain DOMAIN [-r|--resolve] [-o|--output FILENAME]"
    )
    print("--domain: domain name to check for (use TLD)")
    print(
        "--resolve: try resolving IP addresses for subdomains found (can take some time)"
    )
    print("--output: output file (CSV format) - default: output.csv")


def check_domain(domain, resolve, output):
    """Main entry point of the app"""
    print(f"Checking domain: {domain}")
    results_crtsh = check_domain_crtsh(domain)
    results_fb = check_domain_fb(domain)

    results_all = {"crt.sh": results_crtsh, "Facebook CT": results_fb["data"]}
    results = parse_results(results_all)
    if resolve:
        print("Resolving domain names to IP addresses")
    for (domain_name, domain_info) in results.items():
        if resolve:
            try:
                ip_addresses = "\n".join(
                    list(
                        {
                            addr[-1][0]
                            for addr in socket.getaddrinfo(domain_name, 0, 0, 0, 0)
                        }
                    )
                )
            # pylint: disable=broad-except
            except Exception:
                ip_addresses = "not found"
        else:
            ip_addresses = "not checked"
        domain_info["resolved_ips"] = ip_addresses

    export_results(results, output)


def check_domain_crtsh(domain):
    """Check domain on crt.sh"""
    print(f"Checking domain [{domain}] on crt.sh")

    conn_string = "host='crt.sh' dbname='certwatch' user='guest'"

    conn = psycopg2.connect(conn_string)
    conn.set_session(autocommit=True)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor)

    query = """
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
    """

    cursor.execute(query.format(domain))

    domains = []
    for result in cursor:
        domains.append(
            {
                "domains": [result.common_name],
                "not_valid_after": result.not_valid_after.replace(
                    tzinfo=datetime.timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%S%z"),
                "not_valid_before": result.not_valid_before.replace(
                    tzinfo=datetime.timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%S%z"),
                "cert_hash_sha256": result.cert_hash_sha256.hex(),
                "issuer_name": result.issuer_name,
            }
        )

    return domains


def check_domain_fb(domain):
    """Check domain on Facebook CT"""
    print(f"Checking domain [{domain}] on Facebook CT")
    access_token = os.getenv("FB_ACCESS_TOKEN")
    limit = 20000
    try:
        # pylint: disable=line-too-long
        res = requests.get(
            f"https://graph.facebook.com/certificates?query={domain}&access_token={access_token}&limit={limit}&fields=cert_hash_sha256,domains,issuer_name,not_valid_after,not_valid_before",
            timeout=60,
        )

        if res.status_code != 200:
            print(f"Error getting certificates from Facebook CT: {res.text}")
            return {}

        return res.json()

    # pylint: disable=broad-except
    except Exception as err:
        print(f"Error getting certificates from Facebook CT: {err}")
        traceback.print_exc()
        return {}


def export_results(results, output):
    """Export results to CSV file"""
    csv_columns = [
        "domain",
        "first_time_seen",
        "not_valid_before",
        "not_valid_after",
        "last_issuer",
        "is_expired",
        "resolved_ips",
        "found_in",
    ]
    to_print = []
    for domain in results:
        tmp = results[domain]
        del tmp["first_issuer"]
        del tmp["issuers"]
        del tmp["hash_history"]
        del tmp["current_hash"]
        tmp["first_time_seen"] = tmp["first_time_seen"].strftime("%Y-%m-%d %H:%M")
        tmp["not_valid_before"] = tmp["not_valid_before"].strftime("%Y-%m-%d %H:%M")
        tmp["not_valid_after"] = tmp["not_valid_after"].strftime("%Y-%m-%d %H:%M")
        tmp["domain"] = domain
        tmp["found_in"] = "/".join(tmp["found_in"])
        to_print.append(tmp)

    try:
        with open(output, "w", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns, delimiter=";")
            writer.writeheader()
            for data in to_print:
                writer.writerow(data)
        print(f"Results saved to {output}")
    except IOError:
        print("I/O error")


def parse_results(results):
    """Parse results"""
    domains = {}
    for provider in results:
        print(f"Parsing results from {provider}: {len(results[provider])}")
        for res in results[provider]:
            not_valid_after = datetime.datetime.strptime(
                res["not_valid_after"], "%Y-%m-%dT%H:%M:%S%z"
            )
            not_valid_before = datetime.datetime.strptime(
                res["not_valid_before"], "%Y-%m-%dT%H:%M:%S%z"
            )

            for domain in res["domains"]:
                if domain in domains:
                    if domains[domain]["first_time_seen"] > not_valid_before:
                        domains[domain]["first_time_seen"] = not_valid_before
                        domains[domain]["first_issuer"] = res["issuer_name"]

                    if domains[domain]["not_valid_after"] < not_valid_after:
                        domains[domain]["not_valid_after"] = not_valid_after
                        domains[domain]["not_valid_before"] = not_valid_before
                        domains[domain]["last_issuer"] = res["issuer_name"]
                        domains[domain]["current_hash"] = res["cert_hash_sha256"]
                        domains[domain][
                            "is_expired"
                        ] = not_valid_after < datetime.datetime.now(
                            not_valid_after.tzinfo
                        )

                    if res["issuer_name"] not in domains[domain]["issuers"]:
                        domains[domain]["issuers"].append(res["issuer_name"])

                    if res["cert_hash_sha256"] not in domains[domain]["hash_history"]:
                        domains[domain]["hash_history"].append(res["cert_hash_sha256"])

                    if provider not in domains[domain]["found_in"]:
                        domains[domain]["found_in"].append(provider)

                else:
                    domains[domain] = {
                        "first_time_seen": not_valid_before,
                        "not_valid_after": not_valid_after,
                        "not_valid_before": not_valid_before,
                        "hash_history": [res["cert_hash_sha256"]],
                        "current_hash": res["cert_hash_sha256"],
                        "first_issuer": res["issuer_name"],
                        "last_issuer": res["issuer_name"],
                        "issuers": [res["issuer_name"]],
                        "is_expired": not_valid_after
                        < datetime.datetime.now(not_valid_after.tzinfo),
                        "found_in": [provider],
                    }
    print(f"Identified {len(domains)} unique sub-domains")
    return domains


if __name__ == "__main__":

    DOMAIN = None
    RESOLVE = False
    OUTPUT = "output.csv"

    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "d:ro:", ["domain=", "resolve", "output="])
    # pylint: disable=broad-except
    except Exception:
        print("Error parsing arguments")

    for opt, arg in opts:
        if opt in ["-d", "--domain"]:
            DOMAIN = arg
        elif opt in ["-r", "--resolve"]:
            RESOLVE = True
        elif opt in ["-o", "--output"]:
            OUTPUT = arg

    if not DOMAIN:
        print_usage()
        sys.exit(2)

    check_domain(DOMAIN, RESOLVE, OUTPUT)
