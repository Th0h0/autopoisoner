import requests
import argparse
import random
import re
from print_utils import *

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False, help= "file containing URLs to be tested")
parser.add_argument("--url", "-u", type=str, required=False, help= "url to be tested")
parser.add_argument("--verbose", "-v", action='store_true', help= "activate verbose mode")
parser.add_argument("--behavior", "-b", action='store_true', help= "activate a lighter version of verbose, highlighting interesting cache behavior")

args = parser.parse_args()

if not (args.file or args.url):
    parser.error('No input selected: Please add --file or --url.')

outputFile = open("output.txt", "a")
CANARY = "ndvyepenbvtidpvyzh.com"

headersToFuzz = {
    "x-forwarded-scheme": "http",
    "x-forwarded-host": CANARY,
    "x-forwarded-proto": "http",
    "x-http-method-override": "POST",
    "x-amz-website-redirect-location": CANARY,
    "x-rewrite-url": CANARY,
    "x-host": CANARY,
    "user-agent": CANARY,
    "handle": CANARY,
    "h0st": CANARY,
    "Transfer-Encoding": CANARY,
    "x-original-url": CANARY,
    "x-original-host": CANARY,
    "x-forwarded-prefix": CANARY,
    "x-amz-server-side-encryption": CANARY,
    "trailer": CANARY,
    "fastly-ssl": CANARY,
    "fastly-host": CANARY,
    "fastly-ff": CANARY,
    "fastly-client-ip": CANARY,
    "content-type": CANARY,
    "api-version": CANARY,
    "acunetix-header": CANARY,
    "accept-version": CANARY
    }

def canary_in_response(response : requests.Response):
    for val in response.headers.values():
        if CANARY in val:
            return True
    if CANARY in response.text:
        return True

    return False

def crawl_files(URL, response : requests.Response):
    responseText = response.text
    regexp1 = '(?<=src=")(\/[^\/].+?)(?=")'
    regexp2 = '(?<=href=")(\/[^\/].+?)(?=")'

    filesURL = re.findall(regexp1, responseText)
    filesURL += re.findall(regexp2, responseText)

    selectedFiles = []

    #Select two random extensions

    if len(filesURL) >= 2:
        selectedFiles = random.sample(filesURL,2)
    elif len(filesURL) == 1:
        selectedFiles = [filesURL[0]]

    for i in range(len(selectedFiles)):
        selectedFiles[i] = URL + selectedFiles[i]

    return selectedFiles

def use_caching(headers):
    if headers.get("X-Cache-Hits") or headers.get("X-Cache") or headers.get("Age") or headers.get("Cf-Cache-Status") or (headers.get("Cache-Control") and ("public" in headers.get("Cache-Control"))):
        return True
    else:
        return False

def vulnerability_confirmed(responseCandidate : requests.Response, url, randNum, buster):
    confirmationResponse = requests.get(f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False)
    if confirmationResponse.status_code == responseCandidate.status_code and confirmationResponse.text == responseCandidate.text:
        if canary_in_response(responseCandidate):
            if canary_in_response(confirmationResponse):
                return True
            else:
                return False
        else:
            return True
    else:
        return False

def base_request(url):
    randNum = str(random.randrange(9999999999999))
    buster = str(random.randrange(9999999999999))
    response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False)

    return response

def port_poisoning_check(url, initialResponse):
    randNum = str(random.randrange(9999999999999))
    buster = str(random.randrange(9999999999999))
    findingState = 0

    host = url.split("://")[1].split("/")[0]
    response = None
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers={"Host": f"{host}:8888"}, allow_redirects=False)
    except:
        return
    explicitCache = str(use_caching(response.headers)).upper()

    if response.status_code != initialResponse.status_code:
        findingState = 1
        potential_verbose_message("STATUS_CODE", args, url)
        if vulnerability_confirmed(response, url, randNum, buster):
            findingState = 2
            behavior_or_confirmed_message("CONFIRMED", "STATUS", explicitCache, url, outputFile=outputFile)
        else:
            potential_verbose_message("UNSUCCESSFUL", args)
            if args.behavior:
                behavior_or_confirmed_message("BEHAVIOR", "STATUS", explicitCache, url)

    elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
        findingState = 1
        potential_verbose_message("LENGTH", args, url)
        if vulnerability_confirmed(response, url, randNum, buster):
            findingState = 2
            behavior_or_confirmed_message("CONFIRMED", "LENGTH", explicitCache, url , outputFile=outputFile)

        else:
            potential_verbose_message("UNSUCCESSFUL", args)
            if args.behavior:
                behavior_or_confirmed_message("BEHAVIOR", "LENGTH", explicitCache, url)

    if findingState == 1:
        return "UNCONFIRMED"

def headers_poisoning_check(url, initialResponse):
    findingState = 0
    for header in headersToFuzz.keys():
        payload = {header: headersToFuzz[header]}
        randNum = str(random.randrange(9999999999999))
        buster = str(random.randrange(9999999999999))
        response = None
        try:
            response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers=payload, allow_redirects=False)
        except:
            continue
        explicitCache = str(use_caching(response.headers)).upper()

        if canary_in_response(response):
            findingState = 1
            potential_verbose_message("CANARY", args, url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message("CONFIRMED", "REFLECTION", explicitCache, url, header=header, outputFile=outputFile)

            else:
                potential_verbose_message("UNSUCCESSFUL", args)
                if args.behavior:
                    behavior_or_confirmed_message("BEHAVIOR", "REFLECTION", explicitCache, url, header=header)

        elif response.status_code != initialResponse.status_code:
            findingState = 1
            potential_verbose_message("STATUS_CODE", args, url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message("CONFIRMED", "STATUS", explicitCache, url, header=header, outputFile=outputFile)
            else:
                potential_verbose_message("UNSUCCESSFUL", args)
                if args.behavior:
                    behavior_or_confirmed_message("BEHAVIOR", "STATUS", explicitCache, url, header=header)

        elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
            findingState = 1
            potential_verbose_message("LENGTH", args, url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message("CONFIRMED", "LENGTH", explicitCache, url, header=header, outputFile=outputFile)
            else:
                potential_verbose_message("UNSUCCESSFUL", args)
                if args.behavior:
                    behavior_or_confirmed_message("BEHAVIOR", "LENGTH", explicitCache, url, header=header)

    if findingState == 1:
        return "UNCONFIRMED"

def crawl_and_scan(url, initialResponse):
    selectedURLS = crawl_files(url, initialResponse)
    for url in selectedURLS:
        potential_verbose_message("CRAWLING", args, url)
        initResponse = base_request(url)
        port_poisoning_check(url, initResponse)
        headers_poisoning_check(url, initResponse)


def cache_poisoning_check(url):
    initialResponse = None
    try:
        initialResponse = base_request(url)
    except:
        potential_verbose_message("ERROR", args, url)

    if initialResponse and initialResponse.status_code in (200, 304, 302, 301, 401, 402, 403):
        resultPort = port_poisoning_check(url, initialResponse)
        resultHeaders = headers_poisoning_check(url, initialResponse)
        if resultHeaders == "UNCONFIRMED" or resultPort == "UNCONFIRMED":
            crawl_and_scan(url, initialResponse)

def main():
    if args.file:
        inputFile = open(args.file, "r")
        for url in inputFile:
            url = url.replace("\n", "")
            cache_poisoning_check(url)
        inputFile.close()

    if args.url:
        cache_poisoning_check(args.url)

main()

outputFile.close()
