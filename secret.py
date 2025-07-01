#!/usr/bin/env python3

import requests
import re
import sys
import os
import argparse
import glob
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

def parser_input(input):
    urls = []
    if input.startswith("http://") or input.startswith("https://") or input.startswith("file://"):
        urls.append(input)
    elif os.path.isfile(input):
        if input.endswith(".xml"):
            with open(input, "r") as file:
                content = file.read()
                urls += re.findall(r"<request base64=\"true\"(.+?)</request>", content)
        elif input.endswith(".txt"):
            with open(input, "r") as file:
                lines = file.readlines()
                for line in lines:
                    line = line.strip()
                    if line.startswith("http"):
                        urls.append(line)
        else:
            urls.append("file://" + os.path.abspath(input))
    elif os.path.isdir(input):
        for root, dirs, files in os.walk(input):
            for file in files:
                urls.append("file://" + os.path.join(root, file))
    elif "*" in input:
        for file in glob.glob(input):
            urls.append("file://" + os.path.abspath(file))
    else:
        print(f"[-] Invalid input: {input}")
        sys.exit(1)
    return urls

def analyze(url, regex, pattern, output, onlyjs):
    secrets = []
    try:
        if url.startswith("file://"):
            filepath = url[7:]
            with open(filepath, "r", errors="ignore") as f:
                content = f.read()
        else:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(url, headers=headers, timeout=10)
            content = response.text

        if onlyjs:
            if not url.endswith(".js"):
                print(f"[-] Skipping non-JS URL: {url}")
                return
            js_files = [url]
        else:
            soup = BeautifulSoup(content, "html.parser")
            script_tags = soup.find_all("script", src=True)
            js_files = [urljoin(url, tag['src']) for tag in script_tags]

        for js_url in js_files:
            try:
                if js_url.startswith("file://"):
                    js_path = js_url[7:]
                    with open(js_path, "r", errors="ignore") as js_file:
                        js_content = js_file.read()
                else:
                    js_response = requests.get(js_url, headers=headers, timeout=10)
                    js_content = js_response.text

                for line_num, line in enumerate(js_content.splitlines(), 1):
                    for name, reg in regex.items():
                        for match in re.finditer(reg, line):
                            result = f"[{name}] {match.group()} (Line {line_num}) in {js_url}"
                            print(result)
                            secrets.append(result)
            except Exception as e:
                print(f"[-] Error reading JS file {js_url}: {e}")

        if output and secrets:
            with open(output, "a") as out_file:
                for secret in secrets:
                    out_file.write(secret + "\n")

    except Exception as e:
        print(f"[-] Error analyzing {url}: {e}")

def main():
    parser = argparse.ArgumentParser(description="SecretFinder - Discover sensitive data in JS files")
    parser.add_argument("-i", "--input", help="Input: URL, file, folder or Burp XML", required=True)
    parser.add_argument("-o", "--output", help="Output file for found secrets")
    parser.add_argument("-r", "--regex", help="Custom regex pattern")
    parser.add_argument("-p", "--pattern", help="Custom pattern name")
    parser.add_argument("-j", "--js", help="Only analyze provided JS files, skip HTML parsing", action="store_true")
    args = parser.parse_args()

    # Built-in regex patterns
    regex = {
        'General API Key': r'(?i)\bAPI\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Token': r'(?i)\bAPI\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Access Key': r'(?i)\bAPI\s*Access\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Secret': r'(?i)\bAPI\s*Secret\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key (v1)': r'(?i)\bAPI\s*Key\s*\(v1\)\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key (v2)': r'(?i)\bAPI\s*Key\s*\(v2\)\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'OAuth API Key': r'(?i)OAuth\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'OAuth Access Token': r'(?i)OAuth\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'Bearer API Token': r'(?i)Bearer\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key for Service': r'(?i)\bAPI\s*Key\s*for\s*Service\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'REST API Key': r'(?i)REST\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Access Token': r'(?i)\bAPI\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'Public API Key': r'(?i)Public\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'Private API Key': r'(?i)Private\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key (Secure)': r'(?i)API\s*Key\s*\(Secure\)\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'Custom API Key': r'(?i)Custom\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Authorization Key': r'(?i)API\s*Authorization\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Auth Key': r'(?i)API\s*Auth\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Access Credentials': r'(?i)API\s*Access\s*Credentials\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API User Key': r'(?i)API\s*User\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Client Key': r'(?i)API\s*Client\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Service Key': r'(?i)API\s*Service\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Request Key': r'(?i)API\s*Request\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Authentication Token': r'(?i)API\s*Authentication\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key (User)': r'(?i)API\s*Key\s*\(User\)\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'App API Key': r'(?i)App\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Gateway Key': r'(?i)API\s*Gateway\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'Webhook API Key': r'(?i)Webhook\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key for Integration': r'(?i)API\s*Key\s*for\s*Integration\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key for App': r'(?i)API\s*Key\s*for\s*App\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'API Key for Service (v2)': r'(?i)API\s*Key\s*for\s*Service\s*\(v2\)\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'Zoom API Key': r'(?i)Zoom\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Zoom OAuth Access Token': r'(?i)Zoom\s*OAuth\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Trello API Key': r'(?i)Trello\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Twilio API Key': r'(?i)Twilio\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Unity Analytics API Key': r'(?i)Unity\s*Analytics\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Vercel API Key': r'(?i)Vercel\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Wix API Key': r'(?i)Wix\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Xero API Key': r'(?i)Xero\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Yandex API Key': r'(?i)Yandex\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Zoho API Key': r'(?i)Zoho\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'AirTable API Key': r'(?i)AirTable\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Postmark API Key': r'(?i)Postmark\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Mailtrap API Key': r'(?i)Mailtrap\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Sendinblue API Key': r'(?i)Sendinblue\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'MongoDB Atlas API Key': r'(?i)MongoDB\s*Atlas\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Okta API Token': r'(?i)Okta\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Plaid API Key': r'(?i)Plaid\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Intercom API Key': r'(?i)Intercom\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Veeva Vault API Key': r'(?i)Veeva\s*Vault\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Freshservice API Key': r'(?i)Freshservice\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Freshchat API Key': r'(?i)Freshchat\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Kaltura API Key': r'(?i)Kaltura\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Pusher API Key': r'(?i)Pusher\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Sentry API Key': r'(?i)Sentry\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Segment API Key': r'(?i)Segment\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Twitch API Key': r'(?i)Twitch\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Mixpanel API Key': r'(?i)Mixpanel\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Shopify API Key': r'(?i)Shopify\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Twilio API SID': r'(?i)Twilio\s*AccountSID\s*[:=]?\s*[\'"]?([A-Za-z0-9]{34})[\'"]?',
    'Mailgun API Key': r'(?i)Mailgun\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Heroku API Token': r'(?i)Heroku\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'GitHub OAuth Token': r'(?i)GitHub\s*OAuth\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{36})[\'"]?',
    'GitHub SSH Key': r'(?i)GitHub\s*SSH\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
    'Google API Key': r'(?i)Google\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{39})[\'"]?',
    'AWS Secret Access Key': r'(?i)AWS\s*Secret\s*Access\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
    'Google Cloud API Key': r'(?i)Google\s*Cloud\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{39})[\'"]?',
    'Amazon Cognito Identity Pool Key': r'(?i)Amazon\s*Cognito\s*Identity\s*Pool\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Auth0 API Key': r'(?i)Auth0\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Xero OAuth Token': r'(?i)Xero\s*OAuth\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'DigitalOcean API Key': r'(?i)DigitalOcean\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Trello OAuth Token': r'(?i)Trello\s*OAuth\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Mastodon API Key': r'(?i)Mastodon\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Auth0 API Token': r'(?i)Auth0\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Strava API Key': r'(?i)Strava\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Braintree API Key': r'(?i)Braintree\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Vimeo API Key': r'(?i)Vimeo\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Wistia API Key': r'(?i)Wistia\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'ABTasty API Key': r'(?i)ABTasty\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32})[\'"]?',
    'Algolia API Key': r'(?i)Algolia\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Amplitude API Keys': r'(?i)Amplitude\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Asana Access Token': r'(?i)Asana\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{30})[\'"]?',
    'AWS Access Key ID': r'(?i)AWS\s*Access\s*Key\s*ID\s*[:=]?\s*[\'"]?([AIAZ0-9]{20})[\'"]?',
    'AWS Secret Key': r'(?i)AWS\s*Secret\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
    'Azure Application Insights APP ID': r'(?i)Azure\s*Application\s*Insights\s*APP\s*ID\s*[:=]?\s*[\'"]?([A-Za-z0-9\-]{36})[\'"]?',
    'Azure API Key': r'(?i)Azure\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Bazaarvoice Passkey': r'(?i)Bazaarvoice\s*Passkey\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Bing Maps API Key': r'(?i)Bing\s*Maps\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Bit.ly Access Token': r'(?i)Bit\.ly\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Branch.io Key': r'(?i)Branch\.io\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Branch.io Secret': r'(?i)Branch\.io\s*Secret\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'BrowserStack Access Key': r'(?i)BrowserStack\s*Access\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Buildkite Access Token': r'(?i)Buildkite\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'ButterCMS API Key': r'(?i)ButterCMS\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32})[\'"]?',
    'Calendly API Key': r'(?i)Calendly\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Contentful Access Token': r'(?i)Contentful\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'captchaKey': r'(?i)captchaKey\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
    'CircleCI Access Token': r'(?i)CircleCI\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Cloudflare API Key': r'(?i)Cloudflare\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Cypress Record Key': r'(?i)Cypress\s*Record\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'DataDog API Key': r'(?i)DataDog\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Delighted API Key': r'(?i)Delighted\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Deviant Art Access Token': r'(?i)Deviant\s*Art\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Deviant Art Secret': r'(?i)Deviant\s*Art\s*Secret\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Dropbox API Key': r'(?i)Dropbox\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Facebook Access Token': r'(?i)Facebook\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Facebook AppSecret': r'(?i)Facebook\s*AppSecret\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Firebase API Key': r'(?i)Firebase\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{39})[\'"]?',
    'Firebase Cloud Messaging (FCM)': r'(?i)Firebase\s*Cloud\s*Messaging\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'FreshDesk API Key': r'(?i)FreshDesk\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Github Client ID': r'(?i)GitHub\s*Client\s*ID\s*[:=]?\s*[\'"]?([A-Za-z0-9]{20})[\'"]?',
    'Github Client Secret': r'(?i)GitHub\s*Client\s*Secret\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'GitHub Token': r'(?i)GitHub\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{36})[\'"]?',
    'GitHub Private SSH Key': r'(?i)GitHub\s*Private\s*SSH\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
    'GitLab Personal Access Token': r'(?i)GitLab\s*Personal\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'GitLab Runner Registration Token': r'(?i)GitLab\s*Runner\s*Registration\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Google Cloud Service Account Credentials': r'(?i)Google\s*Cloud\s*Service\s*Account\s*Credentials\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{39})[\'"]?',
    'Google Maps API Key': r'(?i)Google\s*Maps\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{39})[\'"]?',
    'Google Recaptcha Key': r'(?i)Google\s*Recaptcha\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{40})[\'"]?',
    'Grafana Access Token': r'(?i)Grafana\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Help Scout OAUTH': r'(?i)Help\s*Scout\s*OAUTH\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Heroku API Key': r'(?i)Heroku\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'HubSpot API Key': r'(?i)HubSpot\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Infura API Key': r'(?i)Infura\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Instagram Access Token': r'(?i)Instagram\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Instagram Basic Display API': r'(?i)Instagram\s*Basic\s*Display\s*API\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Instagram Graph API': r'(?i)Instagram\s*Graph\s*API\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Ipstack API Key': r'(?i)Ipstack\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Iterable API Key': r'(?i)Iterable\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'JumpCloud API Key': r'(?i)JumpCloud\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Keen.io API Key': r'(?i)Keen\.io\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'LinkedIn OAUTH': r'(?i)LinkedIn\s*OAUTH\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Lokalise API Key': r'(?i)Lokalise\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Loqate API Key': r'(?i)Loqate\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'MailChimp API Key': r'(?i)MailChimp\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'MailGun Private Key': r'(?i)MailGun\s*Private\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Mapbox API Key': r'(?i)Mapbox\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Microsoft Azure Tenant': r'(?i)Microsoft\s*Azure\s*Tenant\s*[:=]?\s*[\'"]?([A-Za-z0-9]{36})[\'"]?',
    'Microsoft SAS': r'(?i)Microsoft\s*Shared\s*Access\s*Signature\s*[:=]?\s*[\'"]?([A-Za-z0-9]{40})[\'"]?',
    'Microsoft Teams Webhook': r'(?i)Microsoft\s*Teams\s*Webhook\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'New Relic Personal API Key': r'(?i)New\s*Relic\s*Personal\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'New Relic REST API': r'(?i)New\s*Relic\s*REST\s*API\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'NPM token': r'(?i)NPM\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{36})[\'"]?',
    'OpsGenie API Key': r'(?i)OpsGenie\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'PagerDuty API token': r'(?i)PagerDuty\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Paypal client id': r'(?i)Paypal\s*Client\s*ID\s*[:=]?\s*[\'"]?([A-Za-z0-9]{30})[\'"]?',
    'Paypal client secret key': r'(?i)Paypal\s*Client\s*Secret\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Pendo Integration Key': r'(?i)Pendo\s*Integration\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'PivotalTracker API Token': r'(?i)PivotalTracker\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Razorpay API Key': r'(?i)Razorpay\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Razorpay API Secret Key': r'(?i)Razorpay\s*API\s*Secret\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Salesforce API Key': r'(?i)Salesforce\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'SauceLabs Access Key': r'(?i)SauceLabs\s*Username\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'SendGrid API Token': r'(?i)SendGrid\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Shodan API Key': r'(?i)Shodan\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Slack API Token': r'(?i)Slack\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Slack Webhook': r'(?i)Slack\s*Webhook\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Sonarcloud API Key': r'(?i)Sonarcloud\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Spotify Access Token': r'(?i)Spotify\s*Access\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Square API Key': r'(?i)Square\s*API\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Stripe Live Token': r'(?i)Stripe\s*Live\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Telegram Bot API Token': r'(?i)Telegram\s*Bot\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Travis CI API token': r'(?i)Travis\s*CI\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Twilio Account SID': r'(?i)Twilio\s*Account\s*SID\s*[:=]?\s*[\'"]?([A-Za-z0-9]{34})[\'"]?',
    'Twilio Auth Token': r'(?i)Twilio\s*Auth\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Twitter API Secret': r'(?i)Twitter\s*API\s*Secret\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Twitter Bearer Token': r'(?i)Twitter\s*Bearer\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Visual Studio App Center API Token': r'(?i)Visual\s*Studio\s*App\s*Center\s*API\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
       'google_api'     : r'AIza[0-9A-Za-z-_]{35}',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    }

    # Add custom pattern if provided
    if args.regex and args.pattern:
        regex[args.pattern] = args.regex

    # Process input (file or single)
    urls = []
    if os.path.isfile(args.input) and args.input.endswith(".txt"):
        with open(args.input, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    urls.extend(parser_input(line))
    else:
        urls = parser_input(args.input)

    for url in urls:
        print(f"[+] Analyzing {url}")
        analyze(url, regex, args.pattern, args.output, args.js)

if __name__ == "__main__":
    main()
