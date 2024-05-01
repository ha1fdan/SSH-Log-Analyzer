import re
from collections import Counter
import requests

def get_country_iso(ip):
    try:
        response = requests.get(f"https://api.ha1fdan.xyz/{ip}")
        if response.status_code == 200:
            data = response.json()
            return data.get('country', {}).get('name')
        else:
            print(f"Failed to get data for IP: {ip}, Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed for IP: {ip}, Error: {e}")
    return None

def analyze_auth_log(filepath, frequency_threshold, country_filter):
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    not_filtered_country_ips = []

    try:
        with open(filepath, 'r') as file:
            log_content = file.read()

        ips = ip_pattern.findall(log_content)
        ip_count = Counter(ips)

        for ip, count in ip_count.items():
            if count > frequency_threshold:
                iso_code = get_country_iso(ip)
                if iso_code and iso_code != country_filter:
                    not_filtered_country_ips.append(ip)
                    print(f"IP Address: {ip} -> Count: {count} -> Country: {iso_code}")

        with open('firewall-cmd.txt', 'w') as f:
            for ip in not_filtered_country_ips:
                f.write(f"firewall-cmd --permanent --zone=drop --add-source={ip}\n")
            f.write(f"firewall-cmd --reload\n")

        with open('github_log.txt', 'a+') as f:
            for ip in not_filtered_country_ips:
                f.write(f"{ip}\n")

    except FileNotFoundError:
        print(f"Error: The file '{filepath}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
DEFAULT_COUNTRY = 'Denmark'
FREQUENCY_THRESHOLD = 50
AUTH_LOG_FILE = 'auth.log'
analyze_auth_log(AUTH_LOG_FILE, FREQUENCY_THRESHOLD, DEFAULT_COUNTRY)
