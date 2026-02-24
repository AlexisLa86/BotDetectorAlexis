import re
import os
from collections import Counter
from datetime import datetime
parsed_data = []


log_pattern = r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?\s+\[(?P<timestamp>.*?)\]\s+"(?P<request>.*?)"\s+(?P<status>\d{3})'


sample_line = '178.33.227.239 - - [24/Feb/2026:09:00:00 +0000] "GET /cart HTTP/1.1" 200 14607 "https://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'

match = re.search(log_pattern, sample_line)
if match:
    print(match.groupdict()) # This returns a clean Python dictionary!

with open("access.log", 'r') as f:
    for line in f:
        match = re.search(log_pattern, line)
        if match:
            # 5. If it matches, grab the dictionary and add it to our list
            parsed_data.append(match.groupdict())
            # 6. Check if it worked
print(f"Successfully parsed {len(parsed_data)} lines!")

# List Comprehension
all_ips = [entry['ip'] for entry in parsed_data]

# list into the Counter
ip_counts = Counter(all_ips)

# leaders
print("\n--- TOP 5 MOST ACTIVE IPs ---")
for ip, count in ip_counts.most_common(5):
    print(f"IP: {ip} | Total Requests: {count}")
# Filter for requests that resulted in a 404
failed_requests = [entry for entry in parsed_data if entry['status'] == '404']

# IPs potentionly guilty 
suspect_ips = Counter([entry['ip'] for entry in failed_requests])

# URLs they were trying to access
requested_paths = Counter([entry['request'] for entry in failed_requests])

print(f"\n--- Total 404 Errors Found: {len(failed_requests)} ---")
print("\n--- Top IPs Triggering 404s ---")
print(suspect_ips.most_common(5))

print("\n--- Top Most 'Missing' Files (Suspected Bot Targets) ---")
print(requested_paths.most_common(5))

# which hours get the most "404" errors
hourly_errors = Counter()

for entry in parsed_data:
    if entry['status'] == '404':
        # Example timestamp: 24/Feb/2026:09:00:00 +0000
        
        raw_time = entry['timestamp'].split(' ')[0]
        
        # str to datetime
        dt_obj = datetime.strptime(raw_time, '%d/%b/%Y:%H:%M:%S')
        
        # Record the hour
        hourly_errors[dt_obj.hour] += 1

print("\n--- 404 Errors by Hour of Day ---")
for hour in sorted(hourly_errors.keys()):
    print(f"Hour {hour:02d}:00 - {hourly_errors[hour]} errors")
# 1. Define our high-risk targets
blacklisted_paths = ['wp-login.php', '.env', 'admin', 'config']

# 2. Initialize the set
flagged_ips = set()

# 3. Logic: If they hit a bad path, they are a bot. 
# If they have more than X 404s, they are a bot.
for entry in parsed_data:
    # Check for sensitive paths
    if any(path in entry['request'] for path in blacklisted_paths):
        flagged_ips.add(entry['ip'])



for ip, count in suspect_ips.items():
    if count > 5:
        flagged_ips.add(ip) 

import streamlit as st
import re
import pandas as pd
from collections import Counter
from datetime import datetime


log_regex = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\d+)'

@st.cache_data # This keeps the dashboard fast
def process_logs():
    parsed_data = []
    
    with open('access.log', 'r') as f:
        for line in f:
            match = re.search(log_regex, line)
            if match:
                parsed_data.append(match.groupdict())
    return parsed_data

data = process_logs()
df = pd.DataFrame(data) # Convert to a DataFrame for easy charting

# UI

failed_requests = [entry for entry in data if entry['status'] == '404']
suspect_ips = Counter([entry['ip'] for entry in failed_requests])
requested_paths = Counter([entry['request'] for entry in failed_requests])

# Hourly Logic

daily_errors = Counter()
hourly_errors = Counter()

for entry in failed_requests:
    # Example timestamp: 24/Feb/2026:09:00:00
    raw_time = entry['timestamp'].split(' ')[0]
    dt_obj = datetime.strptime(raw_time, '%d/%b/%Y:%H:%M:%S')
    
    # Track the specific date (e.g., "2026-02-24")
    daily_errors[dt_obj.date()] += 1
    
    # Still track the hour for the "Peak Hour" metric
    hourly_errors[dt_obj.hour] += 1

# Flagging Logic
blacklisted_paths = ['wp-login.php', '.env', 'admin', 'config']
flagged_ips = set()
for entry in data:
    if any(path in entry['request'] for path in blacklisted_paths):
        flagged_ips.add(entry['ip'])

# --- 2. THE VISUALS ---
st.title("🛡️ Cyber-Sentry: Logic-Driven SIEM")

# Metrics variables
c1, c2, c3 = st.columns(3)
c1.metric("Failed Requests (404)", len(failed_requests))
c2.metric("Flagged Bot IPs", len(flagged_ips), delta="High Priority", delta_color="inverse")
c3.metric("Peak Attack Hour", f"{max(hourly_errors, key=hourly_errors.get)}:00")

# Temporal Analysis (Line Chart of hourly_errors)
st.subheader("📅 Attack Timeline (404 Errors by Hour)")
# Counter to a sorted DataFrame for Streamlit
chart_data = pd.DataFrame(sorted(hourly_errors.items()), columns=['Hour', 'Errors']).set_index('Hour')
st.line_chart(chart_data)

# Bottom Row: Probes and Suspects
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("🔎 Top Suspected Bot Targets")
    # Show requested_paths Counter
    path_df = pd.DataFrame(requested_paths.most_common(10), columns=['Path', 'Attempts'])
    st.bar_chart(path_df.set_index('Path'))

with col_right:
    st.subheader("🏴 Highest Risk IP Addresses")
    # Show suspect_ips Counter
    ip_df = pd.DataFrame(suspect_ips.most_common(10), columns=['IP Address', '404 Count'])

    st.dataframe(ip_df, use_container_width=True)



