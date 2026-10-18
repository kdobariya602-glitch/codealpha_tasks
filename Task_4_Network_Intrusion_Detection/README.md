# CodeAlpha Task 4 — Network Intrusion Detection System

## Start here
Watch `Task_4_Simple_English_Tutorial.mp4` first.

## Run the dashboard
1. Install Python 3.10 or newer.
2. Double-click `RUN_WEBSITE_WINDOWS.bat`.
3. Open `http://127.0.0.1:5004`.
4. Click Load Sample Alerts to understand the table.
5. To parse actual events, paste newline-delimited Suricata EVE JSON and click Parse Log.

## Suricata support files
See `suricata_lab/` for example local rules, an EVE JSON output snippet, and setup notes. Merge snippets carefully into your existing configuration and validate them for your installed Suricata version.

## Important
The Flask dashboard does not itself capture packets or run Suricata. Sample alerts are synthetic. To claim live intrusion detection, you must configure and run Suricata separately on an authorized lab/network and record actual results.
