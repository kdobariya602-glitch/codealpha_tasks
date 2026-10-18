# Task 4 — Network Intrusion Detection System Report

## Objective
Set up network monitoring that detects suspicious activity, records alerts, and supports investigation and response.

## Components
- Flask dashboard for viewing example alerts and parsing EVE JSON
- Suricata example rules and EVE JSON configuration snippet in `suricata_lab/`
- Python requirements for the dashboard

## Lab setup — complete after actual configuration
- Operating system:
- Suricata version:
- Interface or PCAP used:
- Configuration test result:
- Rules enabled:
- EVE JSON file path:
- Dashboard URL:
- Date/time of test:

## Results — record actual observations
For each alert, record timestamp, source/destination, signature, severity, evidence, investigation, false-positive assessment, and action taken. Attach screenshots or sanitized log excerpts.

## Response workflow
1. Validate the alert and confirm timestamps and endpoints.
2. Correlate with other logs and expected network activity.
3. Determine whether it is benign, suspicious, or confirmed malicious.
4. Escalate or contain only under an approved incident-response process.
5. Preserve evidence and document the outcome.

## Limitations
The included dashboard is not a live sensor. Built-in sample alerts are synthetic. Example rules require validation and tuning. An alert alone is not proof of compromise.

## Conclusion
Write a conclusion only after completing the live lab test. If you only used sample data, label the result as a dashboard demonstration rather than a live NIDS test.
