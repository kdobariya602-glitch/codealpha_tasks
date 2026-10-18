# Suricata Lab Setup Notes

1. Install Suricata using the official documentation for your operating system.
2. Back up your existing `suricata.yaml` before editing it.
3. Add the EVE JSON output settings from `eve-json-output-example.yaml` into the matching existing `outputs` section; do not replace the whole config.
4. Add the example rules from `codealpha-local.rules` to your local rules file, then make sure that file is included by your configuration.
5. Validate the configuration using the test command supported by your installed version (commonly `suricata -T -c /path/to/suricata.yaml`).
6. Start Suricata on an interface or PCAP in an authorized lab. Check the official documentation for platform-specific interface syntax.
7. Find the generated `eve.json` and paste newline-delimited JSON into the dashboard parser. Each line must be one JSON object; do not wrap the events in an array.
8. Record actual alerts, configuration, screenshots, and false-positive checks in your report.

These snippets are examples, not a guaranteed drop-in configuration for every Suricata version or operating system. Validate and tune before use. Only monitor networks you own or are authorized to monitor.
