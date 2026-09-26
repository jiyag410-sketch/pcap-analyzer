# Sample Captures

Actual `.pcap` files are gitignored (they can be large and sometimes contain
sensitive data), so this folder is empty in the repo. To test the analyzer,
download real forensic sample captures from:

- https://www.malware-traffic-analysis.net/ — real malware traffic captures
  with write-ups, great for testing the beaconing and DNS tunneling detectors
- https://wiki.wireshark.org/SampleCaptures — general protocol sample captures
- Or generate your own: `tcpdump -i eth0 -w samples/test.pcap`

Drop any `.pcap`/`.pcapng` file here and run:

```
python main.py samples/your_capture.pcap --report reports/report.md
```
