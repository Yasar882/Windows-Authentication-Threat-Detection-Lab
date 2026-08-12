# Lab Architecture

```text
Kali Linux 192.168.42.3
        |
        | authentication test
        v
Windows 10 Pro 192.168.42.5
        |
        | Event ID 4625
        v
Splunk Universal Forwarder
        |
        | TCP/9997
        v
Physical Windows PC 192.168.42.1
Splunk Enterprise
        |
        v
index=windows
```

Ports:
- Splunk Web: TCP/8000
- Splunk receiving: TCP/9997
- Windows RDP: TCP/3389
