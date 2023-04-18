# golira🦍

golira is a CLI tool created for Security Analysts who don't want to leave their terminal. <br>
It takes the IP address you want to check as a first argument and then runs it through VirusTotal's API. <br>
After that, golira returns the output in a pretty readable format which shows if the IP is harmless, malicious, suspicious or undetected.

## Installation

Simply clone the repo, build it, then run golira

```bash
  git clone https://github.com/WiktorGmur/golira.git
  cd golira
  go build golira.go
  ./golira {Suspicious_IP_Here}
```
    
