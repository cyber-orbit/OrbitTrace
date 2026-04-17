# 🛰️ OrbitTrace — OSINT Investigation Framework

```
  ██████╗ ██████╗ ██████╗ ██╗████████╗████████╗██████╗  █████╗  ██████╗███████╗
 ██╔═══██╗██╔══██╗██╔══██╗██║╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██║   ██║██████╔╝██████╔╝██║   ██║      ██║   ██████╔╝███████║██║     █████╗  
 ██║   ██║██╔══██╗██╔══██╗██║   ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
 ╚██████╔╝██║  ██║██████╔╝██║   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
```

**OrbitTrace** is a modular, open-source OSINT (Open Source Intelligence) framework for investigating usernames, emails, phone numbers, domains, IP addresses, images, and files — entirely using free public data sources with no paid API keys required.

---

## ⚠️ Legal Disclaimer

> OrbitTrace is intended for **educational purposes**, **ethical security research**, and **investigating your own digital footprint only**.  
> Always obtain proper authorization before investigating any target.  
> The authors assume no liability for misuse. Use responsibly and in accordance with applicable laws.

---

## 📁 Project Structure

```
OrbitTrace/
├── orbittrace.py          # Main engine & dispatcher
├── cli.py                 # CLI argument parser
├── detector.py            # Auto-detect target type
├── requirements.txt       # Python dependencies
├── README.md
├── modules/
│   ├── username_scan.py   # 25+ social platform username check
│   ├── email_lookup.py    # Email validation, MX, Gravatar, breaches
│   ├── phone_lookup.py    # Phone carrier, location, VoIP detection
│   ├── domain_lookup.py   # WHOIS, DNS, subdomains, SSL
│   ├── ip_lookup.py       # Geolocation, reverse DNS, WHOIS, blacklists
│   ├── image_search.py    # EXIF extraction, GPS, reverse search links
│   └── metadata_scan.py   # PDF/Office/audio metadata extraction
├── utils/
│   ├── logger.py          # Colored terminal output
│   └── helpers.py         # HTTP, DNS, and utility functions
├── reports/
│   └── json_report.py     # Save results to JSON
└── output/                # Generated reports (auto-created)
```

---

## 🚀 Installation

### Requirements
- Python 3.8+
- pip

### Quick Setup

```bash
# 1. Clone or extract the project
cd OrbitTrace

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate       # Linux/Mac
# venv\Scripts\activate        # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Make the CLI executable (Linux/Mac)
chmod +x orbittrace.py

# 5. Run it!
python orbittrace.py --help
# or
python cli.py --help
```

### Optional: Install as a system command

```bash
# Create a wrapper script
echo '#!/bin/bash
python3 /path/to/OrbitTrace/cli.py "$@"' > /usr/local/bin/orbittrace
chmod +x /usr/local/bin/orbittrace
```

---

## 🔎 Usage

### Basic Syntax
```
python orbittrace.py <type> <target> [options]
# or
python cli.py <type> <target> [options]
```

### Supported Target Types

| Command    | Description                                    |
|------------|------------------------------------------------|
| `username` | Scan 25+ social platforms for a username       |
| `email`    | Email validation, MX records, Gravatar, breach |
| `phone`    | Carrier, location, VoIP/mobile detection       |
| `domain`   | WHOIS, DNS records, subdomain enum, SSL cert   |
| `ip`       | Geolocation, reverse DNS, ASN, blacklists      |
| `image`    | EXIF data, GPS coordinates, reverse search     |
| `file`     | Metadata from PDFs, Office docs, audio files   |
| `auto`     | Auto-detect the target type                    |

### Command Examples

```bash
# Username scan across 25+ platforms
python cli.py username johndoe

# Email investigation
python cli.py email target@example.com

# Phone lookup (include country code for best results)
python cli.py phone +15558675309

# Domain full scan
python cli.py domain example.com

# IP address investigation
python cli.py ip 8.8.8.8

# Image EXIF + GPS extraction
python cli.py image photo.jpg

# PDF/Office metadata
python cli.py file document.pdf

# Auto-detect type
python cli.py auto 8.8.8.8
python cli.py auto johndoe@gmail.com

# Verbose mode (show debug output)
python cli.py domain example.com --verbose

# Custom output directory
python cli.py username johndoe --output /tmp/osint-reports
```

---

## 📊 Module Details

### 🔍 Username Scanner (`username`)
- Checks **25+ platforms**: GitHub, Twitter/X, Instagram, Reddit, TikTok, LinkedIn, YouTube, Pinterest, Twitch, Steam, Keybase, HackerNews, GitLab, Bitbucket, Gravatar, DeviantArt, Medium, Pastebin, SoundCloud, Flickr, Vimeo, Disqus, HackerEarth, DockerHub, NPM, PyPI
- Concurrent requests via thread pool (fast!)
- Reports confirmed profile URLs

### 📧 Email Lookup (`email`)
- Format validation
- Domain resolution check
- Free email provider detection
- MX record enumeration (requires `dnspython`)
- Gravatar avatar/profile check
- Disposable email domain detection
- HaveIBeenPwned breach check (API key required for full data)

### 📞 Phone Lookup (`phone`)
- Parse international phone numbers (E164, national, RFC3966 formats)
- Geographic location identification
- Carrier name detection
- Timezone(s) for the number
- Type classification: mobile, fixed line, VoIP, toll-free, etc.
- Requires: `phonenumbers` library

### 🌐 Domain Lookup (`domain`)
- Full WHOIS data (registrar, dates, nameservers, registrant)
- DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA
- Subdomain enumeration: wordlist + crt.sh certificate transparency
- SSL/TLS certificate details (issuer, SANs, validity dates)
- HTTP response headers analysis
- Technology detection (CDN, web server, framework)

### 🌍 IP Lookup (`ip`)
- Geolocation via ip-api.com (country, city, ISP, lat/lon)
- Reverse DNS PTR record lookup
- ASN / BGP info via bgpview.io
- Hosting/proxy/mobile flag detection
- GreyNoise community threat intelligence
- DNS blacklist (DNSBL) check: Spamhaus ZEN, SORBS, Barracuda, SpamCop

### 🖼️ Image Search (`image`)
- EXIF metadata extraction (Make, Model, Software, timestamps)
- **GPS coordinate extraction and Google Maps link** ⚠️
- File hashes (MD5, SHA1, SHA256)
- Image dimensions and format detection
- Reverse image search links (Google Lens, TinEye, Yandex, Bing, PimEyes)
- Suspicious findings analysis

### 📄 Metadata Scanner (`file`)
- **PDF**: Author, creator, producer, page count, creation/modification dates
- **Office (.docx/.xlsx/.pptx)**: Author, last modified by, company, template path, revision count
- **Legacy Office (.doc/.xls/.ppt)**: Basic metadata via olefile
- **Images**: Full EXIF data
- **Audio**: ID3 tags via mutagen (artist, album, title, etc.)
- File hashes for all types
- Suspicious findings: author names, company, internal paths

---

## 📝 Output Reports

All results are saved to the `output/` directory (or custom path with `--output`) as JSON files:

```
output/
├── username_johndoe_20241215_143022.json
├── email_test_gmail_com_20241215_143150.json
├── ip_8_8_8_8_20241215_143301.json
└── ...
```

Each report includes:
- **Meta**: target, type, timestamp, elapsed time
- **Results**: all module-specific findings

---

## 🔑 Optional API Keys

OrbitTrace works **without any API keys**. However, some features are enhanced with free keys:

| Service | Usage | Get Key |
|---------|-------|---------|
| HaveIBeenPwned | Full email breach data | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| AbuseIPDB | Full IP abuse reports | [abuseipdb.com](https://www.abuseipdb.com) |

To add API keys, open the relevant module file and add your key to the appropriate variable.

---

## 🛠️ Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP requests |
| `beautifulsoup4` | HTML parsing |
| `colorama` | Colored terminal output |
| `dnspython` | DNS record lookups |
| `python-whois` | WHOIS queries |
| `phonenumbers` | Phone number parsing |
| `Pillow` | Image processing & EXIF |
| `exifread` | EXIF fallback reader |
| `pypdf` | PDF metadata |
| `mutagen` | Audio file metadata |
| `olefile` | Legacy Office files |

---

## 🤝 Contributing

Pull requests welcome! To add a new platform to the username scanner, add an entry to the `PLATFORMS` dict in `modules/username_scan.py`.

---

## 📜 License

MIT License — free to use, modify, and distribute.
