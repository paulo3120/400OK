<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0--Ultimate-blue?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go" alt="Go"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-orange?style=for-the-badge" alt="Platform"/>
</p>

```
    ██╗  ██╗ ██████╗  ██████╗  ██████╗ ██╗  ██╗
    ██║  ██║██╔═████╗██╔═████╗██╔═══██╗██║ ██╔╝
    ███████║██║██╔██║██║██╔██║██║   ██║█████╔╝
    ╚════██║████╔╝██║████╔╝██║██║   ██║██╔═██╗
         ██║╚██████╔╝╚██████╔╝╚██████╔╝██║  ██╗
         ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝
                                    ULTIMATE EDITION
```

<p align="center">
  <b>Ultra Comprehensive 403/401 Bypass Tool </b><br>
  <i>22 Techniques | 4,400+ Payloads </i>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> |
  <a href="#-features">Features</a> |
  <a href="#-techniques">Techniques</a> |
  <a href="#-usage">Usage</a> |
  <a href="#-why-400ok">Why 400OK?</a>
</p>

---

## What is 400OK?

Ever hit a **403 Forbidden** and thought "there's gotta be a way around this"? Yeah, we've all been there.

**400OK Ultimate Edition** is your Swiss Army knife for access control bypass testing. Born from the fusion of the best bypass tools (`nomore403` + `byp4xx` + the legendary Monster script), this beast packs **22 unique bypass techniques** and over **4,400 payloads** into a single, lightning-fast Go binary.

Whether you're hunting bugs, doing a pentest, or just curious about that forbidden admin panel - 400OK has your back.

```
One tool to rule them all, one tool to find them,
One tool to bypass all and in the 200 bind them.
```

---

## Quick Start

### Option 1: Download & Run (Recommended)

```bash
# Download the latest release
wget https://github.com/0xbugatti/400OK/releases/latest/download/400OK-linux-amd64.tar.gz

# Extract and run
tar -xzf 400OK-linux-amd64.tar.gz
cd 400OK
./400OK -u https://target.com/admin
```

### Option 2: Build from Source

```bash
# Clone the repo
git clone https://github.com/0xbugatti/400OK.git
cd 400OK

# Build it
go build -o 400OK

# Run it
./400OK -u https://target.com/admin
```

### Option 3: Go Install

```bash
go install github.com/0xbugatti/400OK@latest
```

**That's it.** You're ready to bypass some access controls.

---

## Features

| Feature                        | Description                                                |
| :----------------------------- | :--------------------------------------------------------- |
| **22 Bypass Techniques** | From verb tampering to Unicode encoding - we've got it all |
| **4,400+ Payloads**      | The most comprehensive payload collection assembled        |
| **Auto-Calibration**     | Smart filtering eliminates false positives automatically   |
| **Blazing Fast**         | Native Go HTTP client with 50+ concurrent goroutines       |
| **JSON Export**          | Export findings to JSON for your reports                   |
| **Burp Integration**     | Import requests directly from Burp Suite                   |
| **Graceful Exit**        | Ctrl+C shows summary before exit                           |
| **Proxy Support**        | Route through Burp, ZAP, or any proxy                      |
| **Rate Limit Aware**     | Auto-stops on 429 responses                                |
| **Technique Selection**  | Include or exclude specific techniques                     |

---

## Techniques

400OK comes loaded with **22 bypass techniques** organized into three tiers:

### Core Techniques (Low Noise)

| Technique                 | Flag                | What It Does                                       | Requests |
| :------------------------ | :------------------ | :------------------------------------------------- | :------- |
| **Verb Tampering**  | `verbs`           | Tests 86 HTTP methods (GET, POST, PATCH, POUET...) | 86       |
| **Verb Case**       | `verbs-case`      | Method capitalization tricks (get, GeT, gET)       | ~20      |
| **Headers**         | `headers`         | 53 bypass headers with 24 IP variations            | ~1,200   |
| **End Paths**       | `endpaths`        | Path suffixes (/, /., /?, /..;/)                   | 72       |
| **Mid Paths**       | `midpaths`        | Path traversal patterns inserted mid-URL           | 245      |
| **HTTP Versions**   | `http-versions`   | HTTP/1.0 vs HTTP/1.1 vs HTTP/2                     | 6        |
| **Path Case**       | `path-case`       | Case manipulation (/Admin, /ADMIN, /aDmIn)         | Variable |
| **Double Encoding** | `double-encoding` | %252e instead of %2e                               | Variable |
| **Bug Bounty Tips** | `bugbounty-tips`  | 13 proven techniques from real bounties            | 13       |

### Monster Exclusive Techniques (Medium Noise)

| Technique               | Flag              | What It Does                             | Requests |
| :---------------------- | :---------------- | :--------------------------------------- | :------- |
| **IPv6 Bypass**   | `ipv6`          | IPv6 localhost representations           | 10       |
| **Host Header**   | `host-header`   | Virtual host routing manipulation        | 19       |
| **Unicode/IIS**   | `unicode`       | Overlong UTF-8 encoding for IIS          | 23       |
| **WAF Bypass**    | `waf-bypass`    | WAF rule evasion patterns                | 6        |
| **Via Header**    | `via-header`    | Via header manipulation                  | 5        |
| **Forwarded**     | `forwarded`     | RFC 7239 Forwarded header                | 8        |
| **Cache Control** | `cache-control` | Cache manipulation bypass                | 6        |
| **Accept Header** | `accept-header` | Content negotiation tricks               | 6        |
| **Protocol**      | `protocol`      | HTTP/HTTPS protocol switching            | 2        |
| **Port**          | `port`          | Non-standard port testing                | 8        |
| **Wayback**       | `wayback`       | Check Wayback Machine for archived pages | API      |

### Heavy Hitters (High Noise - Use Selectively)

| Technique               | Flag              | What It Does                               | Requests |
| :---------------------- | :---------------- | :----------------------------------------- | :------- |
| **Extensions**    | `extensions`    | 926 file extensions (.php, .aspx, .bak...) | 926      |
| **Default Creds** | `default-creds` | 1,909 credential pairs via HTTP Basic Auth | 1,909    |

---

## Usage

### Basic Scan (All Techniques)

```bash
./400OK -u https://target.com/admin
```

### Select Specific Techniques

```bash
# Only test bug bounty tips and header manipulation
./400OK -u https://target.com/admin -k bugbounty-tips,headers,verbs
```

### Exclude Noisy Techniques

```bash
# Run everything EXCEPT default credentials and extensions
./400OK -u https://target.com/admin -e default-creds,extensions
```

### With Proxy (Burp Suite)

```bash
./400OK -u https://target.com/admin -x http://127.0.0.1:8080
```

### Custom Headers

```bash
./400OK -u https://target.com/admin -H "Authorization: Bearer eyJ..." -H "X-Custom: value"
```

### Export to JSON

```bash
./400OK -u https://target.com/admin -j results.json
```

### Stealth Mode

```bash
# Slow and quiet - 500ms delay, only 10 concurrent requests, random user-agent
./400OK -u https://target.com/admin -d 500 -m 10 --random-agent -k bugbounty-tips,headers
```

### From Burp Suite Request File

```bash
./400OK --request-file burp_request.txt
```

### Pipe Multiple URLs

```bash
cat urls.txt | ./400OK
```

---

## Scan Profiles

### Quick Scan (Bug Bounty)

*Fast, low noise, high-value techniques*

```bash
./400OK -u https://target.com/admin -k verbs,headers,bugbounty-tips -d 100
```

### Standard Scan (Pentest)

*Balanced - excludes the noisiest techniques*

```bash
./400OK -u https://target.com/admin -e default-creds -x http://127.0.0.1:8080
```

### Full Arsenal (Lab Environment)

*Everything, including the kitchen sink*

```bash
./400OK -u https://target.com/admin -v
```

### Ninja Mode (Stealth)

*Minimal footprint, maximum patience*

```bash
./400OK -u https://target.com/admin -k bugbounty-tips,headers -d 1000 -m 5 --random-agent
```

---

## All Flags

```
REQUIRED:
  -u, --uri              Target URL (e.g., https://target.com/admin)

TECHNIQUE SELECTION:
  -k, --technique        Include only these techniques (comma-separated)
  -e, --exclude          Exclude these techniques (comma-separated)
                         Note: -k and -e are mutually exclusive

REQUEST OPTIONS:
  -H, --header           Custom headers (repeatable)
  -t, --http-method      Force specific HTTP method
  -a, --user-agent       Custom User-Agent string
  --random-agent         Use random User-Agent per request
  -i, --bypass-ip        IP to inject in bypass headers

PERFORMANCE:
  -m, --max-goroutines   Max concurrent requests (default: 50)
  -d, --delay            Delay between requests in ms (default: 0)
  --timeout              Request timeout in ms (default: 6000)
  -l, --rate-limit       Stop on 429 responses

PROXY & NETWORK:
  -x, --proxy            Proxy URL (e.g., http://127.0.0.1:8080)
  -r, --redirect         Follow redirects
  --http                 Use HTTP instead of HTTPS

OUTPUT:
  -v, --verbose          Show all responses (not just bypasses)
  --unique               Show only unique status/length combinations
  -j, --json             Export results to JSON file
  -s, --summary          Show scan summary (default: true)
  --no-banner            Hide the startup banner

INPUT:
  -f, --folder           Custom payloads folder location
  --request-file         Load request from Burp-style file
  --status               Filter by status codes (e.g., 200,301,403)
```

---

## How It Works

### 1. Auto-Calibration

400OK first makes a baseline request to understand the "normal" response. Any bypass attempt that returns the same content length is filtered out - no more wading through thousands of false positives.

### 2. Parallel Execution

Using Go's goroutines, 400OK fires off 50+ requests simultaneously (configurable). This means scanning completes in seconds, not hours.

### 3. Smart Filtering

Results are deduplicated and only genuinely different responses are shown. The tool tracks:

- Status codes
- Content lengths
- Response patterns

### 4. Graceful Handling

Press Ctrl+C at any time - 400OK will show you what it found so far before exiting cleanly.

---

## Why 400OK?

We compared 400OK against every major bypass tool. Here's how it stacks up:

| Feature                    | bypass-403.sh | byp4xx | nomore403 | **400OK Ultimate** |
| :------------------------- | :-----------: | :-----: | :-------: | :----------------------: |
| **Techniques**       |      ~20      |    9    |     8     |       **22**       |
| **Total Payloads**   |      ~20      |  3,480  |   1,420   |     **4,400+**     |
| **HTTP Methods**     |       3       |   84   |    17    |       **86**       |
| **Auto-Calibration** |      No      |   No   |    Yes    |      **Yes**      |
| **IPv6 Bypass**      |      No      |   No   |    No    |      **Yes**      |
| **Unicode/IIS**      |      No      |   No   |    No    |      **Yes**      |
| **Wayback Check**    |      No      |   No   |    No    |      **Yes**      |
| **WAF Bypass**       |      No      |   No   |    No    |      **Yes**      |
| **JSON Export**      |      No      |   No   |    No    |      **Yes**      |
| **Concurrency**      |       1       | Limited |    50    |      **50+**      |
| **Performance**      |     Slow     |  Fast  |   Fast   |    **Fastest**    |

**400OK Ultimate = Best of All Worlds**

---

## Payload Files

400OK ships with a comprehensive payload collection:

| File             |            Count | Purpose                          |
| :--------------- | ---------------: | :------------------------------- |
| `httpmethods`  |               86 | HTTP verb tampering              |
| `headers`      |               53 | Bypass header names              |
| `endpaths`     |               72 | Path suffix patterns             |
| `midpaths`     |              245 | Path traversal patterns          |
| `useragents`   |              999 | User-Agent rotation              |
| `extensions`   |              926 | File extension enumeration       |
| `defaultcreds` |            1,909 | Default username:password pairs  |
| `ipv6`         |               10 | IPv6 localhost representations   |
| `unicode`      |               23 | Overlong UTF-8 encodings         |
| `waf`          |                6 | WAF bypass patterns              |
| `hostvalues`   |               19 | Host header values               |
| `via`          |                5 | Via header values                |
| `forwarded`    |                8 | Forwarded header values          |
| `cache`        |                6 | Cache-Control values             |
| `accept`       |                6 | Accept header values             |
| `ports`        |                8 | Port variations                  |
| **Total**  | **4,400+** | **Comprehensive coverage** |

---

## Bug Bounty Techniques (Built-in)

These 13 battle-tested techniques come hardcoded in 400OK:

| # | Pattern                    | Description               |
| :-: | :------------------------- | :------------------------ |
| 1 | `/%2e/{{path}}`          | URL encoded dot           |
| 2 | `/%ef%bc%8f{{path}}`     | Unicode fullwidth slash   |
| 3 | `{{path}}?`              | Query string terminator   |
| 4 | `{{path}}??`             | Double query string       |
| 5 | `{{path}}//`             | Double trailing slash     |
| 6 | `{{path}}/`              | Trailing slash            |
| 7 | `/./{{path}}/./`         | Dot slash wrappers        |
| 8 | `{{path}}/.randomstring` | Hidden file pattern       |
| 9 | `{{path}}..;/`           | Semicolon path with slash |
| 10 | `{{path}}..;`            | Semicolon path terminator |
| 11 | `/.;/{{path}}`           | Semicolon prefix          |
| 12 | `/.;/{{path}}/.;/`       | Semicolon wrapper         |
| 13 | `/;foo=bar/{{path}}`     | Parameter injection       |

---

## Troubleshooting

### Too many results?

The auto-calibration should filter false positives. If you're still seeing noise:

```bash
# Use unique mode
./400OK -u <target> --unique

# Or increase delay to avoid rate-based inconsistencies
./400OK -u <target> -d 200
```

### Scan too slow?

```bash
# Increase concurrent requests (be careful with this)
./400OK -u <target> -m 100
```

### Getting rate limited?

```bash
# Enable rate limit detection and add delay
./400OK -u <target> -l -d 500
```

### Want to see everything?

```bash
# Verbose mode shows all responses
./400OK -u <target> -v
```

---

## Examples: Real-World Scenarios

### Scenario 1: Quick Bug Bounty Recon

You found `/admin` returning 403. Quick check with low-noise techniques:

```bash
./400OK -u https://target.com/admin -k bugbounty-tips,verbs,headers -d 100
```

### Scenario 2: Comprehensive Pentest

You have authorization and want thorough testing through Burp:

```bash
./400OK -u https://target.com/admin -x http://127.0.0.1:8080 -H "Authorization: Bearer token123" -e default-creds
```

### Scenario 3: Checking for IIS Unicode Bypass

Target is running IIS and you suspect unicode normalization issues:

```bash
./400OK -u https://target.com/admin -k unicode,path-case,extensions
```

### Scenario 4: 401 Unauthorized Testing

Endpoint returns 401 - test for weak/default credentials:

```bash
./400OK -u https://target.com/admin -k default-creds -v
```

### Scenario 5: WAF Bypass Assessment

Testing if WAF can be evaded:

```bash
./400OK -u https://target.com/admin -k waf-bypass,bugbounty-tips,double-encoding,headers
```

---

## Legal Disclaimer

**400OK is designed for authorized security testing only.**

Before using this tool:

1. **Get explicit written permission** from the target system owner
2. **Understand your scope** - know what you're allowed to test
3. **Know your local laws** - unauthorized access is illegal
4. **Use responsibly** - don't cause denial of service
5. **Respect rate limits** - be a good internet citizen

**Unauthorized use may violate:**

- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar legislation in other jurisdictions

The authors are not responsible for misuse of this tool. Use responsibly.

---

## Credits

400OK Ultimate Edition stands on the shoulders of giants:

- **[devploit](https://github.com/devploit)** - Original `nomore403` creator
- **[lobuhi](https://github.com/lobuhi)** - `byp4xx` creator
- **[@me_dheeraj](https://twitter.com/me_dheeraj)** - Monster script techniques
- **The Bug Bounty Community** - For discovering and sharing these techniques
- **You** - For using this tool responsibly

---

## Contributing

Found a new bypass technique? Have an idea for improvement?

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-bypass`)
3. Commit your changes (`git commit -m 'Add amazing bypass technique'`)
4. Push to the branch (`git push origin feature/amazing-bypass`)
5. Open a Pull Request

---

## Contact

- **GitHub**: [@0xbugatti](https://github.com/0xbugatti)
- **Issues**: [Report bugs or request features](https://github.com/0xbugatti/400OK/issues)

---

## License

MIT License - Use it, modify it, share it. Just don't be evil with it.

---

<p align="center">
  <b>Built with determination by 0xBUGATTI</b><br>
  <i>"Because 403 is just a suggestion"</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Go-00ADD8?style=flat-square&logo=go" alt="Made with Go"/>
  <img src="https://img.shields.io/badge/For-Pentesters-black?style=flat-square&logo=hackaday" alt="For Pentesters"/>
</p>
