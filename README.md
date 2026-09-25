# 🔐 WebSec Scanner

[![CI](https://github.com/akaPierre/websec-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/akaPierre/websec-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)

🇺🇸 English | **[🇧🇷 Ler em Português](README.pt-BR.md)**

An educational web application vulnerability scanner.

> ⚠️ **Use only against systems you have explicit authorization to test.**
> Unauthorized use is illegal and unethical.

## 🚀 Features

- 🔍 Subdomain discovery via DNS
- 🛡️ HTTP security header checks
- 🍪 Cookie security flags (Secure, HttpOnly, SameSite)
- 🌐 CORS misconfiguration detection (reflected origin, credentials)
- 🔑 JWT weak-algorithm detection (`alg: none`)
- ↪️ Open redirect probing
- 🔒 HTTPS and SSL certificate analysis
- 🚪 Sensitive port scanning (TCP)
- 📂 Exposed endpoint detection
- 🧬 Technology fingerprinting
- ☠️ Basic subdomain takeover detection
- 📊 JSON report + colorized terminal output

## 🧱 Stack

- Java 21
- Spring Boot 3.5.12
- Maven
- WebFlux (WebClient) — fully non-blocking scanner pipelines built on Project Reactor: per-host scanners run concurrently via `Mono.zip`, multiple hosts run concurrently via `flatMap`, and blocking work (DNS resolution, raw TCP sockets) is bridged in through `Schedulers.boundedElastic()`
- dnsjava

## ⚙️ Prerequisites

```bash
java -version   # Java 21+
mvn -version    # Maven 3.9+
```

## 🏃 Running it

```bash
# Clone the repository
git clone https://github.com/akaPierre/websec-scanner.git
cd websec-scanner

# Build
mvn clean package -DskipTests

# Interactive mode
java -jar target/websec-scanner-1.0.0.jar

# Direct mode
java -jar target/websec-scanner-1.0.0.jar scanme.nmap.org

# Or via script
chmod +x run.sh
./run.sh scanme.nmap.org
```

## 🐳 Running with Docker

```bash
docker build -t websec-scanner .
docker run --rm -v "$(pwd)/reports:/app/reports" websec-scanner scanme.nmap.org
```

## 🧪 Tests

```bash
./mvnw test
```

Scanner modules are covered with [MockWebServer](https://github.com/square/okhttp/tree/master/mockwebserver)-backed unit tests (`src/test/java/com/websec/scanner/scanner`).

## 📊 Report structure

```json
{
  "domain": "example.com",
  "scannedAt": "2026-03-23 21:00:00",
  "scanDuration": "12.4s",
  "totalFindings": 7,
  "summary": {
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 1
  },
  "findings": [
    {
      "type": "HEADER",
      "severity": "HIGH",
      "title": "Missing security header: Content-Security-Policy",
      "description": "...",
      "evidence": "...",
      "recommendation": "...",
      "target": "https://example.com"
    }
  ]
}
```

## 📁 Project structure

```
websec-scanner/
├── src/main/java/com/websec/scanner/
│   ├── cli/           # CLI interface
│   ├── engine/        # Scan orchestrator
│   ├── scanner/       # Analysis modules
│   ├── model/         # POJOs and enums
│   ├── report/        # Report generation
│   └── config/        # Configuration
└── src/main/resources/
    ├── application.properties
    └── wordlists/     # Subdomains and endpoints
```

## 📜 License

MIT — for educational purposes only. See [LICENSE](LICENSE).
