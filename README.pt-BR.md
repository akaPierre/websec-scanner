# 🔐 WebSec Scanner

[![CI](https://github.com/akaPierre/websec-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/akaPierre/websec-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)

**[🇺🇸 Read in English](README.md)** | 🇧🇷 Português

Ferramenta educativa de análise de vulnerabilidades para aplicações web.

> ⚠️ **Use apenas em sistemas que você possui autorização explícita para testar.**
> O uso não autorizado é ilegal e antiético.

## 🚀 Funcionalidades

- 🔍 Descoberta de subdomínios via DNS
- 🛡️ Verificação de headers de segurança HTTP
- 🔒 Análise de HTTPS e certificado SSL
- 🚪 Scan de portas sensíveis (TCP)
- 📂 Detecção de endpoints expostos
- 🧬 Fingerprinting de tecnologias
- ☠️ Detecção básica de subdomain takeover
- 📊 Relatório em JSON + terminal colorido

## 🧱 Stack

- Java 21
- Spring Boot 3.5.12
- Maven
- WebFlux (WebClient)
- dnsjava

## ⚙️ Pré-requisitos

```bash
java -version   # Java 21+
mvn -version    # Maven 3.9+
```

## 🏃 Como executar

```bash
# Clone o repositório
git clone https://github.com/akaPierre/websec-scanner.git
cd websec-scanner

# Build
mvn clean package -DskipTests

# Modo interativo
java -jar target/websec-scanner-1.0.0.jar

# Modo direto
java -jar target/websec-scanner-1.0.0.jar scanme.nmap.org

# Ou via script
chmod +x run.sh
./run.sh scanme.nmap.org
```

## 🐳 Executar com Docker

```bash
docker build -t websec-scanner .
docker run --rm -v "$(pwd)/reports:/app/reports" websec-scanner scanme.nmap.org
```

## 🧪 Testes

```bash
./mvnw test
```

## 📊 Estrutura do Relatório

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
      "title": "Header de segurança ausente: Content-Security-Policy",
      "description": "...",
      "evidence": "...",
      "recommendation": "...",
      "target": "https://example.com"
    }
  ]
}
```

## 📁 Estrutura do Projeto

```
websec-scanner/
├── src/main/java/com/websec/scanner/
│   ├── cli/           # Interface CLI
│   ├── engine/        # Orquestrador do scan
│   ├── scanner/       # Módulos de análise
│   ├── model/         # POJOs e enums
│   ├── report/        # Geração de relatório
│   └── config/        # Configurações
└── src/main/resources/
    ├── application.properties
    └── wordlists/     # Subdomínios e endpoints
```

## 📜 Licença

MIT — apenas para fins educacionais. Veja [LICENSE](LICENSE).
