# Vulnerable Java Application

**⚠️ WARNING: This application is intentionally vulnerable and should NEVER be deployed to production!**

This is an intentionally vulnerable Spring Boot application (Java + Kotlin) designed for testing security remediation tools and learning about common web application vulnerabilities.

## Purpose

This application is designed to:
- Test automated security scanning and remediation tools
- Demonstrate common OWASP Top 10 vulnerabilities in Java/Spring Boot
- Provide a realistic codebase with 200+ dependency vulnerabilities
- Showcase different vulnerability remediation scenarios across the Java ecosystem

## Features

- Spring Boot 2.1.6 (from 2019) with extensive vulnerable dependencies
- Mixed Java and Kotlin codebase
- User authentication (with vulnerabilities)
- File upload/download
- Database operations (simulated)
- External API integration
- Search functionality
- Admin operations
- Multiple data parsers (XML, YAML, JSON)

## Vulnerabilities

### Code Vulnerabilities (SAST)

| Vulnerability | CWE | File | Line | Severity |
|--------------|-----|------|------|----------|
| Hardcoded Secrets | CWE-798 | VulnerableApplication.java | 19-22 | HIGH |
| Insecure CORS | CWE-942 | VulnerableApplication.java | 32-41 | MEDIUM |
| SQL Injection | CWE-89 | VulnerableController.java | 81-96 | CRITICAL |
| Command Injection | CWE-78 | VulnerableController.java | 99-117 | CRITICAL |
| Path Traversal | CWE-22 | VulnerableController.java | 120-132 | HIGH |
| Unrestricted File Upload | CWE-434 | VulnerableController.java | 135-150 | HIGH |
| Cross-Site Scripting (XSS) | CWE-79 | VulnerableController.java | 153-157 | HIGH |
| Server-Side Request Forgery (SSRF) | CWE-918 | VulnerableController.java | 160-181 | HIGH |
| Remote Code Execution | CWE-94 | VulnerableController.java | 184-196 | CRITICAL |
| Insecure Deserialization | CWE-502 | VulnerableController.java | 199-212 | CRITICAL |
| Missing Authentication | CWE-862 | VulnerableController.java | 215-223 | CRITICAL |
| Insecure Direct Object Reference | CWE-639 | VulnerableController.java | 226-238 | MEDIUM |
| XML External Entity (XXE) | CWE-611 | VulnerableController.java | 241-256 | HIGH |
| YAML Deserialization | CWE-502 | VulnerableController.java | 259-271 | HIGH |
| Mass Assignment | CWE-915 | VulnerableController.java | 274-286 | MEDIUM |
| Sensitive Data Exposure | CWE-200 | VulnerableController.java | 289-301 | HIGH |
| Insecure Randomness | CWE-330 | VulnerableController.java | 304-315 | MEDIUM |
| Open Redirect | CWE-601 | VulnerableController.java | 318-322 | MEDIUM |
| Information Disclosure | CWE-209 | VulnerableController.java | 325-335 | MEDIUM |
| Weak Cryptography (MD5) | CWE-327 | VulnerableController.java | 338-355 | HIGH |
| Debug Mode Enabled | CWE-489 | application.properties | 6-8 | MEDIUM |
| Exposed Secrets in Config | CWE-798 | application.properties | 11-62 | CRITICAL |

### Dependency Vulnerabilities (SCA)

This application uses **70+ direct dependencies from 2017-2019**, which pull in **300+ total dependencies** when including transitive dependencies, resulting in **200+ known vulnerabilities**.

**High-CVE Packages:**
- `spring-boot-starter-parent:2.1.6` - Multiple Spring vulnerabilities
- `jackson-databind:2.9.9` - Deserialization RCE (30+ CVEs)
- `log4j:1.2.17` - Multiple critical vulnerabilities
- `commons-collections:3.2.1` - Deserialization RCE (CVE-2015-7501)
- `commons-collections4:4.1` - Various security issues
- `commons-beanutils:1.9.3` - Deserialization vulnerabilities
- `commons-fileupload:1.3.3` - DoS, path traversal (5+ CVEs)
- `commons-compress:1.18` - Zip slip, DoS (10+ CVEs)
- `mysql-connector-java:5.1.46` - JDBC vulnerabilities
- `h2:1.4.197` - RCE vulnerabilities
- `httpclient:4.5.6` - Multiple HTTP issues
- `jjwt:0.9.1` - JWT vulnerabilities
- `xerces:2.11.0` - XXE vulnerabilities
- `dom4j:1.6.1` - XXE injection
- `snakeyaml:1.23` - Deserialization RCE
- `velocity:1.7` - Template injection
- `freemarker:2.3.28` - Template injection
- `kryo:4.0.2` - Deserialization issues
- `guava:25.1-jre` - DoS vulnerabilities
- `poi:3.17` - XXE, zip slip (10+ CVEs)
- `itextpdf:5.5.13` - XSS, XXE issues
- `aws-java-sdk-s3:1.11.327` - AWS SDK vulnerabilities
- `struts2-core:2.5.20` - RCE vulnerabilities
- `hibernate-core:5.3.10` - SQL injection issues
- `netty-all:4.1.36` - HTTP smuggling (10+ CVEs)
- `elasticsearch:6.8.1` - Multiple security issues
- `kafka-clients:2.2.1` - Security vulnerabilities
- `bouncycastle:1.61` - Cryptographic issues
- `jsoup:1.11.3` - XSS vulnerabilities

**Expected Total:** 200-250 vulnerabilities from dependencies (Maven build required to verify exact count)

## Remediation Scenarios

This application includes various remediation scenarios:

### 1. Simple Direct Version Bumps (~30-40 packages)
- `jackson-databind 2.9.9 → 2.15.x`
- `commons-fileupload 1.3.3 → 1.5`
- `guava 25.1-jre → 32.x`

### 2. Transitive Dependency Upgrades (~40-50 packages)
- Spring Boot 2.1.6 pulls in hundreds of vulnerable transitive dependencies
- Upgrading Spring Boot to 3.x fixes many transitive issues

### 3. Diamond Dependencies (~30-40 packages)
- Multiple packages depend on same vulnerable Jackson, Commons, or Netty versions
- Require coordinated upgrades or dependency management

### 4. Ecosystem-Specific Maneuvers (~40-50 packages)
- Use Maven `<dependencyManagement>` to override transitive versions
- Maven exclusions for problematic dependencies
- May require `mvn dependency:tree` analysis

### 5. Breaking Changes (~40-50 packages)
- Spring Boot 2.x → 3.x (major API changes, Java 17+ required)
- Jackson 2.9 → 2.15 (API changes)
- Hibernate 5.x → 6.x (JPA changes)
- Log4j 1.x → Log4j2 (complete rewrite)

### 6. Unhealthy/Unsupported Packages (~20-30 packages)
- `log4j:1.2.17` - EOL, migrate to Log4j2
- `velocity:1.7` - Deprecated, migrate to alternatives
- Older Apache Commons libraries with no maintainers

### 7. Unfixable Issues (~15-20 packages)
- Deep transitive chains requiring upstream fixes
- Vulnerabilities in archived/unmaintained packages
- Legacy Spring Boot 2.x specific dependencies

## Setup

### Prerequisites

- **Java 11 or higher**
- **Maven 3.6+** (required for building and dependency resolution)

### Build and Run

```bash
# Install dependencies and build
mvn clean install

# Run the application
mvn spring-boot:run

# Application will run on http://localhost:8080
```

## Security Testing

```bash
# Run Snyk test (Maven required)
snyk test --file=pom.xml

# Expected output: 200+ vulnerabilities

# View dependency tree
mvn dependency:tree

# Generate dependency report
mvn dependency:analyze

# Build and run tests
mvn clean test
```

## Java Version Note

This project targets Java 11 for maximum compatibility with the old Spring Boot 2.1.6 version. The vulnerable dependencies from 2019 were built for Java 8-11.

## API Endpoints

All endpoints are intentionally vulnerable:

- `POST /api/login` - SQL Injection
- `GET /api/exec?cmd=ls` - Command Injection
- `GET /api/files?filename=test.txt` - Path Traversal
- `POST /api/upload` - Unrestricted File Upload
- `GET /api/search?query=<script>` - XSS
- `GET /api/proxy?url=http://internal` - SSRF
- `POST /api/evaluate` - RCE
- `POST /api/deserialize` - Insecure Deserialization
- `DELETE /api/admin/users/1` - Missing Auth
- `GET /api/users/1` - IDOR
- `POST /api/parse-xml` - XXE
- `POST /api/parse-yaml` - YAML Deserialization
- `POST /api/register` - Mass Assignment
- `GET /api/debug` - Data Exposure
- `GET /redirect?url=` - Open Redirect
- `POST /api/hash` - Weak Cryptography

## OWASP Top 10 Coverage

- ✅ A01:2021 - Broken Access Control
- ✅ A02:2021 - Cryptographic Failures
- ✅ A03:2021 - Injection
- ✅ A04:2021 - Insecure Design
- ✅ A05:2021 - Security Misconfiguration
- ✅ A06:2021 - Vulnerable and Outdated Components
- ✅ A07:2021 - Identification and Authentication Failures
- ✅ A08:2021 - Software and Data Integrity Failures
- ✅ A09:2021 - Security Logging and Monitoring Failures
- ✅ A10:2021 - Server-Side Request Forgery

## Java/Spring Boot Specific Vulnerabilities

### Spring Security Misconfigurations
- CORS enabled for all origins
- Actuator endpoints exposed without authentication
- Debug mode enabled

### Dependency Injection Issues
- Beans with insecure default configurations
- Auto-configuration vulnerabilities

### JVM-Specific Issues
- Insecure deserialization via ObjectInputStream
- Classpath manipulation possibilities
- Reflection-based vulnerabilities

## Maven Dependency Tree Structure

The pom.xml includes:
- **70+ direct dependencies** with known vulnerabilities
- Expected **300+ transitive dependencies**
- Multiple vulnerable versions of commonly-used libraries
- Old framework versions that pull in vulnerable dependency chains

## Kotlin Integration

The project includes Kotlin support demonstrating:
- Mixed Java/Kotlin codebases (common in modern Spring Boot apps)
- Kotlin-specific dependency vulnerabilities
- Jackson Kotlin module with deserialization issues

## License

MIT License - Use for educational and testing purposes only.

## Disclaimer

**DO NOT use this application in production environments. It contains intentional security vulnerabilities and should only be used in isolated, controlled environments for security testing and education.**

## Maven Build Notes

This project requires Maven to:
1. Resolve all 300+ dependencies (direct and transitive)
2. Download vulnerable dependency versions from Maven Central
3. Generate the dependency tree for Snyk scanning
4. Compile Java and Kotlin source files
5. Package the application as an executable JAR

Without Maven installed, the project structure and code are complete but cannot be built or scanned.
