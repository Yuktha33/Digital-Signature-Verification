# Digital Signature Verification System (Spring Boot)

Sign any file with an RSA or ECDSA private key and let anyone verify it with the matching public key.
A single changed byte in the document makes verification fail.

## Features
- **Key management**: RSA (2048/3072/4096) or EC (P-256/P-384) key pairs
- **Private keys encrypted at rest**: PBKDF2-HMAC-SHA256 (210k iterations) → AES-256-GCM; wrong password is detected
- **Sign** any file → Base64 signature + SHA-256 document hash (SHA256withRSA / SHA256withECDSA)
- **Verify** by stored alias *or* by pasting a PEM public key (works for signatures made elsewhere)
- **Audit trail**: every signature and every verification attempt is stored
- REST API + built-in web UI (`/`) + H2 console (`/h2-console`)
- JUnit tests: valid, tampered doc, wrong key, wrong password, garbage signature

## Requirements
Java 17+, Maven 3.8+

## Run
```bash
mvn spring-boot:run
# open http://localhost:8080
```
Run tests: `mvn test`   |   Build jar: `mvn clean package && java -jar target/digital-signature-system-1.0.0.jar`

## REST API
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/keys` | Generate key pair `{alias,password,algorithm?,keySize?}` |
| GET | `/api/keys` | List keys (public info only) |
| GET | `/api/keys/{alias}/public` | Download public key `.pem` |
| DELETE | `/api/keys/{alias}` | Delete key |
| POST | `/api/sign` | multipart: `file`, `alias`, `password` |
| POST | `/api/verify` | multipart: `file`, `signature`, and `alias` **or** `publicKeyPem` |
| GET | `/api/signatures` | Signatures issued |
| GET | `/api/verifications` | Verification log |

### Example with curl
```bash
# 1. create key
curl -X POST localhost:8080/api/keys -H "Content-Type: application/json" \
  -d '{"alias":"alice","password":"S3cretPass!","algorithm":"RSA","keySize":2048}'

# 2. sign
curl -F file=@contract.pdf -F alias=alice -F password='S3cretPass!' localhost:8080/api/sign

# 3. verify (paste the signature returned above)
curl -F file=@contract.pdf -F alias=alice -F signature='BASE64_SIGNATURE' localhost:8080/api/verify
```

## How it works
```
SIGN:    document ──SHA-256──► digest ──encrypt with PRIVATE key──► signature
VERIFY:  signature ──decrypt with PUBLIC key──► digest A
         document ──SHA-256──► digest B        valid  ⇔  A == B
```

## Project layout
```
src/main/java/com/example/dsvs
 ├─ DigitalSignatureApplication.java
 ├─ controller/  KeyController, SignatureController
 ├─ service/     KeyService, KeyProtectionService, SignatureService
 ├─ entity/      KeyPairEntity, SignatureRecord, VerificationLog
 ├─ repository/  Spring Data JPA repositories
 ├─ dto/         request/response records
 └─ exception/   ApiException, GlobalExceptionHandler
src/main/resources/static/index.html   (web UI)
src/test/java/.../SignatureServiceTest.java
```

## Production notes
This is a learning/demo project. Before real use add authentication (Spring Security/JWT), HTTPS,
per-user key ownership, a production database (PostgreSQL), and consider an HSM/KMS for private keys.
