<h1 align="center">JWTelescope</h1>
<p align="center">
  <img width="1045" height="474" alt="jwtelescope" src="https://github.com/user-attachments/assets/4a0a435a-592e-4231-87f6-c49f5e3231a3" />
</p>

🔭 **JWTelescope** is an advanced CLI tool for decoding, inspecting, and performing security analysis on JSON Web Tokens (JWTs). It is designed for **bug bounty hunters, pentesters, and developers** who want fast insight into JWT structure, claims, and common misconfigurations.

The tool focuses on **read-only analysis** and **risk assessment**, making it safe to use during reconnaissance and triage phases.

---

## ✨ Features

* Decode JWT **header** and **payload** (Base64URL)
* Pretty, colorized terminal output
* Automatic detection of **common JWT security issues**
* Risk scoring system: **Low / Medium / High**
* Human-readable timestamp conversion (`exp`, `iat`, `nbf`)
* Detection of dangerous patterns:

  * `alg: none`
  * Missing or expired `exp`
  * Very long-lived tokens
  * Weak or generic `aud`
  * Suspicious `kid` values (path traversal, predictability)
  * Symmetric algorithm confusion risk (HS256)
  * Dangerous custom claims (`admin`, `role`, `scope`, etc.)
  * External `jku` / `x5u` URLs
* Structured **JSON output** for reports and automation
* Pipe-friendly modes (`--raw`, `--stdin`)
* Minimal dependencies (Python standard library only)

---

## 🧠 Use Cases

* Bug bounty reconnaissance
* JWT misconfiguration detection
* Token triage during API testing
* Security reporting (HackerOne / Bugcrowd)
* Learning and understanding JWT internals

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/urdev4ever/jwtelescope.git
cd jwtelescope
```

Make the script executable (optional):

```bash
chmod +x jwtelescope.py
```

Requirements:

* Python **3.8+**
* No external libraries required

---

## 🚀 Usage
<img width="898" height="427" alt="jwtelescopehelp" src="https://github.com/user-attachments/assets/15dc281e-86b6-44cc-a344-a795241f6183" />

### Read a JWT directly

```bash
./jwtelescope.py -r "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Read from a file

```bash
./jwtelescope.py -f token.jwt
```

### Read from stdin (piping)

```bash
echo "JWT_TOKEN" | ./jwtelescope.py --stdin
```

### Raw JSON output (no colors, no analysis)

```bash
./jwtelescope.py -r "JWT_TOKEN" --raw
```

### Show only security warnings

```bash
./jwtelescope.py -r "JWT_TOKEN" --only-warnings
```

### Show risk score

```bash
./jwtelescope.py -r "JWT_TOKEN" --score
```

### Generate structured JSON report

```bash
./jwtelescope.py -r "JWT_TOKEN" --json > report.json
```

<h5>[ ! ] Note: You can only use ./jwtelescope.py if you made it executable, otherwise you will need to use:</h5>

```bash
python jwtelescope.py 
```

---

## 🧪 Example Output (using authorized JWT from anytask.com)

* Decoded header
  
  <img width="431" height="177" alt="image (31)" src="https://github.com/user-attachments/assets/edca3371-2a6c-46ba-8c3f-3be0e987d4f5" />

* Decoded payload
  
  <img width="355" height="502" alt="image (32)" src="https://github.com/user-attachments/assets/1851b20b-9cf1-493e-8d67-ba9b4985dbe1" />

* Signature Details
  
  <img width="388" height="74" alt="image" src="https://github.com/user-attachments/assets/b4269c8c-bef3-48a3-9800-d477fc7aca9b" />

* Token metadata (length, algorithm, key ID)
  
  <img width="202" height="92" alt="image" src="https://github.com/user-attachments/assets/ce5a1795-c0d8-4406-9d23-8691dba61733" />

* Common claims overview

  <img width="510" height="119" alt="image" src="https://github.com/user-attachments/assets/b76c421c-1d06-4ff7-89d4-c184ea2281f9" />

* Security findings with severity

  <img width="831" height="79" alt="image" src="https://github.com/user-attachments/assets/e5ee6788-0ad2-4a29-b7ed-adb6c8456d15" />

* Overall risk score

  <img width="159" height="41" alt="image" src="https://github.com/user-attachments/assets/23651d36-dded-426e-bca8-fd3bd71d0879" />


---

## ⚠️ Risk Scoring Logic (Simplified)

| Issue                   | Severity |
| ----------------------- | -------- |
| `alg: none`             | Critical |
| Missing `exp`           | High     |
| Expired token           | High     |
| Expiration > 10 years   | High     |
| Weak `aud`              | Medium   |
| HS256 confusion risk    | Medium   |
| Dangerous custom claims | Medium   |
| Missing `nbf`           | Low      |

Final risk levels:

* **Low**: Mostly informational issues
* **Medium**: Potential security weakness
* **High**: Likely exploitable misconfiguration

---

## 📄 JSON Output Structure

```json
{
  "metadata": {},
  "token_info": {},
  "header": {},
  "payload": {},
  "security_analysis": {},
  "common_claims": {}
}
```

Designed for easy ingestion into scripts, CI pipelines, or reports.

---

## 🔒 Security Philosophy

JWTelescope:

* **Does NOT modify tokens**
* **Does NOT brute-force secrets**
* **Does NOT bypass authentication**

It is a **passive analysis tool** intended for legitimate security testing.

---

## ⭐ Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.
Always test against systems you own or have explicit permission to test.

---
made with <3 by URDev
