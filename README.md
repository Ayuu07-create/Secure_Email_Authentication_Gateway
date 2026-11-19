# 🔐 Secure Email Authentication Gateway

A web-based gateway for analyzing email authentication using **SPF, DKIM, and DMARC**. It parses raw email headers, checks DNS authentication records, analyzes DKIM signatures, and presents the results through a security dashboard.

## ✨ Features

- 📧 Raw email header analysis
- 🛡️ SPF record detection
- 🔑 DKIM signature parsing
- 🌐 DKIM public-key DNS lookup
- 🔒 DMARC policy analysis
- 📊 Authentication status dashboard
- 🔍 Real email header testing

## 🏗️ Architecture

```text
Raw Email
    ↓
Header Parser
    ↓
┌─────────┬─────────┬─────────┐
│   SPF   │  DKIM   │  DMARC  │
└────┬────┴────┬────┴────┬────┘
     ↓         ↓         ↓
        DNS Analysis
             ↓
     Security Report
```

## ⚙️ Tech Stack

- **Python**
- **Flask**
- **dnspython**
- **dkimpy**
- **cryptography**
- **HTML / CSS**

## 📁 Project Structure

```text
email-auth-gateway/
├── app.py
├── generate_dkim.py
├── requirements.txt
├── .env
├── .gitignore
├── README.md
│
├── auth/
│   ├── parser.py
│   ├── spf.py
│   ├── dkim.py
│   └── dmarc.py
│
├── keys/
│   ├── dkim_private.pem
│   └── dkim_public.pem
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```

## 🚀 Setup

### 1. Create virtual environment

```bash
python -m venv venv
```

### 2. Activate

**Windows:**

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Generate DKIM keys

```bash
python generate_dkim.py
```

### 5. Run the application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## 🧪 Testing

Paste raw email headers into the gateway.

For real-world testing, use **Gmail → Show original** and paste the original email content into the application.

The gateway analyzes:

```text
SPF   → PASS / FAIL / UNKNOWN
DKIM  → PASS / FAIL / UNKNOWN
DMARC → PASS / FAIL / UNKNOWN
```

## 🔐 Security

The DKIM private key must **never** be published or committed to GitHub.

Only the DKIM public key should be published through DNS.

## 🚧 Future Enhancements

- Independent DKIM cryptographic verification
- Complete SPF sender-IP evaluation
- Full DMARC alignment engine
- Security scoring
- DMARC report analysis
- Authentication history

## 📚 Standards

- SPF — RFC 7208
- DKIM — RFC 6376
- DMARC — RFC 7489

## 📄 License

For educational and security research purposes.