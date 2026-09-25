# 🛡️ Cybersecurity Quiz-Generator-BedROCK Agent

> **Moved.** This project now lives in [ai-agents-lab/bedrock-quiz-agent](https://github.com/yashbhosale2403/ai-agents-lab/tree/main/bedrock-quiz-agent). This repository is archived.

> An intelligent AI-powered cybersecurity quiz generation system built with AWS Bedrock, Lambda, and AstraDB

[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock-FF9900?logo=amazon-aws)](https://aws.amazon.com/bedrock/)
[![AstraDB](https://img.shields.io/badge/Database-AstraDB-00C4CC)](https://www.datastax.com/products/datastax-astra)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)](https://github.com)

---

---

## 🎯 Overview

The **Cybersecurity Quiz-Generator-BedROCK Agent** is an intelligent workflow designed specifically for cybersecurity education and training. It combines:
- **Security Document Ingestion** into vector databases
- **Contextual Retrieval** using semantic search on cybersecurity content
- **LLM-powered Generation** with AWS Bedrock
- **Structured Quiz Output** for security assessments

This system automatically generates domain-specific multiple-choice questions on cybersecurity topics by leveraging contextual knowledge from security documentation, threat intelligence, compliance guides, and best practices.

### Use Cases
- 🎓 **Security Awareness Training**: Generate quizzes for employee security training programs
- 🔐 **Certification Prep**: Create practice questions for CISSP, CEH, CompTIA Security+, etc.
- 🏢 **Compliance Testing**: Assess knowledge on GDPR, HIPAA, PCI-DSS, SOC 2
- 🚨 **Incident Response Training**: Test IR procedures and protocols
- 🌐 **Security Operations**: Validate SOC analyst knowledge
- 📱 **Application Security**: Generate questions on secure coding practices

---

## ✨ Features

- **🔍 Intelligent Context Retrieval**: Fetches relevant cybersecurity content from AstraDB vector store
- **🤖 Multi-Model Support**: Compatible with Claude, Titan, and NOVA models
- **⚙️ Configurable Difficulty**: Generate quizzes from beginner to advanced levels
- **📊 Structured Output**: Returns well-formatted JSON quiz data
- **🔄 Scalable Architecture**: Serverless design with AWS Lambda
- **🎨 Customizable Topics**: Cover various security domains (Network, Cloud, AppSec, etc.)
- **🛡️ Industry-Aligned**: Questions based on real-world security scenarios
- **📚 Knowledge Base Support**: Integrates with your custom security documentation

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────────┐
│   Security  │─────▶│ Bedrock Flow │─────▶│   Lambda    │─────▶│   AstraDB    │
│  Trainer    │      │              │      │  Function   │      │  (Security   │
└─────────────┘      └──────────────┘      └─────────────┘      │   Content)   │
                            │                      │             └──────────────┘
                            │                      │                     │
                            ▼                      ▼                     ▼
                     ┌──────────────┐      ┌─────────────┐      ┌──────────────┐
                     │ Bedrock Agent│◀─────│   Context   │◀─────│  Retrieved   │
                     │  (Security   │      │  Retrieval  │      │   Security   │
                     │   Expert)    │      └─────────────┘      │    Docs      │
                     └──────────────┘                            └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Foundation   │
                     │ Model (LLM)  │
                     │  NOVA/Claude │
                     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Cybersecurity│
                     │ Quiz Output  │
                     │    (JSON)    │
                     └──────────────┘
```

### Workflow Steps

1. **Security Trainer Input**: Cybersecurity topic, difficulty level, and question count
2. **Flow Trigger**: Bedrock Flow initiates the security quiz workflow
3. **Lambda Execution**: Queries AstraDB for relevant cybersecurity context
4. **Context Retrieval**: Fetches domain-specific security knowledge
5. **Agent Processing**: Bedrock Agent formats the security-focused prompt
6. **LLM Generation**: Foundation model creates cybersecurity quiz questions
7. **Output Delivery**: Returns structured JSON quiz with security scenarios

---

## 📦 Prerequisites

### Required Services
- ✅ **AWS Account** with Bedrock enabled
- ✅ **AstraDB Account** (DataStax)
- ✅ **AWS CLI** or CloudShell
- ✅ **Python 3.9+**
- ✅ **Cybersecurity Documentation** (PDFs, markdown, text files)

### IAM Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:*",
        "lambda:*",
        "iam:PassRole"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 🚀 Setup Guide

### Step 1: Configure AstraDB for Cybersecurity Content

1. **Create Database**
   - Navigate to [AstraDB Console](https://astra.datastax.com/)
   - Create a new database: `cybersecurity-quiz-db`
   - Note down:
     - Database ID
     - Keyspace name: `security_keyspace`
     - Application Token

2. **Create Collection**
   ```sql
   CREATE TABLE cybersecurity_knowledge (
     id UUID PRIMARY KEY,
     topic TEXT,
     category TEXT,
     difficulty TEXT,
     content TEXT,
     tags SET<TEXT>,
     created_at TIMESTAMP
   );
   ```

3. **Insert Sample Cybersecurity Data**
   ```json
   [
     {
       "topic": "Network Security",
       "category": "Firewall",
       "difficulty": "medium",
       "content": "A firewall is a network security device that monitors incoming and outgoing network traffic and decides whether to allow or block specific traffic based on defined security rules. Firewalls can be hardware-based, software-based, or a combination of both...",
       "tags": ["firewall", "network", "perimeter-security"]
     },
     {
       "topic": "Web Application Security",
       "category": "OWASP",
       "difficulty": "hard",
       "content": "SQL Injection is a code injection technique that exploits vulnerabilities in an application's database layer. Attackers can insert malicious SQL statements into entry fields for execution. Prevention includes using parameterized queries, input validation, and least privilege principles...",
       "tags": ["sql-injection", "owasp-top-10", "web-security"]
     },
     {
       "topic": "Cryptography",
       "category": "Encryption",
       "difficulty": "medium",
       "content": "AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used for securing sensitive data. It uses block cipher with key sizes of 128, 192, or 256 bits. AES is approved by the U.S. government for protecting classified information...",
       "tags": ["encryption", "aes", "cryptography"]
     },
     {
       "topic": "Cloud Security",
       "category": "AWS",
       "difficulty": "medium",
       "content": "AWS IAM (Identity and Access Management) enables secure access control to AWS resources. Best practices include: using MFA, following least privilege principle, rotating credentials regularly, and using IAM roles instead of access keys...",
       "tags": ["iam", "aws", "cloud-security", "access-control"]
     },
     {
       "topic": "Incident Response",
       "category": "IR Process",
       "difficulty": "easy",
       "content": "The incident response lifecycle consists of six phases: Preparation, Identification, Containment, Eradication, Recovery, and Lessons Learned. Each phase is critical for effective security incident management...",
       "tags": ["incident-response", "nist", "security-operations"]
     }
   ]
   ```

---

### Step 2: Deploy Lambda Function

**Create `lambda/handler.py`:**

```python
import json
import requests
import os

ASTRA_DB_URL = os.environ["ASTRA_DB_URL"]
ASTRA_DB_TOKEN = os.environ["ASTRA_DB_TOKEN"]

def lambda_handler(event, context):
    """
    Query AstraDB for cybersecurity quiz context based on topic and difficulty
    """
    topic = event.get("topic", "Network Security")
    difficulty = event.get("difficulty", "medium")
    category = event.get("category", "")
    
    headers = {
        "x-cassandra-token": ASTRA_DB_TOKEN,
        "Content-Type": "application/json"
    }
    
    # Build query based on parameters
    query_filter = {"topic": topic}
    if difficulty:
        query_filter["difficulty"] = difficulty
    if category:
        query_filter["category"] = category
    
    query = {"find": query_filter}
    
    try:
        response = requests.post(
            f"{ASTRA_DB_URL}/api/rest/v2/keyspaces/security_keyspace/cybersecurity_knowledge/find",
            headers=headers,
            json=query,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get("data"):
            content = data["data"][0]["content"]
            tags = data["data"][0].get("tags", [])
        else:
            content = "No cybersecurity content found for the specified topic."
            tags = []
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "topic": topic,
                "category": category,
                "difficulty": difficulty,
                "context": content,
                "tags": tags
            })
        }
    except requests.exceptions.RequestException as e:
        print(f"Error querying AstraDB: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Failed to retrieve cybersecurity content",
                "details": str(e)
            })
        }
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Internal server error",
                "details": str(e)
            })
        }
```

**Create `lambda/requirements.txt`:**
```
requests==2.31.0
```

**Environment Variables:**
```bash
ASTRA_DB_URL=https://your-database-id-region.apps.astra.datastax.com
ASTRA_DB_TOKEN=AstraCS:xxxxx
```

**Deploy with SAM:**
```bash
cd lambda
sam build
sam deploy --guided
```

---

### Step 3: Create Bedrock Agent

1. **Navigate to Bedrock Console**
   - Go to **Amazon Bedrock** → **Agents** → **Create Agent**

2. **Configure Agent**
   - **Name**: `Cybersecurity-Quiz-Generator-Agent`
   - **Description**: "Generates cybersecurity assessment quizzes"
   - **Foundation Model**: Claude 3 Sonnet / NOVA / Titan
   
3. **Define Prompt Template**
   ```
   You are an expert Cybersecurity Quiz Generator Agent with deep knowledge in:
   - Network Security & Firewalls
   - Web Application Security (OWASP Top 10)
   - Cryptography & Encryption
   - Cloud Security (AWS, Azure, GCP)
   - Incident Response & Forensics
   - Compliance (GDPR, HIPAA, PCI-DSS, SOC 2)
   - Threat Intelligence & Malware Analysis
   - Identity & Access Management
   - Security Operations (SOC)
   - Penetration Testing & Ethical Hacking
   
   Task: Generate {question_count} multiple-choice cybersecurity questions based on the provided context.
   
   Parameters:
   - Topic: {topic}
   - Category: {category}
   - Difficulty: {difficulty}
   - Context: {context}
   - Tags: {tags}
   
   Requirements:
   - Each question must have 4 realistic options (A, B, C, D)
   - Clearly indicate the correct answer
   - Include brief explanations for correct answers
   - Use real-world security scenarios and examples
   - Ensure questions test practical knowledge, not just theory
   - Vary question types: definition, scenario-based, best practice, troubleshooting
   - Use industry-standard terminology
   - Reference relevant frameworks (NIST, CIS, MITRE ATT&CK) when appropriate
   
   Output Format: JSON array with question objects
   ```

4. **Add Action Group**
   - **Name**: `AstraDBSecurityQueryAction`
   - **Description**: "Retrieves cybersecurity knowledge from AstraDB"
   - **Lambda Function**: Select deployed function
   - **Input Schema**:
   ```json
   {
     "topic": {
       "type": "string",
       "description": "Cybersecurity topic (e.g., Network Security, Web Security, Cryptography)",
       "examples": ["Network Security", "Cloud Security", "Incident Response"]
     },
     "category": {
       "type": "string",
       "description": "Specific category within the topic",
       "examples": ["Firewall", "OWASP", "Encryption", "IAM"]
     },
     "difficulty": {
       "type": "string",
       "enum": ["easy", "medium", "hard", "expert"],
       "description": "Quiz difficulty level"
     },
     "question_count": {
       "type": "integer",
       "minimum": 1,
       "maximum": 50,
       "default": 10,
       "description": "Number of questions to generate"
     }
   }
   ```

5. **Publish & Create Alias**
   - Version: `v1`
   - Alias: `cybersecurity-quiz-prod`

---

### Step 4: Import Bedrock Flow

1. **Create Flow**
   - Go to **Bedrock** → **Flows** → **Create Flow**
   - Name: `Cybersecurity-Quiz-Flow`
   - Select **Import from file** (if you have existing flow)

2. **Configure Flow Nodes**
   - **Input Node**: User parameters (topic, category, difficulty, question_count)
   - **Validation Node**: Validate security topic selection
   - **Agent Node**: Link to `Cybersecurity-Quiz-Generator-Agent`
   - **Output Node**: Return formatted security quiz
   - **Error Handling Node**: Handle failures gracefully

3. **Test Flow**
   - Use the built-in test console
   - Test with different security topics
   - Verify output format and question quality

---

## 📂 Project Structure

```
cybersecurity-quiz-generator/
│
├── flows/
│   └── cybersecurity-quiz-flow.json    # Exported Bedrock Flow definition
│
├── lambda/
│   ├── handler.py                       # Lambda function code
│   ├── requirements.txt                 # Python dependencies
│   └── template.yaml                    # SAM deployment template
│
├── data/
│   ├── cybersecurity-content/
│   │   ├── network-security.json        # Network security content
│   │   ├── web-security.json            # Web application security content
│   │   ├── cloud-security.json          # Cloud security content
│   │   ├── cryptography.json            # Cryptography content
│   │   └── incident-response.json       # IR procedures
│   └── import-scripts/
│       └── load_security_data.py        # Script to import data to AstraDB
│
├── docs/
│   ├── architecture.md                  # Detailed architecture docs
│   ├── api-reference.md                 # API documentation
│   └── security-topics.md               # Available security topics
│
├── examples/
│   ├── sample-network-quiz.json         # Example network security quiz
│   ├── sample-web-quiz.json             # Example web security quiz
│   └── sample-cloud-quiz.json           # Example cloud security quiz
│
├── tests/
│   ├── test_lambda.py                   # Lambda function tests
│   └── test_integration.py              # Integration tests
│
├── .gitignore
├── README.md
└── LICENSE
```

---

## 💡 Usage Examples

### Example 1: Network Security Quiz

**Input:**
```json
{
  "topic": "Network Security",
  "category": "Firewall",
  "difficulty": "medium",
  "question_count": 5
}
```

**Lambda Context Response:**
```json
{
  "topic": "Network Security",
  "category": "Firewall",
  "difficulty": "medium",
  "context": "A firewall is a network security device that monitors incoming and outgoing network traffic...",
  "tags": ["firewall", "network", "perimeter-security"]
}
```

**Final Quiz Output:**
```json
{
  "quiz": [
    {
      "question": "What is the primary function of a stateful firewall?",
      "options": [
        "Only filter packets based on source and destination IP addresses",
        "Track the state of network connections and make decisions based on context",
        "Block all incoming traffic by default",
        "Only inspect application layer protocols"
      ],
      "correct_answer": "B",
      "explanation": "Stateful firewalls maintain a state table to track active connections and make filtering decisions based on the context of the traffic, not just individual packets."
    },
    {
      "question": "In a DMZ architecture, where should a web server be placed?",
      "options": [
        "Inside the internal network",
        "Between two firewalls in the DMZ",
        "Outside the firewall on the internet",
        "On the same network as database servers"
      ],
      "correct_answer": "B",
      "explanation": "A DMZ (Demilitarized Zone) sits between two firewalls - one facing the internet and one protecting the internal network. Web servers should be placed here to provide controlled public access while protecting internal resources."
    },
    {
      "question": "Which firewall rule practice enhances security the most?",
      "options": [
        "Allow all traffic and block specific threats",
        "Deny all traffic by default and allow only necessary services",
        "Allow all internal traffic without restrictions",
        "Use the same rules for all network segments"
      ],
      "correct_answer": "B",
      "explanation": "The principle of 'default deny' (implicit deny) is a security best practice where all traffic is blocked by default, and only explicitly allowed traffic is permitted. This minimizes attack surface."
    },
    {
      "question": "What is egress filtering on a firewall?",
      "options": [
        "Filtering incoming traffic from the internet",
        "Filtering traffic between internal network segments",
        "Filtering outbound traffic leaving the network",
        "Filtering traffic at the application layer only"
      ],
      "correct_answer": "C",
      "explanation": "Egress filtering controls outbound traffic leaving your network. It helps prevent data exfiltration, command-and-control communications from malware, and unauthorized connections."
    },
    {
      "question": "Which port should typically be blocked at the perimeter firewall for security?",
      "options": [
        "Port 443 (HTTPS)",
        "Port 80 (HTTP)",
        "Port 445 (SMB)",
        "Port 53 (DNS)"
      ],
      "correct_answer": "C",
      "explanation": "Port 445 (SMB - Server Message Block) should be blocked at perimeter firewalls as it's commonly exploited by worms and ransomware (e.g., WannaCry). SMB should only be used internally."
    }
  ],
  "metadata": {
    "topic": "Network Security",
    "category": "Firewall",
    "difficulty": "medium",
    "total_questions": 5,
    "generated_at": "2025-10-28T10:30:00Z"
  }
}
```

---

### Example 2: Web Application Security (OWASP) Quiz

**Input:**
```json
{
  "topic": "Web Application Security",
  "category": "OWASP",
  "difficulty": "hard",
  "question_count": 3
}
```

**Sample Questions:**

1. **A web application is vulnerable to SQL Injection. Which mitigation is MOST effective?**
   - A) Input validation using blacklists
   - B) Using parameterized queries/prepared statements ✓
   - C) Hiding error messages from users
   - D) Using SSL/TLS encryption
   
   **Explanation**: Parameterized queries ensure SQL code and data are separated, preventing injection attacks. Input validation alone is insufficient as attackers can bypass blacklists.

2. **What is the primary risk of Cross-Site Scripting (XSS)?**
   - A) Server resources exhaustion
   - B) Database corruption
   - C) Executing malicious scripts in victim's browser ✓
   - D) Network bandwidth saturation
   
   **Explanation**: XSS allows attackers to inject malicious scripts that execute in the context of a victim's browser, potentially stealing session cookies, credentials, or performing actions on behalf of the user.

3. **Which HTTP header helps prevent clickjacking attacks?**
   - A) Content-Security-Policy
   - B) X-Frame-Options ✓
   - C) Strict-Transport-Security
   - D) X-XSS-Protection
   
   **Explanation**: X-Frame-Options header prevents your site from being embedded in iframes, mitigating clickjacking attacks where attackers overlay transparent frames to trick users into clicking malicious elements.

---

### Example 3: Cloud Security (AWS IAM) Quiz

**Input:**
```json
{
  "topic": "Cloud Security",
  "category": "AWS",
  "difficulty": "medium",
  "question_count": 5
}
```

**Sample Questions:**

1. **What is the AWS security best practice for root account?**
   - A) Use it for daily administrative tasks
   - B) Enable MFA and use it only for initial setup ✓
   - C) Share credentials with the security team
   - D) Disable it completely after account creation
   
   **Explanation**: The root account has unrestricted access. Best practice is to enable MFA, use it only for tasks requiring root access, and use IAM users/roles for daily operations.

2. **Which IAM feature allows temporary security credentials?**
   - A) IAM Users
   - B) IAM Groups
   - C) IAM Roles ✓
   - D) IAM Policies
   
   **Explanation**: IAM Roles provide temporary security credentials via AWS STS (Security Token Service), ideal for applications, services, and cross-account access without long-term credentials.

---

### Example 4: Incident Response Quiz

**Input:**
```json
{
  "topic": "Incident Response",
  "category": "IR Process",
  "difficulty": "easy",
  "question_count": 5
}
```

**Sample Questions:**

1. **What is the FIRST phase of the incident response lifecycle?**
   - A) Identification
   - B) Preparation ✓
   - C) Containment
   - D) Recovery
   
   **Explanation**: Preparation is the first phase where organizations develop IR plans, train teams, and establish tools and processes before incidents occur.

2. **During which phase should you document lessons learned?**
   - A) Identification
   - B) Eradication
   - C) Recovery
   - D) Post-Incident Activity ✓
   
   **Explanation**: The final phase involves reviewing the incident, documenting lessons learned, and improving processes to prevent future incidents.



## 🔧 Deployment

### Export Flow for Version Control

```bash
# Export cybersecurity flow definition
aws bedrock-agent get-flow \
  --flow-identifier <FLOW_ID> \
  --region us-east-1 \
  > flows/cybersecurity-quiz-flow.json

# Commit to repository
git add flows/cybersecurity-quiz-flow.json
git commit -m "Export Cybersecurity Quiz Flow v1.0"
git push origin main
```

### Automated Deployment

Create a GitHub Actions workflow (`.github/workflows/deploy.yml`):

```yaml
name: Deploy Cybersecurity Quiz Generator

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Deploy Lambda Function
        run: |
          cd lambda
          sam build
          sam deploy --no-confirm-changeset
      
      - name: Update AstraDB Security Content
        run: |
          python data/import-scripts/load_security_data.py
        env:
          ASTRA_DB_TOKEN: ${{ secrets.ASTRA_DB_TOKEN }}
          ASTRA_DB_URL: ${{ secrets.ASTRA_DB_URL }}
```

---

## 📚 Available Security Topics

### Network Security
- Firewalls & IDS/IPS
- VPN & Secure Remote Access
- Network Segmentation
- DDoS Protection
- Network Monitoring

### Web Application Security
- OWASP Top 10
- SQL Injection
- Cross-Site Scripting (XSS)
- CSRF & Session Management
- API Security

### Cloud Security
- AWS IAM & Security
- Azure Security Center
- GCP Security Best Practices
- Container Security
- Serverless Security

### Cryptography
- Symmetric & Asymmetric Encryption
- Hashing Algorithms
- Digital Signatures
- PKI & Certificate Management
- TLS/SSL

### Incident Response
- IR Lifecycle (NIST)
- Digital Forensics
- Malware Analysis
- Threat Hunting
- Security Operations

### Compliance & Governance
- GDPR
- HIPAA
- PCI-DSS
- SOC 2
- ISO 27001

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/NewSecurityTopic`)
3. Add cybersecurity content to `data/cybersecurity-content/`
4. Commit your changes (`git commit -m 'Add new security topic: XYZ'`)
5. Push to the branch (`git push origin feature/NewSecurityTopic`)
6. Open a Pull Request

### Adding New Security Content

To add new cybersecurity topics:

1. Create a JSON file in `data/cybersecurity-content/`
2. Follow this structure:
```json
{
  "topic": "Your Security Topic",
  "category": "Specific Category",
  "difficulty": "easy|medium|hard|expert",
  "content": "Detailed security content...",
  "tags": ["tag1", "tag2", "tag3"]
}
```
3. Run the import script to load into AstraDB

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙋‍♂️ Support

For questions or issues:
- 📧 Email: security-quiz@example.com
- 💬 GitHub Issues: [Create an issue](https://github.com/yourusername/cybersecurity-quiz-generator/issues)
- 📚 Documentation: [Read the docs](https://docs.example.com/cybersecurity-quiz)
- 🔐 Security Issues: security@example.com

---

## 🌟 Acknowledgments

- AWS Bedrock team for powerful AI capabilities
- DataStax for AstraDB vector database
- OWASP for web security resources
- NIST for cybersecurity frameworks
- MITRE ATT&CK for threat intelligence
- Open-source security community

---

## ⚠️ Disclaimer

This tool is designed for educational and training purposes. The quizzes generated should be reviewed by cybersecurity professionals before use in production training environments. Always follow your organization's security policies and compliance requirements.

---

**Built with ❤️ using AWS Bedrock, Lambda, and AstraDB for Cybersecurity Education**
