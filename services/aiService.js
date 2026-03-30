const Groq = require('groq-sdk');

// Security-focused system prompt
const SECURITY_SYSTEM_PROMPT = `You are an expert cybersecurity assistant specializing in penetration testing, vulnerability assessment, and security best practices.

Your expertise includes:
- OWASP Top 10 vulnerabilities and mitigations
- Network security and penetration testing
- Web application security
- Mobile application security
- Cloud security
- Incident response and forensics
- Security compliance (GDPR, HIPAA, PCI-DSS)
- Kali Linux tools and usage
- Exploit development and mitigation
- Security architecture and hardening

Guidelines:
1. Always prioritize safety and legal compliance
2. Explain vulnerabilities clearly with practical examples
3. Provide actionable remediation steps
4. Reference industry standards (OWASP, NIST, ISO 27001)
5. Suggest relevant tools and commands when appropriate
6. If unsure, acknowledge limitations and suggest consulting security professionals

Current date: ${new Date().toISOString().split('T')[0]}`;

class AIService {
    constructor() {
        // Initialize Groq with API key
        this.apiKey = process.env.GROQ_API_KEY;
        this.mockMode = !this.apiKey;

        if (!this.mockMode) {
            this.groq = new Groq({ apiKey: this.apiKey });
            console.log('✅ Groq AI Service initialized');
        } else {
            console.log('⚠️  Groq AI Service running in MOCK mode (Set GROQ_API_KEY in .env)');
        }
    }

    async chat(message, context = {}) {
        try {
            if (this.mockMode) {
                // Simulate network delay
                await new Promise(resolve => setTimeout(resolve, 500));
                return this.getMockResponse(message, context);
            }

            const messages = [
                {
                    role: 'system',
                    content: SECURITY_SYSTEM_PROMPT
                }
            ];

            // Add context if provided
            if (context && Object.keys(context).length > 0) {
                messages.push({
                    role: 'system',
                    content: `Context: ${JSON.stringify(context)}`
                });
            }

            messages.push({
                role: 'user',
                content: message
            });

            const completion = await this.groq.chat.completions.create({
                messages: messages,
                model: 'llama3-8b-8192',  // Groq's fast Llama 3 model
                temperature: 0.7,
                max_tokens: 1024,
                top_p: 1,
                stream: false
            });

            const response = completion.choices[0]?.message?.content || 'No response generated';

            return {
                success: true,
                response: response,
                timestamp: new Date().toISOString(),
                model: 'llama3-8b-8192',
                provider: 'groq'
            };
        } catch (error) {
            console.error('Groq API Error:', error);
            return {
                success: false,
                error: 'AI service temporarily unavailable',
                fallback: this.getMockResponse(message, context)
            };
        }
    }

    async analyzeVulnerability(vulnerabilityData) {
        const prompt = `Analyze the following vulnerability and provide:
1. Risk assessment
2. Exploitation scenario
3. Step-by-step remediation
4. Prevention recommendations

Vulnerability Data:
${JSON.stringify(vulnerabilityData, null, 2)}`;

        return this.chat(prompt, { type: 'vulnerability_analysis' });
    }

    async generateReportSummary(scanResults) {
        const prompt = `Generate an executive summary of the following security scan results:

${JSON.stringify(scanResults, null, 2)}

Include:
- Overall risk level
- Critical findings
- Remediation priorities
- Timeline recommendations`;

        return this.chat(prompt, { type: 'report_summary' });
    }

    async suggestRemediation(vulnerabilityType, severity) {
        const prompt = `Provide detailed remediation steps for a ${severity} severity ${vulnerabilityType} vulnerability.

Include:
1. Immediate containment actions
2. Long-term fixes
3. Testing validation steps
4. Monitoring recommendations`;

        return this.chat(prompt, { type: 'remediation' });
    }

    async explainCVE(cveId) {
        const prompt = `Explain CVE-${cveId} in detail:
1. What is the vulnerability?
2. Which systems are affected?
3. How can it be exploited?
4. What are the mitigations?
5. Real-world impact examples`;

        return this.chat(prompt, { type: 'cve_explanation' });
    }

    getMockResponse(message, context) {
        const lowerMessage = message.toLowerCase();

        // Mock responses for common security questions
        if (lowerMessage.includes('sql injection') || lowerMessage.includes('sqli')) {
            return {
                success: true,
                response: `**SQL Injection (SQLi)** is one of the most critical web application vulnerabilities.

**What it is:**
SQL Injection occurs when an attacker can insert malicious SQL code into queries, allowing them to read, modify, or delete database contents.

**Common Attack Vectors:**
- Login forms (bypass authentication)
- Search fields
- URL parameters
- API endpoints

**Example Payload:**
\`\`\`sql
' OR '1'='1' --
' UNION SELECT username, password FROM users --
\`\`\`

**Prevention:**
1. Use parameterized queries/prepared statements
2. Input validation and sanitization
3. Principle of least privilege for database accounts
4. Web Application Firewall (WAF)
5. Regular security testing

**Tools for Detection:**
- SQLMap (automated SQLi detection)
- Burp Suite
- OWASP ZAP

Would you like me to explain any specific aspect in more detail?`,
                timestamp: new Date().toISOString(),
                model: 'mock-mode',
                provider: 'local',
                mock: true
            };
        }

        if (lowerMessage.includes('xss') || lowerMessage.includes('cross-site')) {
            return {
                success: true,
                response: `**Cross-Site Scripting (XSS)** allows attackers to inject client-side scripts into web pages.

**Types of XSS:**

1. **Stored XSS** - Malicious script is permanently stored on the server
2. **Reflected XSS** - Script is reflected off the web server (e.g., in error messages)
3. **DOM-based XSS** - Vulnerability exists in client-side code

**Example Payload:**
\`\`\`html
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
\`\`\`

**Impact:**
- Session hijacking
- Credential theft
- Defacement
- Malware distribution

**Prevention:**
1. Output encoding/escaping
2. Content Security Policy (CSP)
3. Input validation
4. HttpOnly cookie flag
5. X-XSS-Protection header

**Testing Tools:**
- XSStrike
- DalFox
- Burp Suite XSS payloads`,
                timestamp: new Date().toISOString(),
                model: 'mock-mode',
                provider: 'local',
                mock: true
            };
        }

        if (lowerMessage.includes('nmap')) {
            return {
                success: true,
                response: `**Nmap** (Network Mapper) is the industry standard for network discovery and security auditing.

**Basic Commands:**

\`\`\`bash
# Basic port scan
nmap target.com

# Scan specific ports
nmap -p 22,80,443 target.com

# Service version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Aggressive scan (all features)
nmap -A target.com

# Scan entire subnet
nmap 192.168.1.0/24

# Stealth scan (TCP SYN)
nmap -sS target.com

# UDP scan
nmap -sU target.com
\`\`\`

**Common Options:**
- \`-sS\`: TCP SYN scan (stealthy)
- \`-sT\`: TCP connect scan
- \`-sU\`: UDP scan
- \`-sV\`: Version detection
- \`-O\`: OS detection
- \`-A\`: Aggressive (OS, version, scripts, traceroute)
- \`-p\`: Port specification
- \`-T\`: Timing template (0-5)

**Script Scanning:**
\`\`\`bash
# Vulnerability scanning
nmap --script vuln target.com

# HTTP enumeration
nmap --script http-enum target.com

# SMB checks
nmap --script smb-* target.com
\`\`\``,
                timestamp: new Date().toISOString(),
                model: 'mock-mode',
                provider: 'local',
                mock: true
            };
        }

        if (lowerMessage.includes('owasp') || lowerMessage.includes('top 10')) {
            return {
                success: true,
                response: `**OWASP Top 10 (2021)** - The most critical security risks to web applications:

1. **Broken Access Control**
   - Users accessing unauthorized functions/data
   - Prevention: Deny by default, implement once, reuse

2. **Cryptographic Failures**
   - Weak encryption, exposed sensitive data
   - Prevention: Encrypt data at rest and in transit

3. **Injection**
   - SQL, NoSQL, OS command, LDAP injection
   - Prevention: Parameterized queries, input validation

4. **Insecure Design**
   - Fundamental design flaws
   - Prevention: Threat modeling, secure design patterns

5. **Security Misconfiguration**
   - Default configs, incomplete setups
   - Prevention: Hardening guides, automated scanning

6. **Vulnerable and Outdated Components**
   - Using components with known vulnerabilities
   - Prevention: Inventory management, regular updates

7. **Identification and Authentication Failures**
   - Weak passwords, session management issues
   - Prevention: MFA, strong session handling

8. **Software and Data Integrity Failures**
   - Insecure deserialization, CI/CD issues
   - Prevention: Integrity verification, digital signatures

9. **Security Logging and Monitoring Failures**
   - Insufficient logging, missed detections
   - Prevention: Comprehensive logging, real-time monitoring

10. **Server-Side Request Forgery (SSRF)**
    - Server making unauthorized requests
    - Prevention: Input validation, network segmentation`,
                timestamp: new Date().toISOString(),
                model: 'mock-mode',
                provider: 'local',
                mock: true
            };
        }

        // Default response
        return {
            success: true,
            response: `I'm your AI Security Assistant powered by Groq! I can help you with:

**Topics I Cover:**
- 🛡️ Vulnerability explanations (OWASP Top 10)
- 🔧 Security tools and commands (Nmap, Burp Suite, etc.)
- 📋 Penetration testing methodologies
- 🛠️ Remediation strategies
- 📚 CVE analysis
- 🔐 Best practices and compliance

**Try asking me about:**
- "What is SQL Injection?"
- "How do I use Nmap?"
- "Explain XSS vulnerabilities"
- "OWASP Top 10 overview"
- "How to prevent [vulnerability]?"

*Note: I'm currently running in demo mode. To use Groq's ultra-fast LLM inference (up to 800+ tokens/second), configure your GROQ_API_KEY in the backend .env file.*

What security topic would you like to explore?`,
            timestamp: new Date().toISOString(),
            model: 'mock-mode',
            provider: 'local',
            mock: true
        };
    }
}

module.exports = new AIService();
