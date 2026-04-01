/**
 * Mobile Application Security Scanner Module
 * Detects vulnerabilities in Android and iOS applications
 */

const axios = require('axios');

class MobileSecurityScanner {
    constructor() {
        this.platforms = {
            android: 'Android',
            ios: 'iOS'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            android: [
                {
                    id: 'MOB-A-001',
                    title: 'Insecure WebView Implementation',
                    description: 'WebView configured without proper security settings allowing JavaScript execution',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /setJavaScriptEnabled\s*\(\s*true\s*\)/.test(content) &&
                                   !/addJavascriptInterface/.test(content) === false;
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-002',
                    title: 'Debug Flag Enabled',
                    description: 'Android application has debug flag enabled in production',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /android:debuggable\s*=\s*["']true["']/.test(content) ||
                                   /android:debuggable\s*=\s*"true"/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-003',
                    title: 'Exported Components',
                    description: 'Android components (Activity, Service, BroadcastReceiver) are exported without proper permissions',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /android:exported\s*=\s*["']true["']/.test(content) &&
                                   !/android:permission/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-004',
                    title: 'Insecure Backup Enabled',
                    description: 'Android backup is enabled allowing data extraction via ADB',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /android:allowBackup\s*=\s*["']true["']/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-005',
                    title: 'Cleartext Traffic Allowed',
                    description: 'Application allows cleartext (HTTP) traffic',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /android:usesCleartextTraffic\s*=\s*["']true["']/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-006',
                    title: 'Weak Cryptographic Algorithm',
                    description: 'Application uses weak cryptographic algorithms (MD5, SHA1, DES)',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            const weakAlgos = ['MessageDigest.getInstance("MD5"', 'Cipher.getInstance("DES')];
                            return weakAlgos.some(a => content.includes(a));
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-007',
                    title: 'Hardcoded Credentials',
                    description: 'Application contains hardcoded credentials or API keys',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            const patterns = [
                                /password\s*[=:]\s*["'][^"']+["']/i,
                                /api_key\s*[=:]\s*["'][A-Za-z0-9]{16,}/i,
                                /"sk_live_[^"]+"/,
                                /"AIza[A-Za-z0-9_-]{35}"/
                            ];
                            return patterns.some(p => p.test(content));
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-008',
                    title: 'Insecure SharedPreferences',
                    description: 'Data stored in SharedPreferences without encryption',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /getSharedPreferences\s*\(/.test(content) &&
                                   !/EncryptedSharedPreferences/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-009',
                    title: 'Root Detection Bypass Possible',
                    description: 'Root detection can be bypassed using common techniques',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return /root|checkRoot|SUFile/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-010',
                    title: 'Insecure SSL/TLS Implementation',
                    description: 'TrustManager incorrectly implements certificate validation',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            return /TrustManager\s*{|NullTrustManager|ALLOW_ALL_HOSTNAME_VERIFIER/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-011',
                    title: 'Deep Link Without Verification',
                    description: 'Deep links handled without proper validation',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /<intent-filter>/.test(content) && 
                                   !/android:scheme/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-A-012',
                    title: 'Clipboard Access Risk',
                    description: 'Application may read/write sensitive data to clipboard',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return /ClipboardManager|ClipData/.test(content);
                        }
                        return false;
                    }
                }
            ],
            ios: [
                {
                    id: 'MOB-I-001',
                    title: 'Jailbreak Detection Bypass Possible',
                    description: 'Jailbreak detection can be bypassed',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            const jailbreakPaths = ['/Applications/Cydia.app', '/Library/MobileSubstrate', '/bin/bash'];
                            return jailbreakPaths.some(p => content.includes(p));
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-002',
                    title: 'Insecure Keychain Storage',
                    description: 'Keychain items stored without proper access control',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /kSecAttrAccessibleWhenUnlocked/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-003',
                    title: 'Weak TLS Configuration',
                    description: 'ATS (App Transport Security) disabled or misconfigured',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /NSAllowsArbitraryLoads\s*=\s*YES/.test(content) ||
                                   /NSAllowsLocalNetworking\s*=\s*YES/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-004',
                    title: 'Hardcoded Credentials',
                    description: 'iOS application contains hardcoded credentials',
                    severity: 'critical',
                    check: async (content) => {
                        if (content) {
                            const patterns = [
                                /password\s*=\s*["'][^"']+["']/i,
                                /api_key\s*=\s*["'][A-Za-z0-9]{16,}/i,
                                /"sk_live_[^"]+"/
                            ];
                            return patterns.some(p => p.test(content));
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-005',
                    title: 'Insecure Data Storage',
                    description: 'Sensitive data stored in plist files or UserDefaults',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /\.plist/.test(content) && 
                                   (content.includes('password') || content.includes('token'));
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-006',
                    title: 'Debug Symbols Exposed',
                    description: 'Binary contains debug symbols that may aid reverse engineering',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /<compile\s+source=\s*"Yes"/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-007',
                    title: 'Pasteboard Sensitive Data',
                    description: 'Application copies sensitive data to pasteboard',
                    severity: 'low',
                    check: async (content) => {
                        if (content) {
                            return /UIPasteboard|generalPasteboard/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-008',
                    title: 'Insecure Random Number Generation',
                    description: 'Uses arc4random instead of SecRandomCopyBytes',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /arc4random/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-009',
                    title: 'Weak Crypto Usage',
                    description: 'Uses CommonCrypto with weak algorithms',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /CC_MD5|CC_SHA1|CCCrypt/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-I-010',
                    title: 'URL Scheme Hijacking Risk',
                    description: 'Custom URL schemes may be intercepted',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /CFBundleURLTypes/.test(content);
                        }
                        return false;
                    }
                }
            ],
            general: [
                {
                    id: 'MOB-G-001',
                    title: 'Excessive Permissions Requested',
                    description: 'Application requests more permissions than necessary',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            const excessivePerms = ['READ_CONTACTS', 'READ_SMS', 'CAMERA', 'RECORD_AUDIO'];
                            return excessivePerms.filter(p => content.includes(p)).length >= 3;
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-G-002',
                    title: 'Logging of Sensitive Data',
                    description: 'Application logs sensitive information',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /Log\.|NSLog|print\(/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-G-003',
                    title: 'Insecure Session Management',
                    description: 'Session tokens stored or transmitted insecurely',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return /session.*storage|sessionStorage/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-G-004',
                    title: 'No Certificate Pinning',
                    description: 'Application does not implement certificate pinning',
                    severity: 'high',
                    check: async (content) => {
                        if (content) {
                            return !/certificate.*pinning|SSL.*pinning|TrustManager/.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-G-005',
                    title: 'Insufficient Binary Protection',
                    description: 'Binary not obfuscated and easily reversible',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            const classNames = content.match(/[A-Z][a-zA-Z]+/g) || [];
                            return classNames.length > 100 && !/proguard|obfuscate/i.test(content);
                        }
                        return false;
                    }
                },
                {
                    id: 'MOB-G-006',
                    title: 'Third-party SDK Vulnerabilities',
                    description: 'Application uses outdated third-party libraries',
                    severity: 'medium',
                    check: async (content) => {
                        if (content) {
                            return /version\s*[<>=]+\s*["']/.test(content);
                        }
                        return false;
                    }
                }
            ]
        };
    }

    async scanTarget(url, scanId, options = {}) {
        const { platform = 'android', content } = options;
        
        const results = {
            scanId,
            targetUrl: url,
            scanner: 'Mobile Application Security Scanner',
            platform: platform,
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            findings: {}
        };

        try {
            let scanContent = content;
            
            if (!scanContent && url) {
                try {
                    const response = await axios.get(url, {
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: { 'User-Agent': 'VulnScanPro/2.0 Security Scanner' }
                    });
                    scanContent = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                } catch (err) {
                    console.log('Could not fetch URL content for mobile scan');
                }
            }

            const patternsToCheck = platform === 'ios' ? [...this.patterns.ios, ...this.patterns.general] : [...this.patterns.android, ...this.patterns.general];

            for (const pattern of patternsToCheck) {
                try {
                    const isVulnerable = await pattern.check(scanContent);

                    if (isVulnerable) {
                        const vulnerability = {
                            id: pattern.id,
                            title: pattern.title,
                            description: pattern.description,
                            severity: pattern.severity,
                            platform: platform.toUpperCase(),
                            remediation: this.getRemediation(pattern.id),
                            discoveredAt: new Date().toISOString()
                        };

                        results.vulnerabilities.push(vulnerability);
                        results.summary[pattern.severity]++;
                    }
                } catch (err) {
                    console.error(`Mobile check ${pattern.id} failed:`, err.message);
                }
            }

            results.endTime = new Date().toISOString();
            results.totalVulnerabilities = results.vulnerabilities.length;

        } catch (error) {
            results.error = error.message;
            results.endTime = new Date().toISOString();
        }

        return results;
    }

    getRemediation(id) {
        const remediations = {
            'MOB-A-001': 'Disable JavaScript in WebView unless necessary. Use addJavascriptInterface with @JavascriptInterface only for trusted content. Enable DOM storage encryption.',
            'MOB-A-002': 'Set android:debuggable="false" in manifest. Use BuildConfig.DEBUG for conditional debugging code.',
            'MOB-A-003': 'Set android:exported="false" or add proper android:permission for exported components. Use intent filters carefully.',
            'MOB-A-004': 'Set android:allowBackup="false" in manifest. Use Android backup rules with encrypted backups.',
            'MOB-A-005': 'Set android:usesCleartextTraffic="false". Use HTTPS only. Implement network security config.',
            'MOB-A-006': 'Use AES-256 or RSA-2048 for encryption. Use Android Keystore for key storage.',
            'MOB-A-007': 'Never hardcode credentials. Use Android Keystore, EncryptedSharedPreferences, or secure backend authentication.',
            'MOB-A-008': 'Use EncryptedSharedPreferences or Android Keystore for sensitive data storage.',
            'MOB-A-009': 'Implement multiple root detection techniques. Check for su binary, root management apps, and system properties.',
            'MOB-A-010': 'Never implement custom TrustManager. Use system default certificate validation. Implement certificate pinning.',
            'MOB-A-011': 'Validate all deep link data. Use App Links for verified associations.',
            'MOB-A-012': 'Disable copy/paste for sensitive fields. Use custom EditText with paste disabled.',
            'MOB-I-001': 'Implement multiple jailbreak detection methods. Check for common paths, sandbox integrity, and fork ability.',
            'MOB-I-002': 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive keychain items. Enable biometric authentication.',
            'MOB-I-003': 'Enable ATS (App Transport Security). Set NSAllowsArbitraryLoads to NO.',
            'MOB-I-004': 'Never store credentials in code. Use Keychain Services with proper access controls.',
            'MOB-I-005': 'Use Keychain for sensitive data. Never store sensitive info in UserDefaults or plist files.',
            'MOB-I-006': 'Strip debug symbols in release builds. Use Xcode build settings for symbol stripping.',
            'MOB-I-007': 'Avoid copying sensitive data to pasteboard. Clear pasteboard when app enters background.',
            'MOB-I-008': 'Use SecRandomCopyBytes for cryptographic random number generation.',
            'MOB-I-009': 'Use CryptoKit or third-party libraries like CryptoSwift for modern cryptographic operations.',
            'MOB-I-010': 'Validate URL schemes. Use universal links instead of custom URL schemes when possible.',
            'MOB-G-001': 'Request only necessary permissions. Use runtime permission requests with proper justification.',
            'MOB-G-002': 'Remove all logging statements in release builds. Use conditional compilation.',
            'MOB-G-003': 'Use secure token storage. Implement proper session expiration and token refresh.',
            'MOB-G-004': 'Implement certificate pinning using libraries like TrustKit for Android or certificate pinning for iOS.',
            'MOB-G-005': 'Use code obfuscation tools like ProGuard (Android) or obfuscate iOS code. Enable bitcode.',
            'MOB-G-006': 'Regularly update third-party SDKs. Use dependency scanning tools like OWASP Dependency-Check.'
        };
        return remediations[id] || 'Follow mobile security best practices for the affected platform.';
    }

    getSummary() {
        return {
            platforms: Object.entries(this.platforms).map(([key, name]) => ({
                id: key,
                name,
                patternCount: this.patterns[key]?.length || 0
            })),
            generalPatternCount: this.patterns.general.length,
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { MobileSecurityScanner };
