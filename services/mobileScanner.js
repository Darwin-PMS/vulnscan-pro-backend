const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

const MOBILE_PATTERNS = {
    android: [
        {
            id: 'AND-001',
            title: 'Insecure WebView Implementation',
            category: 'WebView Security',
            severity: 'high',
            description: 'WebView with JavaScript enabled and no SSL pinning',
            detection: ['addJavascriptInterface', 'setJavaScriptEnabled', 'WebView'],
            risk: 'Allows remote code execution through injected JavaScript',
            remediation: 'Disable JavaScript if not needed, implement certificate pinning, validate URLs',
            references: ['OWASP M1', 'MASVS-NETWORK-2']
        },
        {
            id: 'AND-002',
            title: 'Exported Components',
            category: 'Component Security',
            severity: 'critical',
            description: 'Activities, Services, or BroadcastReceivers exported without proper permissions',
            detection: ['android:exported', 'android:protectionLevel'],
            risk: 'Allows other apps to interact with app components',
            remediation: 'Set android:exported=false or use proper permission checks',
            references: ['OWASP M4', 'MASVS-PLATFORM-1']
        },
        {
            id: 'AND-003',
            title: 'Insecure Data Storage',
            category: 'Data Storage',
            severity: 'critical',
            description: 'Sensitive data stored in SharedPreferences without encryption',
            detection: ['MODE_WORLD_READABLE', 'MODE_WORLD_WRITABLE', 'SharedPreferences'],
            risk: 'Other apps can access sensitive user data',
            remediation: 'Use EncryptedSharedPreferences, store sensitive data in internal storage',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'AND-004',
            title: 'Weak Cryptography',
            category: 'Cryptography',
            severity: 'critical',
            description: 'Use of deprecated cryptographic algorithms (MD5, SHA1, DES)',
            detection: ['MessageDigest.getInstance("MD5")', 'Cipher.getInstance("DES")', 'SHA1'],
            risk: 'Sensitive data can be decrypted by attackers',
            remediation: 'Use AES-256, SHA-256+, RSA-2048+ from Android Keystore',
            references: ['OWASP M5', 'MASVS-CRYPTO-1']
        },
        {
            id: 'AND-005',
            title: 'Hardcoded Credentials',
            category: 'Code Security',
            severity: 'high',
            description: 'API keys, secrets, or passwords found in source code',
            detection: ['api_key', 'secret', 'password', 'token', 'credential'],
            risk: 'Attackers can extract hardcoded secrets to access backend systems',
            remediation: 'Use Android Keystore, environment variables, or secure backend',
            references: ['OWASP M1', 'MASVS-CRYPTO-6']
        },
        {
            id: 'AND-006',
            title: 'Insecure Network Communication',
            category: 'Network Security',
            severity: 'critical',
            description: 'Cleartext traffic or missing certificate pinning',
            detection: ['usesCleartextTraffic', 'networkSecurityConfig', 'TrustManager'],
            risk: 'Man-in-the-middle attacks can intercept sensitive data',
            remediation: 'Enable TLS, implement certificate pinning, use Network Security Config',
            references: ['OWASP M3', 'MASVS-NETWORK-1']
        },
        {
            id: 'AND-007',
            title: 'Deep Link Vulnerability',
            category: 'Platform Security',
            severity: 'high',
            description: 'URL schemes or App Links without proper validation',
            detection: ['android:scheme', 'intent-filter', 'android:autoVerify'],
            risk: ' attackers can inject malicious data through deep links',
            remediation: 'Validate all URL parameters, use path whitelisting',
            references: ['OWASP M4', 'MASVS-PLATFORM-2']
        },
        {
            id: 'AND-008',
            title: 'Weak Root/Jailbreak Detection',
            category: 'Device Security',
            severity: 'medium',
            description: 'Insufficient or bypassable root/jailbreak detection',
            detection: ['su binary', 'RootManagement', 'Magisk', '/system/app/Superuser.apk'],
            risk: 'Device integrity cannot be verified',
            remediation: 'Use multiple detection methods, SafetyNet API, Play Integrity API',
            references: ['OWASP M8', 'MASVS-RESILIENCE-1']
        },
        {
            id: 'AND-009',
            title: 'Insecure Content Provider',
            category: 'IPC Security',
            severity: 'high',
            description: 'ContentProvider with open permissions or no permission checks',
            detection: ['<provider>', 'android:grantUriPermissions', 'android:permission'],
            risk: 'Unauthorized access to app data',
            remediation: 'Use strict permissions, implement input validation in ContentProvider',
            references: ['OWASP M4', 'MASVS-PLATFORM-1']
        },
        {
            id: 'AND-010',
            title: 'Debug Flags Enabled',
            category: 'Build Security',
            severity: 'medium',
            description: 'Application in debug mode or debuggable flag set',
            detection: ['android:debuggable', 'android:usesCleartextTraffic'],
            risk: 'Attackers can attach debuggers and analyze app behavior',
            remediation: 'Set debuggable=false in release builds, use ProGuard/R8',
            references: ['OWASP M8', 'MASVS-RESILIENCE-5']
        },
        {
            id: 'AND-011',
            title: 'Backup Vulnerability',
            category: 'Data Security',
            severity: 'medium',
            description: 'AndroidManifest allows backups with sensitive data',
            detection: ['android:allowBackup', 'android:fullBackupContent'],
            risk: 'Sensitive data can be extracted from app backups',
            remediation: 'Set android:allowBackup=false or exclude sensitive files',
            references: ['OWASP M2', 'MASVS-STORAGE-2']
        },
        {
            id: 'AND-012',
            title: 'Clipboard Data Exposure',
            category: 'Data Security',
            severity: 'medium',
            description: 'Sensitive data copied to clipboard without restriction',
            detection: ['ClipboardManager', 'ClipboardData'],
            risk: 'Other apps can read sensitive data from clipboard',
            remediation: 'Disable clipboard for sensitive fields, use FLAG_SECURE',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'AND-013',
            title: 'Insecure BroadcastReceiver',
            category: 'IPC Security',
            severity: 'high',
            description: 'BroadcastReceiver with sensitive actions not properly protected',
            detection: ['<receiver>', 'android:permission', 'LocalBroadcastManager'],
            risk: 'Unauthorized apps can send malicious broadcasts',
            remediation: 'Use explicit intents, require permissions for sensitive broadcasts',
            references: ['OWASP M4', 'MASVS-PLATFORM-1']
        },
        {
            id: 'AND-014',
            title: 'SQL Injection (Content Provider)',
            category: 'Injection',
            severity: 'critical',
            description: 'SQL injection vulnerability in ContentProvider queries',
            detection: ['query(', 'rawQuery(', 'selectionArgs'],
            risk: ' attackers can extract or modify database content',
            remediation: 'Use parameterized queries, validate input, implement proper SQL escaping',
            references: ['OWASP M7', 'MASVS-CODE-1']
        },
        {
            id: 'AND-015',
            title: 'Insecure Intent Handling',
            category: 'IPC Security',
            severity: 'medium',
            description: 'Implicit Intents with sensitive data or no verification',
            detection: ['startActivity(intent)', 'Intent Filter', 'Intent.EXTRA_TEXT'],
            risk: 'Sensitive data can be intercepted by malicious apps',
            remediation: 'Use explicit intents, verify receiving packages, avoid sensitive data in intents',
            references: ['OWASP M4', 'MASVS-PLATFORM-2']
        },
        {
            id: 'AND-016',
            title: 'Missing ProGuard/Obfuscation',
            category: 'Code Security',
            severity: 'medium',
            description: 'App not obfuscated making reverse engineering easier',
            detection: ['proguard-rules.pro', '-keepnames', '-donotobfuscate'],
            risk: 'Source code easily readable, easier to find vulnerabilities',
            remediation: 'Enable ProGuard/R8, use code shrinking and obfuscation',
            references: ['OWASP M8', 'MASVS-RESILIENCE-2']
        },
        {
            id: 'AND-017',
            title: 'Insecure External Storage Access',
            category: 'Storage Security',
            severity: 'high',
            description: 'Writing sensitive data to external storage',
            detection: ['Environment.getExternalStorageDirectory()', 'getExternalFilesDir'],
            risk: 'Any app can read sensitive files from external storage',
            remediation: 'Use internal storage only, encrypt data if external storage is necessary',
            references: ['OWASP M2', 'MASVS-STORAGE-3']
        },
        {
            id: 'AND-018',
            title: 'Keyboard Cache Enabled',
            category: 'Input Security',
            severity: 'medium',
            description: 'Text fields with sensitive data have keyboard autocomplete',
            detection: ['android:inputType="textVisiblePassword"', 'android:importantForAutofill'],
            risk: 'Sensitive data like passwords cached by keyboard',
            remediation: 'Set inputType appropriately, use autofill hints correctly',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'AND-019',
            title: 'Insecure Auto-Start',
            category: 'Device Security',
            severity: 'low',
            description: 'App configured to auto-start on boot',
            detection: ['BOOT_COMPLETED', 'RECEIVE_BOOT_COMPLETED', 'BroadcastReceiver'],
            risk: 'App runs unnecessarily, potential for exploitation',
            remediation: 'Remove boot receivers if not necessary',
            references: ['OWASP M8', 'MASVS-RESILIENCE-1']
        },
        {
            id: 'AND-020',
            title: 'Weak Biometric Authentication',
            category: 'Authentication',
            severity: 'high',
            description: 'Biometric auth without device credential fallback properly handled',
            detection: ['BiometricPrompt', 'BiometricManager', 'setAllowedAuthenticators'],
            risk: 'Biometric can be bypassed through fallback mechanism',
            remediation: 'Implement CryptoObject, require biometric + device credential',
            references: ['OWASP M4', 'MASVS-AUTH-1']
        }
    ],
    ios: [
        {
            id: 'IOS-001',
            title: 'Insecure Data Storage (UserDefaults)',
            category: 'Data Storage',
            severity: 'critical',
            description: 'Sensitive data stored in UserDefaults plist',
            detection: ['UserDefaults.standard', '.dictionaryRepresentation', '.setObject'],
            risk: 'Sensitive data easily accessible through iTunes backup',
            remediation: 'Use Keychain for sensitive data, enable iOS Data Protection',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'IOS-002',
            title: 'Keychain Weak Access Control',
            category: 'Data Storage',
            severity: 'high',
            description: 'Keychain items with weak accessibility level',
            detection: ['kSecAttrAccessible', 'kSecAttrAccessibleWhenUnlocked', 'kSecAttrAccessibleAfterFirstUnlock'],
            risk: 'Keychain data accessible in certain conditions',
            remediation: 'Use kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly',
            references: ['OWASP M2', 'MASVS-STORAGE-2']
        },
        {
            id: 'IOS-003',
            title: 'Missing Certificate Pinning',
            category: 'Network Security',
            severity: 'critical',
            description: 'Network requests without SSL certificate pinning',
            detection: ['NSURLSession', 'URLSession', 'serverTrust'],
            risk: 'MITM attacks can intercept network traffic',
            remediation: 'Implement certificate pinning using TrustKit or custom validation',
            references: ['OWASP M3', 'MASVS-NETWORK-2']
        },
        {
            id: 'IOS-004',
            title: 'ATS Disabled or Weak',
            category: 'Network Security',
            severity: 'high',
            description: 'App Transport Security disabled or has exceptions',
            detection: ['NSAppTransportSecurity', 'NSAllowsArbitraryLoads', 'NSExceptionDomains'],
            risk: 'Insecure HTTP connections allowed',
            remediation: 'Enable ATS fully, remove exceptions, use HTTPS only',
            references: ['OWASP M3', 'MASVS-NETWORK-1']
        },
        {
            id: 'IOS-005',
            title: 'Insecure WebView Implementation',
            category: 'WebView Security',
            severity: 'high',
            description: 'WKWebView with JavaScript enabled and no CSP',
            detection: ['WKWebView', 'javaScriptEnabled', 'allowsInlineMediaPlayback'],
            risk: 'XSS and injection attacks through WebView',
            remediation: 'Disable JavaScript if not needed, implement CSP',
            references: ['OWASP M1', 'MASVS-WEBVIEW-1']
        },
        {
            id: 'IOS-006',
            title: 'URL Scheme Hijacking',
            category: 'Platform Security',
            severity: 'high',
            description: 'Custom URL schemes without proper validation',
            detection: ['CFBundleURLTypes', 'UIApplication.open', 'URL Schemes'],
            risk: ' attackers can intercept or manipulate URL scheme calls',
            remediation: 'Validate URL parameters, use universal links instead',
            references: ['OWASP M4', 'MASVS-PLATFORM-2']
        },
        {
            id: 'IOS-007',
            title: 'Pasteboard Data Exposure',
            category: 'Data Security',
            severity: 'medium',
            description: 'Sensitive data copied to clipboard without expiration',
            detection: ['UIPasteboard.general', 'UIPasteboard.general.string'],
            risk: 'Sensitive data remains in clipboard accessible to other apps',
            remediation: 'Set expiration on clipboard data, use find only pasteboard',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'IOS-008',
            title: 'Weak Jailbreak Detection',
            category: 'Device Security',
            severity: 'medium',
            description: 'Insufficient or easily bypassable jailbreak detection',
            detection: ['/Applications/Cydia.app', '/private/var/lib/apt', 'Substrate'],
            risk: 'App runs on compromised device without warning',
            remediation: 'Use multiple detection methods, check for common paths',
            references: ['OWASP M8', 'MASVS-RESILIENCE-1']
        },
        {
            id: 'IOS-009',
            title: 'Insecure Random Number Generation',
            category: 'Cryptography',
            severity: 'high',
            description: 'Using srand() or arc4random() for security-critical operations',
            detection: ['srand()', 'arc4random()', 'arc4random_buf()'],
            risk: 'Predictable random numbers compromise cryptographic security',
            remediation: 'Use SecRandomCopyBytes or SystemRandomNumberGenerator',
            references: ['OWASP M5', 'MASVS-CRYPTO-1']
        },
        {
            id: 'IOS-010',
            title: 'Hardcoded Credentials',
            category: 'Code Security',
            severity: 'critical',
            description: 'API keys, secrets, or passwords in source code',
            detection: ['api_key', 'secret', 'password', 'token', 'credential'],
            risk: 'Secrets easily extracted from decompiled binary',
            remediation: 'Never store secrets in code, use secure backend or Keychain',
            references: ['OWASP M1', 'MASVS-CRYPTO-6']
        },
        {
            id: 'IOS-011',
            title: 'Weak Biometric Authentication',
            category: 'Authentication',
            severity: 'high',
            description: 'LocalAuthentication without proper fallback handling',
            detection: ['LAContext', 'evaluatePolicy', 'biometryType'],
            risk: 'Biometric can be bypassed through fallback mechanism',
            remediation: 'Use LAContext with proper policy, implement device passcode',
            references: ['OWASP M4', 'MASVS-AUTH-1']
        },
        {
            id: 'IOS-012',
            title: 'Insecure Snapshots',
            category: 'Privacy',
            severity: 'medium',
            description: 'App snapshots expose sensitive data in app switcher',
            detection: ['applicationWillResignActive', 'UIGraphicsGetImageFromCurrentImageContext'],
            risk: 'Sensitive screen content visible in app switcher',
            remediation: 'Hide sensitive views, use blur overlay when resigning active',
            references: ['OWASP M2', 'MASVS-PRIVACY-1']
        },
        {
            id: 'IOS-013',
            title: 'Weak Code Obfuscation',
            category: 'Code Security',
            severity: 'medium',
            description: 'App code not properly obfuscated',
            detection: ['class-dump', 'otool', 'strings'],
            risk: 'Easy reverse engineering reveals app logic and vulnerabilities',
            remediation: 'Use LLVM obfuscation, strip debug symbols, use binary scrambling',
            references: ['OWASP M8', 'MASVS-RESILIENCE-2']
        },
        {
            id: 'IOS-014',
            title: 'Insecure Realm/CoreData Configuration',
            category: 'Data Storage',
            severity: 'high',
            description: 'Local database without encryption or proper protection',
            detection: ['Realm.Configuration', 'NSPersistentContainer', 'NSSQLiteStoreType'],
            risk: 'Database can be extracted from jailbroken devices',
            remediation: 'Enable encryption for local databases, use secure keys',
            references: ['OWASP M2', 'MASVS-STORAGE-3']
        },
        {
            id: 'IOS-015',
            title: 'Insecure Logging',
            category: 'Data Security',
            severity: 'medium',
            description: 'Sensitive data logged to console or files',
            detection: ['print(', 'NSLog(', 'os_log(', 'debugPrint('],
            risk: 'Sensitive data visible in logs and crash reports',
            remediation: 'Remove logging in release builds, use compile flags',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'IOS-016',
            title: 'Weak Same-Origin Policy',
            category: 'WebView Security',
            severity: 'medium',
            description: 'WKWebView allows access to arbitrary origins',
            detection: ['configuration.allowsAnyHTTPSCertificate', 'allowFileAccessFromFileURLs'],
            risk: 'Malicious content can access local files',
            remediation: 'Configure WKWebView with proper security settings',
            references: ['OWASP M1', 'MASVS-WEBVIEW-2']
        },
        {
            id: 'IOS-017',
            title: 'Insecure Background Modes',
            category: 'Platform Security',
            severity: 'medium',
            description: 'Background execution enabled unnecessarily',
            detection: ['UIBackgroundModes', 'beginBackgroundTask', 'BGTaskScheduler'],
            risk: 'App continues running and accessing data in background',
            remediation: 'Only enable necessary background modes, clear sensitive data',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'IOS-018',
            title: 'Keyboard Cache Exposure',
            category: 'Input Security',
            severity: 'medium',
            description: 'Sensitive text fields with autocorrect/autocomplete enabled',
            detection: ['autocorrectionType', 'autocapitalizationType', 'spellCheckingType'],
            risk: 'Sensitive data cached by keyboard dictionary',
            remediation: 'Set autocorrectionType = .no for sensitive fields',
            references: ['OWASP M2', 'MASVS-STORAGE-1']
        },
        {
            id: 'IOS-019',
            title: 'Insecure Third-Party Libraries',
            category: 'Code Quality',
            severity: 'high',
            description: 'Outdated or vulnerable third-party SDKs used',
            detection: ['Cartfile', 'Package.swift', 'Podfile.lock', 'CocoaPods'],
            risk: 'Known vulnerabilities in dependencies can be exploited',
            remediation: 'Regularly update dependencies, use dependency scanning',
            references: ['OWASP M10', 'MASVS-CODE-5']
        },
        {
            id: 'IOS-020',
            title: 'Weak Token Storage',
            category: 'Authentication',
            severity: 'high',
            description: 'Authentication tokens not properly secured',
            detection: ['UserDefaults', 'fileManager', 'Keychain with weak access'],
            risk: 'Tokens can be stolen and used for session hijacking',
            remediation: 'Store tokens in Keychain with proper access control',
            references: ['OWASP M4', 'MASVS-AUTH-2']
        }
    ]
};

const MOBILE_TOOLS = {
    android: [
        { name: 'MobSF', description: 'Automated mobile app security analysis', url: 'https://github.com/MobSF/MobSF' },
        { name: 'Drozer', description: 'Security assessment framework for Android', url: 'https://github.com/WithSecureLabs/drozer' },
        { name: 'Frida', description: 'Dynamic instrumentation toolkit', url: 'https://frida.re' },
        { name: ' objection', description: 'Runtime mobile exploration', url: 'https://github.com/sensepost/objection' },
        { name: 'APKTool', description: 'Reverse engineering Android APKs', url: 'https://github.com/iBotPeaches/Apktool' },
        { name: 'Jadx', description: 'Dex to Java decompiler', url: 'https://github.com/skylot/jadx' }
    ],
    ios: [
        { name: 'MobSF', description: 'Automated mobile app security analysis', url: 'https://github.com/MobSF/MobSF' },
        { name: 'Frida', description: 'Dynamic instrumentation toolkit', url: 'https://frida.re' },
        { name: ' objection', description: 'Runtime mobile exploration', url: 'https://github.com/sensepost/objection' },
        { name: 'IPA Analyzer', description: 'iOS app analysis tools', url: 'https://github.com/nettitude/IPAAnalyzer' },
        { name: 'ClassDump', description: 'Objective-C class dumper', url: 'http://stevenygard.com/projects/class-dump' },
        { name: 'Cycript', description: 'Objective-C/JavaScript runtime', url: 'http://www.cycript.org' }
    ]
};

class MobileAppScanner {
    constructor() {
        this.tools = MOBILE_TOOLS;
    }

    async scanAPK(apkContent, platform = 'android') {
        const vulnerabilities = [];
        const analysis = this.analyzeContent(apkContent, platform);

        for (const vuln of analysis.findings) {
            vulnerabilities.push({
                id: uuidv4(),
                vuln_id: vuln.id,
                title: vuln.title,
                category: vuln.category,
                severity: vuln.severity,
                description: vuln.description,
                risk: vuln.risk,
                remediation: vuln.remediation,
                references: vuln.references,
                detected: true,
                matched_pattern: vuln.matched_pattern || null
            });
        }

        return {
            scan_id: uuidv4(),
            platform,
            scan_date: new Date().toISOString(),
            summary: this.generateSummary(analysis.findings),
            findings: vulnerabilities,
            recommendations: this.generateRecommendations(analysis.findings, platform),
            tools: this.tools[platform],
            manifest_analysis: analysis.manifestAnalysis,
            code_analysis: analysis.codeAnalysis,
            network_analysis: analysis.networkAnalysis
        };
    }

    analyzeContent(content, platform) {
        const findings = [];
        const patterns = MOBILE_PATTERNS[platform] || [];

        const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

        for (const pattern of patterns) {
            for (const detection of pattern.detection) {
                if (contentStr.toLowerCase().includes(detection.toLowerCase())) {
                    findings.push({
                        ...pattern,
                        matched_pattern: detection
                    });
                    break;
                }
            }
        }

        return {
            findings,
            manifestAnalysis: this.analyzeManifest(content, platform),
            codeAnalysis: this.analyzeCode(content, platform),
            networkAnalysis: this.analyzeNetwork(content, platform)
        };
    }

    analyzeManifest(content, platform) {
        const analysis = {
            exported_components: [],
            permissions: [],
            security_flags: [],
            issues: []
        };

        const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

        if (platform === 'android') {
            const exportedPatterns = [
                /android:exported\s*=\s*["']?true["']?/gi,
                /<activity[^>]*exported/gi,
                /<service[^>]*exported/gi,
                /<receiver[^>]*exported/gi,
                /<provider[^>]*exported/gi
            ];

            exportedPatterns.forEach(pattern => {
                const matches = contentStr.match(pattern);
                if (matches) {
                    analysis.exported_components.push(...matches);
                }
            });

            const permissionPatterns = [
                /android:permission\s*=\s*["']([^"']+)["']/gi,
                /<uses-permission[^>]*android:name\s*=\s*["']([^"']+)["']/gi
            ];

            permissionPatterns.forEach(pattern => {
                let match;
                while ((match = pattern.exec(contentStr)) !== null) {
                    analysis.permissions.push(match[1]);
                }
            });

            if (contentStr.includes('android:debuggable')) {
                analysis.security_flags.push('Debug flag found');
            }
            if (contentStr.includes('android:allowBackup')) {
                analysis.security_flags.push('Backup enabled');
            }
            if (contentStr.includes('usesCleartextTraffic')) {
                analysis.issues.push('Cleartext traffic allowed');
            }
        } else {
            const urlTypes = contentStr.match(/CFBundleURLTypes[\s\S]*?<\/array>/gi);
            if (urlTypes) {
                analysis.exported_components.push(...urlTypes);
            }

            const entitlements = contentStr.match(/<key>com\.apple\.security\.[\s\S]*?<\/dict>/gi);
            if (entitlements) {
                analysis.security_flags.push(...entitlements);
            }
        }

        return analysis;
    }

    analyzeCode(content, platform) {
        const analysis = {
            suspicious_patterns: [],
            crypto_usage: [],
            storage_usage: [],
            network_usage: [],
            authentication: []
        };

        const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

        const cryptoPatterns = {
            android: [
                { pattern: /Cipher\.getInstance/gi, name: 'Cipher usage' },
                { pattern: /MessageDigest\.getInstance/gi, name: 'MessageDigest usage' },
                { pattern: /SecureRandom/gi, name: 'SecureRandom usage' },
                { pattern: /KeyStore/gi, name: 'KeyStore usage' }
            ],
            ios: [
                { pattern: /SecRandomCopyBytes/gi, name: 'SecRandomCopyBytes usage' },
                { pattern: /CryptoKit/gi, name: 'CryptoKit usage' },
                { pattern: /kSecAttrAccessible/gi, name: 'Keychain access' },
                { pattern: /CCCrypt/gi, name: 'CommonCrypto usage' }
            ]
        };

        const patterns = cryptoPatterns[platform] || [];
        patterns.forEach(({ pattern, name }) => {
            if (pattern.test(contentStr)) {
                analysis.crypto_usage.push(name);
            }
        });

        const storagePatterns = {
            android: ['SharedPreferences', 'getSharedPreferences', 'MODE_WORLD_READABLE', 'MODE_WORLD_WRITABLE'],
            ios: ['UserDefaults', 'NSFileManager', 'Keychain']
        };

        const storage = storagePatterns[platform] || [];
        storage.forEach(term => {
            if (contentStr.includes(term)) {
                analysis.storage_usage.push(term);
            }
        });

        const networkTerms = ['NSURLSession', 'URLSession', 'HttpURLConnection', 'OkHttp', 'Retrofit', 'Alamofire'];
        networkTerms.forEach(term => {
            if (contentStr.includes(term)) {
                analysis.network_usage.push(term);
            }
        });

        const authTerms = ['BiometricPrompt', 'LAContext', 'LocalAuthentication', 'AuthenticationManager'];
        authTerms.forEach(term => {
            if (contentStr.includes(term)) {
                analysis.authentication.push(term);
            }
        });

        return analysis;
    }

    analyzeNetwork(content, platform) {
        const analysis = {
            endpoints: [],
            protocols: [],
            security_headers: [],
            issues: []
        };

        const contentStr = typeof content === 'string' ? content : JSON.stringify(content);

        const protocolTerms = ['http://', 'https://', 'wss://', 'ws://'];
        protocolTerms.forEach(term => {
            const regex = new RegExp(term.replace('://', '://[a-zA-Z0-9.-]+'), 'gi');
            const matches = contentStr.match(regex);
            if (matches) {
                analysis.endpoints.push(...new Set(matches));
            }
        });

        if (contentStr.includes('https://') || contentStr.includes('https:')) {
            analysis.protocols.push('HTTPS detected');
        }
        if (contentStr.includes('http://') || contentStr.includes('http:')) {
            analysis.issues.push('Insecure HTTP usage found');
        }
        if (contentStr.includes('NSAllowsArbitraryLoads')) {
            analysis.issues.push('ATS disabled or has exceptions');
        }
        if (contentStr.includes('setJavaScriptEnabled')) {
            analysis.issues.push('JavaScript enabled in WebView');
        }

        return analysis;
    }

    generateSummary(findings) {
        const summary = {
            critical: findings.filter(f => f.severity === 'critical').length,
            high: findings.filter(f => f.severity === 'high').length,
            medium: findings.filter(f => f.severity === 'medium').length,
            low: findings.filter(f => f.severity === 'low').length,
            total: findings.length
        };

        summary.risk_level = summary.critical > 0 ? 'CRITICAL' :
                            summary.high > 2 ? 'HIGH' :
                            summary.high > 0 ? 'MEDIUM' : 'LOW';

        return summary;
    }

    generateRecommendations(findings, platform) {
        const recommendations = [];

        const criticalFindings = findings.filter(f => f.severity === 'critical');
        if (criticalFindings.length > 0) {
            recommendations.push({
                priority: 'CRITICAL',
                action: 'Address critical vulnerabilities immediately',
                items: criticalFindings.map(f => f.remediation)
            });
        }

        const categories = {};
        findings.forEach(f => {
            if (!categories[f.category]) {
                categories[f.category] = [];
            }
            categories[f.category].push(f);
        });

        Object.entries(categories).forEach(([category, vulns]) => {
            recommendations.push({
                priority: 'CATEGORY',
                action: `${category} Security Review`,
                items: vulns.map(v => `- ${v.title}: ${v.remediation}`)
            });
        });

        recommendations.push({
            priority: 'GENERAL',
            action: 'Security Best Practices',
            items: [
                'Enable ProGuard/R8 code obfuscation',
                'Implement proper error handling without exposing stack traces',
                'Use end-to-end encryption for sensitive communications',
                'Implement proper session management',
                'Regular security audits and penetration testing',
                'Keep all dependencies up to date',
                'Follow OWASP MASVS guidelines'
            ]
        });

        return recommendations;
    }

    getPatterns(platform) {
        return MOBILE_PATTERNS[platform] || [];
    }

    getTools(platform) {
        return this.tools[platform] || [];
    }
}

module.exports = new MobileAppScanner();
