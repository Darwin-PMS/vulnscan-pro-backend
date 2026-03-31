const mobileScanner = require('../services/mobileScanner');
const { v4: uuidv4 } = require('uuid');

const mobileController = {
    async scanAPK(req, res) {
        try {
            const { content, platform, app_name } = req.body;

            if (!content && !req.file) {
                return res.status(400).json({ error: 'APK/IPA content or file is required' });
            }

            const scanPlatform = platform || 'android';
            const scanContent = content || req.file?.buffer?.toString('utf-8') || '';

            const results = await mobileScanner.scanAPK(scanContent, scanPlatform);

            results.app_name = app_name || `Unknown App`;
            results.scan_id = uuidv4();

            res.json({
                success: true,
                scan_id: results.scan_id,
                platform: scanPlatform,
                app_name: results.app_name,
                scan_date: results.scan_date,
                summary: results.summary,
                findings: results.findings,
                recommendations: results.recommendations,
                analysis: {
                    manifest: results.manifest_analysis,
                    code: results.code_analysis,
                    network: results.network_analysis
                },
                tools: results.tools
            });
        } catch (error) {
            console.error('Mobile scan error:', error);
            res.status(500).json({ error: 'Mobile scan failed' });
        }
    },

    async analyzeManifest(req, res) {
        try {
            const { content, platform } = req.body;

            if (!content) {
                return res.status(400).json({ error: 'Manifest content is required' });
            }

            const scanPlatform = platform || 'android';
            const results = await mobileScanner.scanAPK(content, scanPlatform);

            res.json({
                success: true,
                platform: scanPlatform,
                manifest_analysis: results.manifest_analysis,
                exported_components: results.manifest_analysis.exported_components,
                permissions: results.manifest_analysis.permissions,
                security_flags: results.manifest_analysis.security_flags,
                issues: results.manifest_analysis.issues
            });
        } catch (error) {
            console.error('Manifest analysis error:', error);
            res.status(500).json({ error: 'Manifest analysis failed' });
        }
    },

    async analyzeCode(req, res) {
        try {
            const { content, platform } = req.body;

            if (!content) {
                return res.status(400).json({ error: 'Code content is required' });
            }

            const scanPlatform = platform || 'android';
            const results = await mobileScanner.scanAPK(content, scanPlatform);

            res.json({
                success: true,
                platform: scanPlatform,
                code_analysis: results.code_analysis,
                crypto_usage: results.code_analysis.crypto_usage,
                storage_usage: results.code_analysis.storage_usage,
                network_usage: results.code_analysis.network_usage,
                authentication: results.code_analysis.authentication,
                findings: results.findings.filter(f => 
                    f.category === 'Cryptography' || 
                    f.category === 'Data Storage' || 
                    f.category === 'Code Security'
                )
            });
        } catch (error) {
            console.error('Code analysis error:', error);
            res.status(500).json({ error: 'Code analysis failed' });
        }
    },

    async analyzeNetwork(req, res) {
        try {
            const { content, platform } = req.body;

            if (!content) {
                return res.status(400).json({ error: 'Content is required' });
            }

            const scanPlatform = platform || 'android';
            const results = await mobileScanner.scanAPK(content, scanPlatform);

            res.json({
                success: true,
                platform: scanPlatform,
                network_analysis: results.network_analysis,
                endpoints: results.network_analysis.endpoints,
                protocols: results.network_analysis.protocols,
                security_headers: results.network_analysis.security_headers,
                issues: results.network_analysis.issues,
                findings: results.findings.filter(f => f.category === 'Network Security')
            });
        } catch (error) {
            console.error('Network analysis error:', error);
            res.status(500).json({ error: 'Network analysis failed' });
        }
    },

    async getPatterns(req, res) {
        try {
            const { platform } = req.params;
            const patterns = mobileScanner.getPatterns(platform);

            res.json({
                success: true,
                platform,
                patterns,
                total: patterns.length,
                by_category: patterns.reduce((acc, p) => {
                    if (!acc[p.category]) acc[p.category] = [];
                    acc[p.category].push(p);
                    return acc;
                }, {}),
                by_severity: {
                    critical: patterns.filter(p => p.severity === 'critical').length,
                    high: patterns.filter(p => p.severity === 'high').length,
                    medium: patterns.filter(p => p.severity === 'medium').length,
                    low: patterns.filter(p => p.severity === 'low').length
                }
            });
        } catch (error) {
            console.error('Get patterns error:', error);
            res.status(500).json({ error: 'Failed to get patterns' });
        }
    },

    async getTools(req, res) {
        try {
            const { platform } = req.params;
            const tools = mobileScanner.getTools(platform);

            res.json({
                success: true,
                platform,
                tools,
                total: tools.length
            });
        } catch (error) {
            console.error('Get tools error:', error);
            res.status(500).json({ error: 'Failed to get tools' });
        }
    },

    async getSecurityGuide(req, res) {
        try {
            const { platform } = req.params;
            
            const guides = {
                android: {
                    title: 'Android Security Best Practices',
                    owasp: 'OWASP Mobile Top 10 & MASVS',
                    categories: [
                        {
                            name: 'Architecture & Design',
                            items: [
                                'Use secure architecture patterns (MVVM, Clean Architecture)',
                                'Implement proper authentication and session management',
                                'Use secure communication protocols (TLS 1.2+)',
                                'Implement proper error handling without exposing sensitive data'
                            ]
                        },
                        {
                            name: 'Data Storage',
                            items: [
                                'Use EncryptedSharedPreferences for sensitive data',
                                'Store credentials in Android Keystore',
                                'Enable SQLCipher for Room database encryption',
                                'Avoid storing sensitive data in external storage'
                            ]
                        },
                        {
                            name: 'Cryptography',
                            items: [
                                'Use AES-256 for encryption',
                                'Use Android Keystore for key management',
                                'Avoid hardcoded encryption keys',
                                'Use SecureRandom for random number generation'
                            ]
                        },
                        {
                            name: 'Network Security',
                            items: [
                                'Implement certificate pinning',
                                'Use Network Security Config',
                                'Disable cleartext traffic',
                                'Validate all server certificates'
                            ]
                        },
                        {
                            name: 'Platform Security',
                            items: [
                                'Minimize exported components',
                                'Implement proper permission checks',
                                'Validate all Intent extras',
                                'Use explicit Intents for sensitive operations'
                            ]
                        },
                        {
                            name: 'Code Quality',
                            items: [
                                'Use ProGuard/R8 for code obfuscation',
                                'Remove debug flags in release builds',
                                'Implement proper input validation',
                                'Avoid unsafe native code'
                            ]
                        }
                    ],
                    references: [
                        'OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/',
                        'MASVS: https://mas.owasp.org/',
                        'Android Security: https://developer.android.com/topic/security/'
                    ]
                },
                ios: {
                    title: 'iOS Security Best Practices',
                    owasp: 'OWASP Mobile Top 10 & MASVS',
                    categories: [
                        {
                            name: 'Architecture & Design',
                            items: [
                                'Use MVVM or VIPER architecture',
                                'Implement secure authentication flow',
                                'Use proper session management',
                                'Follow Apple security guidelines'
                            ]
                        },
                        {
                            name: 'Data Storage',
                            items: [
                                'Use Keychain for sensitive data',
                                'Enable iOS Data Protection',
                                'Use NSFileProtectionComplete',
                                'Avoid UserDefaults for sensitive data'
                            ]
                        },
                        {
                            name: 'Cryptography',
                            items: [
                                'Use CryptoKit for iOS 13+',
                                'Store keys in Secure Enclave',
                                'Use SecRandomCopyBytes for random numbers',
                                'Avoid custom cryptographic implementations'
                            ]
                        },
                        {
                            name: 'Network Security',
                            items: [
                                'Keep App Transport Security enabled',
                                'Implement certificate pinning with TrustKit',
                                'Use HTTPS exclusively',
                                'Validate server certificates properly'
                            ]
                        },
                        {
                            name: 'Platform Security',
                            items: [
                                'Use Universal Links instead of URL schemes',
                                'Implement proper URL validation',
                                'Clear sensitive data from memory',
                                'Use proper pasteboard management'
                            ]
                        },
                        {
                            name: 'Code Quality',
                            items: [
                                'Use LLVM obfuscation',
                                'Strip debug symbols',
                                'Enable compiler warnings',
                                'Use static analysis tools'
                            ]
                        }
                    ],
                    references: [
                        'OWASP Mobile Top 10: https://owasp.org/www-project-mobile-top-10/',
                        'MASVS: https://mas.owasp.org/',
                        'Apple Security: https://developer.apple.com/documentation/security/'
                    ]
                }
            };

            res.json({
                success: true,
                platform,
                guide: guides[platform] || guides.android
            });
        } catch (error) {
            console.error('Get security guide error:', error);
            res.status(500).json({ error: 'Failed to get security guide' });
        }
    }
};

module.exports = mobileController;
