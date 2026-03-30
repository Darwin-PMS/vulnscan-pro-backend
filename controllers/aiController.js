const aiService = require('../services/aiService');

const aiController = {
    // General chat with AI assistant
    async chat(req, res) {
        try {
            const { message, context } = req.body;

            if (!message) {
                return res.status(400).json({ error: 'Message is required' });
            }

            const result = await aiService.chat(message, context);
            res.json(result);
        } catch (error) {
            console.error('Chat error:', error);
            res.status(500).json({
                error: 'AI service error',
                success: false
            });
        }
    },

    // Analyze a specific vulnerability
    async analyzeVulnerability(req, res) {
        try {
            const { vulnerabilityData } = req.body;

            if (!vulnerabilityData) {
                return res.status(400).json({ error: 'Vulnerability data is required' });
            }

            const result = await aiService.analyzeVulnerability(vulnerabilityData);
            res.json(result);
        } catch (error) {
            console.error('Vulnerability analysis error:', error);
            res.status(500).json({
                error: 'Analysis failed',
                success: false
            });
        }
    },

    // Generate report summary
    async generateReportSummary(req, res) {
        try {
            const { scanResults } = req.body;

            if (!scanResults) {
                return res.status(400).json({ error: 'Scan results are required' });
            }

            const result = await aiService.generateReportSummary(scanResults);
            res.json(result);
        } catch (error) {
            console.error('Report summary error:', error);
            res.status(500).json({
                error: 'Summary generation failed',
                success: false
            });
        }
    },

    // Get remediation suggestions
    async suggestRemediation(req, res) {
        try {
            const { vulnerabilityType, severity } = req.body;

            if (!vulnerabilityType || !severity) {
                return res.status(400).json({ error: 'Vulnerability type and severity are required' });
            }

            const result = await aiService.suggestRemediation(vulnerabilityType, severity);
            res.json(result);
        } catch (error) {
            console.error('Remediation suggestion error:', error);
            res.status(500).json({
                error: 'Suggestion failed',
                success: false
            });
        }
    },

    // Explain a CVE
    async explainCVE(req, res) {
        try {
            const { cveId } = req.params;

            if (!cveId) {
                return res.status(400).json({ error: 'CVE ID is required' });
            }

            const result = await aiService.explainCVE(cveId);
            res.json(result);
        } catch (error) {
            console.error('CVE explanation error:', error);
            res.status(500).json({
                error: 'CVE explanation failed',
                success: false
            });
        }
    },

    // Get quick security tips
    async getSecurityTips(req, res) {
        try {
            const tips = [
                {
                    category: 'Password Security',
                    tip: 'Use passphrases instead of passwords. A 4-word passphrase is more secure and easier to remember than a complex 8-character password.',
                    priority: 'high'
                },
                {
                    category: 'Network Security',
                    tip: 'Always use VPN when connecting to public WiFi. Public networks are often monitored by attackers.',
                    priority: 'high'
                },
                {
                    category: 'Web Security',
                    tip: 'Enable Multi-Factor Authentication (MFA) on all critical accounts. It prevents 99.9% of automated attacks.',
                    priority: 'high'
                },
                {
                    category: 'Email Security',
                    tip: 'Be cautious of phishing emails. Check sender addresses and never click suspicious links.',
                    priority: 'medium'
                },
                {
                    category: 'Updates',
                    tip: 'Keep software updated. Most attacks exploit known vulnerabilities that have already been patched.',
                    priority: 'high'
                },
                {
                    category: 'Backups',
                    tip: 'Follow the 3-2-1 backup rule: 3 copies, 2 different media, 1 offsite.',
                    priority: 'high'
                },
                {
                    category: 'Social Engineering',
                    tip: 'Verify unusual requests through a different channel. Attackers often impersonate colleagues or authority figures.',
                    priority: 'medium'
                },
                {
                    category: 'Mobile Security',
                    tip: 'Review app permissions regularly. Many apps request unnecessary access to sensitive data.',
                    priority: 'medium'
                }
            ];

            // Return random tip
            const randomTip = tips[Math.floor(Math.random() * tips.length)];

            res.json({
                success: true,
                tip: randomTip,
                allTips: tips
            });
        } catch (error) {
            console.error('Security tips error:', error);
            res.status(500).json({
                error: 'Failed to get tips',
                success: false
            });
        }
    }
};

module.exports = aiController;
