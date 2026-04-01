/**
 * LLM/AI Security Scanner Module
 * Detects vulnerabilities in AI/LLM applications and prompt injection attacks
 */

const axios = require('axios');
const { sanitizeInput } = require('../../utils/security');

class LLMSecurityScanner {
    constructor() {
        this.attackCategories = {
            prompt_injection: 'Prompt Injection',
            data_extraction: 'Data Extraction',
            hallucination: 'Hallucination Risk',
            model_manipulation: 'Model Manipulation',
            denial_of_service: 'Denial of Service',
            sensitive_disclosure: 'Sensitive Information Disclosure'
        };

        this.patterns = this.initializePatterns();
    }

    initializePatterns() {
        return {
            prompt_injection: [
                {
                    id: 'LLM-PJ-001',
                    title: 'Direct Prompt Injection',
                    description: 'User input directly concatenated with system prompt without sanitization',
                    severity: 'critical',
                    check: async (input) => {
                        if (!input) return false;
                        const injectionPatterns = [
                            /ignore (previous|above|all) (instructions|prompts?|rules)/i,
                            /you (are|re) now (?:a |an )?/i,
                            /forget (everything|all previous)/i,
                            /system prompt/i,
                            /\\[INST\\]|\\[\\/INST\\]/,
                            /<\|system\|>|<\|user\|>|<\|assistant\|>/,
                            /\}?\s*->?\s*assistant\s*:/i,
                            /\}?\s*->?\s*user\s*:/i,
                            /new (?:system )?instruction/i,
                            /\#\s*system/i
                        ];
                        return injectionPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-PJ-002',
                    title: 'Indirect Prompt Injection via URL',
                    description: 'URL content may contain hidden prompt injection',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const urlPattern = /https?:\/\/[^\s]+/;
                        const urls = input.match(urlPattern) || [];
                        return urls.length > 0;
                    }
                },
                {
                    id: 'LLM-PJ-003',
                    title: 'Context Window Overflow Attempt',
                    description: 'Input designed to overflow context window',
                    severity: 'medium',
                    check: async (input) => {
                        if (!input) return false;
                        return input.length > 10000 || 
                               (input.match(/\n/g) || []).length > 500;
                    }
                },
                {
                    id: 'LLM-PJ-004',
                    title: 'Delimiter Injection',
                    description: 'Attempt to use special delimiters to escape context',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const delimiters = [
                            /```[\s\S]*?```/,
                            /<xml>[\s\S]*?<\/xml>/i,
                            /{{[\s\S]*?}}/,
                            /\[DOC\]|\[\/DOC\]/i,
                            /<pii>|<\/pii>/i
                        ];
                        return delimiters.some(p => p.test(input));
                    }
                }
            ],
            data_extraction: [
                {
                    id: 'LLM-DE-001',
                    title: 'Training Data Extraction Attempt',
                    description: 'Attempts to extract information from model training data',
                    severity: 'medium',
                    check: async (input) => {
                        if (!input) return false;
                        const extractPatterns = [
                            /repeat (the |the )?word/i,
                            /what (is|was) your (?:system )?prompt/i,
                            /tell me (?:about|how to extract).*training/i,
                            /remember (?:my|this) (?:name|instruction)/i,
                            /output (?:all |your )?(?:system|original) prompt/i
                        ];
                        return extractPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-DE-002',
                    title: 'PII Extraction Pattern',
                    description: 'Attempt to extract personally identifiable information',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const piiPatterns = [
                            /extract.*email/i,
                            /find.*phone.*number/i,
                            /show me.*SSN/i,
                            /list.*names.*addresses/i,
                            /what is.*social security/i
                        ];
                        return piiPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-DE-003',
                    title: 'Database Schema Extraction',
                    description: 'Attempt to extract database structure information',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const dbPatterns = [
                            /show.*(table|schema|database)/i,
                            /list.*column.*from/i,
                            /what (tables?|columns|fields)/i,
                            /describe.*table/i
                        ];
                        return dbPatterns.some(p => p.test(input));
                    }
                }
            ],
            hallucination: [
                {
                    id: 'LLM-HA-001',
                    title: 'Unverifiable Claim Pattern',
                    description: 'Prompt may cause model to generate unverified claims',
                    severity: 'low',
                    check: async (input) => {
                        if (!input) return false;
                        return /prove that|verify that|show that/i.test(input);
                    }
                },
                {
                    id: 'LLM-HA-002',
                    title: 'Medical/Financial Advice Request',
                    description: 'Request for medical or financial advice may lead to harmful hallucinations',
                    severity: 'medium',
                    check: async (input) => {
                        if (!input) return false;
                        const sensitivePatterns = [
                            /should i (take|buy|invest)/i,
                            /is it safe to (take|use|do)/i,
                            /what dose of/i,
                            /medical|health.*advice/i,
                            /financial.*advice|investment.*tip/i
                        ];
                        return sensitivePatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-HA-003',
                    title: 'Future Event Prediction',
                    description: 'Request for stock/election/weather predictions',
                    severity: 'medium',
                    check: async (input) => {
                        if (!input) return false;
                        const futurePatterns = [
                            /will.*stock/i,
                            /predict.*election/i,
                            /what will.*be.*price/i,
                            /forecast.*market/i
                        ];
                        return futurePatterns.some(p => p.test(input));
                    }
                }
            ],
            model_manipulation: [
                {
                    id: 'LLM-MM-001',
                    title: 'Jailbreak Attempt',
                    description: 'Attempt to bypass safety guardrails',
                    severity: 'critical',
                    check: async (input) => {
                        if (!input) return false;
                        const jailbreakPatterns = [
                            /DAN\s*(do|have|anything)/i,
                            /pretend (to be|you are)/i,
                            /bypass.*(safety|filter|restriction)/i,
                            /developer mode/i,
                            /roleplay.*without.*(rules|limits)/i,
                            /new.*persona/i
                        ];
                        return jailbreakPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-MM-002',
                    title: 'Refusal Suppression',
                    description: 'Attempt to prevent model from refusing harmful requests',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const suppressionPatterns = [
                            /you (can|will) (always |never )?(refuse|help|comply)/i,
                            /don'?t say (?:you |i )?can'?t/i,
                            /ignore.*(ethics|safety|policy)/i,
                            /no (?:need to |just )?(refuse|warning|disclaimer)/i
                        ];
                        return suppressionPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-MM-003',
                    title: 'Token Smuggling',
                    description: 'Attempt to hide malicious intent using encoding',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const encodingPatterns = [
                            /base64:[A-Za-z0-9+/=]{20,}/i,
                            /\\x[0-9a-f]{2}/i,
                            /\\u[0-9a-f]{4}/i,
                            /ROT13:/i
                        ];
                        return encodingPatterns.some(p => p.test(input));
                    }
                }
            ],
            denial_of_service: [
                {
                    id: 'LLM-DS-001',
                    title: 'Repeated Token Exhaustion',
                    description: 'Request designed to cause excessive token generation',
                    severity: 'medium',
                    check: async (input) => {
                        if (!input) return false;
                        const dosPatterns = [
                            /write (?:a )?(?:long|detailed|extensive).*(?:book|novel|article)/i,
                            /list (?:all |every )?/i,
                            /continue (?:writing|generating)/i
                        ];
                        return dosPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-DS-002',
                    title: 'Infinite Loop Trigger',
                    description: 'Input designed to cause model to enter infinite loop',
                    severity: 'medium',
                    check: async (input) => {
                        if (!input) return false;
                        return input.includes('{') && 
                               input.includes('}') && 
                               input.match(/\{[^{}]*\{[^{}]*\{/);
                    }
                }
            ],
            sensitive_disclosure: [
                {
                    id: 'LLM-SD-001',
                    title: 'API Key Request Pattern',
                    description: 'Request for sensitive API keys or credentials',
                    severity: 'critical',
                    check: async (input) => {
                        if (!input) return false;
                        const keyPatterns = [
                            /show (?:me |my )?(?:API |openai |github )?key/i,
                            /what.*secret/i,
                            /extract.*token/i,
                            /get.*password/i
                        ];
                        return keyPatterns.some(p => p.test(input));
                    }
                },
                {
                    id: 'LLM-SD-002',
                    title: 'Configuration Leakage Request',
                    description: 'Attempt to extract system configuration or prompt',
                    severity: 'high',
                    check: async (input) => {
                        if (!input) return false;
                        const configPatterns = [
                            /what (?:are |is )?(?:your |the )?(?:rules?|instructions?|guidelines?)/i,
                            /tell me (?:about )?(?:yourself|yourself|system)/i,
                            /(?:list|show).*(?:capabilities|abilities)/i
                        ];
                        return configPatterns.some(p => p.test(input));
                    }
                }
            ]
        };
    }

    async scanTarget(input, scanId, options = {}) {
        const results = {
            scanId,
            targetInput: input?.substring(0, 500) || 'N/A',
            scanner: 'LLM/AI Security Scanner',
            startTime: new Date().toISOString(),
            vulnerabilities: [],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            riskScore: 0,
            categories: {}
        };

        try {
            const sanitizedInput = sanitizeInput(input || '');

            for (const [category, patterns] of Object.entries(this.patterns)) {
                const categoryVulns = [];

                for (const pattern of patterns) {
                    try {
                        const isVulnerable = await pattern.check(sanitizedInput);

                        if (isVulnerable) {
                            const vulnerability = {
                                id: pattern.id,
                                category,
                                categoryName: this.attackCategories[category],
                                title: pattern.title,
                                description: pattern.description,
                                severity: pattern.severity,
                                matchFound: sanitizedInput.substring(0, 200),
                                riskLevel: this.getRiskLevel(pattern.severity),
                                remediation: this.getRemediation(pattern.id),
                                discoveredAt: new Date().toISOString()
                            };

                            categoryVulns.push(vulnerability);
                            results.vulnerabilities.push(vulnerability);
                            results.summary[pattern.severity]++;
                            results.riskScore += this.getSeverityScore(pattern.severity);
                        }
                    } catch (err) {
                        console.error(`LLM check ${pattern.id} failed:`, err.message);
                    }
                }

                if (categoryVulns.length > 0) {
                    results.categories[category] = {
                        name: this.attackCategories[category],
                        count: categoryVulns.length,
                        vulnerabilities: categoryVulns
                    };
                }
            }

            results.riskScore = Math.min(100, results.riskScore);
            results.riskLevel = this.getOverallRiskLevel(results.riskScore);
            results.endTime = new Date().toISOString();
            results.totalVulnerabilities = results.vulnerabilities.length;

        } catch (error) {
            results.error = error.message;
            results.endTime = new Date().toISOString();
        }

        return results;
    }

    getSeverityScore(severity) {
        const scores = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
        return scores[severity] || 5;
    }

    getRiskLevel(severity) {
        const levels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
        return levels[severity] || 'Unknown';
    }

    getOverallRiskLevel(score) {
        if (score >= 75) return 'Critical';
        if (score >= 50) return 'High';
        if (score >= 25) return 'Medium';
        if (score >= 10) return 'Low';
        return 'Minimal';
    }

    getRemediation(id) {
        const remediations = {
            'LLM-PJ-001': 'Use input sanitization and validation. Implement prompt injection detection. Separate system prompts from user input using delimiters.',
            'LLM-PJ-002': 'Sanitize and validate URL content before processing. Use content filters for fetched content.',
            'LLM-PJ-003': 'Implement input length limits. Use truncation strategies that preserve context integrity.',
            'LLM-PJ-004': 'Escape or filter special delimiters. Use structured input parsing with allowlists.',
            'LLM-DE-001': 'Implement output filtering. Add guardrails to prevent training data extraction.',
            'LLM-DE-002': 'Use PII detection and redaction. Never output raw PII in responses.',
            'LLM-DE-003': 'Implement query sanitization. Use parameterized queries and access controls.',
            'LLM-HA-001': 'Add uncertainty indicators to responses. Implement fact-checking for generated content.',
            'LLM-HA-002': 'Add medical/financial disclaimers. Redirect to professionals for sensitive advice.',
            'LLM-HA-003': 'Add uncertainty indicators for predictions. Clearly state limitations of predictions.',
            'LLM-MM-001': 'Implement jailbreak detection. Use safety filters and input/output monitoring.',
            'LLM-MM-002': 'Strengthen refusal mechanisms. Implement multiple layers of safety checks.',
            'LLM-MM-003': 'Decode and scan encoded content. Implement content filtering before processing.',
            'LLM-DS-001': 'Implement output length limits. Add rate limiting for generation requests.',
            'LLM-DS-002': 'Implement input parsing validation. Use structured output formats.',
            'LLM-SD-001': 'Implement key/secret detection. Never output sensitive credentials in responses.',
            'LLM-SD-002': 'Implement prompt confidentiality measures. Use externalized system prompts where possible.'
        };
        return remediations[id] || 'Implement AI security best practices and guardrails.';
    }

    validatePrompt(prompt) {
        const results = {
            safe: true,
            issues: [],
            confidence: 1.0,
            recommendations: []
        };

        for (const [category, patterns] of Object.entries(this.patterns)) {
            for (const pattern of patterns) {
                if (pattern.severity === 'critical' || pattern.severity === 'high') {
                    if (pattern.check(prompt)) {
                        results.safe = false;
                        results.issues.push({
                            type: pattern.title,
                            severity: pattern.severity,
                            category
                        });
                        results.confidence -= 0.2;
                    }
                }
            }
        }

        if (!results.safe) {
            results.recommendations.push('Review input for potential injection patterns');
            results.recommendations.push('Implement additional input sanitization');
        }

        return results;
    }

    getSummary() {
        return {
            categories: Object.entries(this.attackCategories).map(([id, name]) => ({
                id,
                name,
                patternCount: this.patterns[id]?.length || 0
            })),
            totalPatterns: Object.values(this.patterns).flat().length
        };
    }
}

module.exports = { LLMSecurityScanner };
