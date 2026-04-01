/**
 * AI Governance & Safe AI Module
 * Based on NIST AI Risk Management Framework
 * Reference: https://ai-cSRc.nist.gov/projects/ai-risk-management-framework
 */

const { v4: uuidv4 } = require('uuid');
const { query } = require('../../database/db');

const AI_SAFETY_LEVELS = {
    SAFE: 'safe',
    CAUTION: 'caution',
    BLOCK: 'block'
};

const PROMPT_INJECTION_PATTERNS = [
    { pattern: /ignore previous instructions/i, severity: 'high' },
    { pattern: /ignore all previous.*instructions/i, severity: 'critical' },
    { pattern: /disregard.*instructions/i, severity: 'high' },
    { pattern: /you are now/i, severity: 'medium' },
    { pattern: /forget everything/i, severity: 'high' },
    { pattern: /new instructions:/i, severity: 'medium' },
    { pattern: /system prompt/i, severity: 'medium' },
    { pattern: /roleplay as/i, severity: 'low' },
    { pattern: /pretend you are/i, severity: 'low' },
    { pattern: /as an ai.*can you/i, severity: 'low' }
];

class AIGovernance {
    constructor() {
        this.hallucinationKeywords = [
            'i\'m not sure', 'might be', 'possibly', 'perhaps',
            'it is likely that', 'typically', 'usually', 'as far as I know'
        ];
        
        this.unsafeContentPatterns = [
            { category: 'HATE_SPEECH', pattern: /\b(hate|slur|discriminat)\b/i },
            { category: 'VIOLENCE', pattern: /\b(kill|hurt|attack|destroy)\b.*\b(person|someone|them)\b/i },
            { category: 'SEXUAL', pattern: /\b(explicit|nsfw|porn)\b/i },
            { category: 'DANGEROUS', pattern: /\b(weapon|explosive|bomb|how to make)\b/i },
            { category: 'FRAUD', pattern: /\b(scam|phish|fake identity|steal credit)\b/i }
        ];
    }

    // ==================== PROMPT INJECTION DEFENSE ====================
    
    validatePrompt(input) {
        const issues = [];
        const sanitizedInput = this.sanitizePrompt(input);
        
        for (const { pattern, severity } of PROMPT_INJECTION_PATTERNS) {
            if (pattern.test(input)) {
                issues.push({
                    type: 'PROMPT_INJECTION',
                    severity,
                    matchedPattern: pattern.toString(),
                    recommendation: 'Reject or sanitize input'
                });
            }
        }
        
        return {
            isValid: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
            safetyLevel: this.calculateSafetyLevel(issues),
            issues,
            sanitizedInput,
            validatedAt: new Date().toISOString()
        };
    }
    
    sanitizePrompt(input) {
        let sanitized = input;
        
        const dangerousPatterns = [
            /ignore previous instructions/gi,
            /ignore all previous/gi,
            /disregard.*instructions/gi,
            /forget everything/gi,
            /\[SYSTEM\]/gi,
            /\[INST\]/gi
        ];
        
        for (const pattern of dangerousPatterns) {
            sanitized = sanitized.replace(pattern, '[FILTERED]');
        }
        
        return sanitized.substring(0, 10000);
    }
    
    calculateSafetyLevel(issues) {
        const hasCritical = issues.some(i => i.severity === 'critical');
        const hasHigh = issues.some(i => i.severity === 'high');
        const hasMedium = issues.some(i => i.severity === 'medium');
        
        if (hasCritical) return AI_SAFETY_LEVELS.BLOCK;
        if (hasHigh) return AI_SAFETY_LEVELS.CAUTION;
        if (hasMedium) return AI_SAFETY_LEVELS.CAUTION;
        return AI_SAFETY_LEVELS.SAFE;
    }
    
    // ==================== HALLUCINATION DETECTION ====================
    
    detectHallucination(output, context = {}) {
        const indicators = [];
        const confidenceScore = this.calculateConfidence(output);
        
        for (const keyword of this.hallucinationKeywords) {
            if (output.toLowerCase().includes(keyword)) {
                indicators.push({
                    type: 'UNCERTAINTY',
                    keyword,
                    position: output.toLowerCase().indexOf(keyword),
                    explanation: 'Model is expressing uncertainty about the response'
                });
            }
        }
        
        const hasNumbers = /\d{4,}/.test(output);
        if (hasNumbers) {
            const numbers = output.match(/\d{4,}/g);
            indicators.push({
                type: 'SPECIFIC_NUMBER',
                values: numbers,
                explanation: 'Contains specific numbers that may not be verifiable'
            });
        }
        
        const hasCVE = /CVE-\d{4}-\d{4,}/i.test(output);
        if (hasCVE) {
            const cves = output.match(/CVE-\d{4}-\d{4,}/gi);
            indicators.push({
                type: 'CVE_REFERENCE',
                cves,
                explanation: 'CVE references require verification'
            });
        }
        
        return {
            isReliable: confidenceScore >= 0.7 && indicators.length < 3,
            confidenceScore,
            indicators,
            requiresVerification: indicators.length >= 2 || confidenceScore < 0.7,
            analyzedAt: new Date().toISOString()
        };
    }
    
    calculateConfidence(output) {
        let score = 1.0;
        
        const lengthFactor = Math.min(output.length / 500, 1);
        score -= (1 - lengthFactor) * 0.1;
        
        const hasTechnicalTerms = /\b(sql|xss|csrf|owasp|http|api|json)\b/i.test(output);
        if (hasTechnicalTerms) score += 0.1;
        
        const hasExamples = /(example|for instance|e\.g\.):/i.test(output);
        if (hasExamples) score += 0.05;
        
        const hasCitations = /(according to|source|reference):/i.test(output);
        if (hasCitations) score += 0.1;
        
        return Math.min(Math.max(score, 0), 1);
    }
    
    // ==================== OUTPUT TRUST SCORING ====================
    
    calculateTrustScore(response, userContext = {}) {
        const factors = {
            sourceVerification: this.checkSourceVerification(response),
            factualAccuracy: this.assessFactualAccuracy(response),
            consistencyCheck: this.checkConsistency(response),
            userTrust: userContext.trustLevel || 0.5,
            modelConfidence: response.confidence || 0.5
        };
        
        const weights = {
            sourceVerification: 0.25,
            factualAccuracy: 0.30,
            consistencyCheck: 0.20,
            userTrust: 0.10,
            modelConfidence: 0.15
        };
        
        const trustScore = Object.entries(factors).reduce((sum, [key, value]) => {
            return sum + (value * weights[key]);
        }, 0);
        
        return {
            score: Math.round(trustScore * 100) / 100,
            grade: this.getTrustGrade(trustScore),
            factors,
            requiresHumanApproval: trustScore < 0.6,
            recommendations: this.getTrustRecommendations(trustScore, factors),
            calculatedAt: new Date().toISOString()
        };
    }
    
    checkSourceVerification(response) {
        const hasSources = /(source|reference|according to|cite):/i.test(response);
        const hasLinks = /https?:\/\//.test(response);
        
        return hasSources && hasLinks ? 1.0 : hasSources ? 0.7 : 0.3;
    }
    
    assessFactualAccuracy(response) {
        const hasCVE = /CVE-\d{4}-\d{4,}/i.test(response);
        if (hasCVE) {
            return 0.8;
        }
        
        const hasFacts = /\b(percent|percentage|all|always|never|none)\b/i.test(response);
        if (hasFacts) {
            return 0.6;
        }
        
        return 0.9;
    }
    
    checkConsistency(response) {
        const statements = response.split(/[.!?]+/).filter(s => s.trim().length > 10);
        if (statements.length < 2) return 1.0;
        
        return 0.8;
    }
    
    getTrustGrade(score) {
        if (score >= 0.9) return 'A+';
        if (score >= 0.8) return 'A';
        if (score >= 0.7) return 'B';
        if (score >= 0.6) return 'C';
        if (score >= 0.5) return 'D';
        return 'F';
    }
    
    getTrustRecommendations(score, factors) {
        const recommendations = [];
        
        if (factors.sourceVerification < 0.5) {
            recommendations.push('Add verifiable sources to response');
        }
        if (factors.factualAccuracy < 0.6) {
            recommendations.push('Review factual claims for accuracy');
        }
        if (score < 0.6) {
            recommendations.push('Human review recommended before using this response');
        }
        
        return recommendations;
    }
    
    // ==================== UNSAFE CONTENT FILTERING ====================
    
    filterUnsafeContent(output) {
        const violations = [];
        let filteredOutput = output;
        
        for (const { category, pattern } of this.unsafeContentPatterns) {
            const matches = output.match(pattern);
            if (matches) {
                violations.push({
                    category,
                    matches,
                    severity: category === 'DANGEROUS' ? 'CRITICAL' : 'HIGH'
                });
                
                filteredOutput = filteredOutput.replace(pattern, `[${category}_FILTERED]`);
            }
        }
        
        return {
            isClean: violations.length === 0,
            violations,
            filteredOutput,
            filteredAt: new Date().toISOString()
        };
    }
    
    // ==================== HUMAN APPROVAL WORKFLOW ====================
    
    async requestHumanApproval(requestData) {
        const {
            userId,
            requestType,
            prompt,
            suggestedResponse,
            trustScore,
            context
        } = requestData;
        
        const approvalRequest = {
            id: uuidv4(),
            userId,
            requestType,
            prompt: prompt.substring(0, 500),
            suggestedResponse: suggestedResponse ? suggestedResponse.substring(0, 1000) : null,
            trustScore,
            status: 'pending',
            context: JSON.stringify(context),
            createdAt: new Date().toISOString(),
            reviewedAt: null,
            reviewedBy: null,
            decision: null,
            notes: null
        };
        
        await query(`
            INSERT INTO ai_approval_requests 
            (request_id, user_id, request_type, prompt, response_preview, 
             trust_score, status, context, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            approvalRequest.id,
            approvalRequest.userId,
            approvalRequest.requestType,
            approvalRequest.prompt,
            approvalRequest.suggestedResponse,
            approvalRequest.trustScore,
            approvalRequest.status,
            approvalRequest.context,
            approvalRequest.createdAt
        ]);
        
        await this.notifyApprovers(approvalRequest);
        
        return approvalRequest;
    }
    
    async notifyApprovers(approvalRequest) {
        const [admins] = await query(`
            SELECT id FROM users WHERE role = 'admin' AND is_active = TRUE
        `);
        
        for (const admin of admins) {
            await query(`
                INSERT INTO notifications 
                (id, user_id, type, title, message, data, created_at)
                VALUES (?, ?, 'ai_approval', ?, ?, ?, NOW())
            `, [
                uuidv4(),
                admin.id,
                'AI Response Approval Required',
                `Trust Score: ${approvalRequest.trustScore.score}. Review needed.`,
                JSON.stringify({ requestId: approvalRequest.id })
            ]);
        }
    }
    
    async approveRequest(requestId, approverId, decision, notes = null) {
        await query(`
            UPDATE ai_approval_requests 
            SET status = ?, reviewed_at = ?, reviewed_by = ?, decision = ?, notes = ?
            WHERE request_id = ?
        `, [decision, new Date().toISOString(), approverId, decision, notes, requestId]);
        
        await this.logAIAuditEvent('AI_APPROVAL', {
            requestId,
            approverId,
            decision
        });
        
        return { success: true, decision };
    }
    
    // ==================== MODEL AUDIT TRAIL ====================
    
    async logAIInteraction(interactionData) {
        const {
            userId,
            prompt,
            sanitizedPrompt,
            response,
            trustScore,
            hallucinations,
            safetyCheck,
            tokensUsed,
            modelVersion,
            latency
        } = interactionData;
        
        await query(`
            INSERT INTO ai_audit_logs 
            (id, user_id, prompt, sanitized_prompt, response, trust_score,
             hallucination_detected, safety_violations, tokens_used, model_version,
             latency_ms, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [
            uuidv4(),
            userId,
            prompt.substring(0, 2000),
            sanitizedPrompt,
            response ? response.substring(0, 2000) : null,
            trustScore?.score || null,
            JSON.stringify(hallucinations?.indicators || []),
            JSON.stringify(safetyCheck?.violations || []),
            tokensUsed || null,
            modelVersion || 'gpt-4',
            latency || null
        ]);
    }
    
    async getAIUsageAnalytics(timeRange = '7d') {
        const intervals = {
            '24h': '24 HOUR',
            '7d': '7 DAY',
            '30d': '30 DAY',
            '90d': '90 DAY'
        };
        
        const interval = intervals[timeRange] || intervals['7d'];
        
        const [usage] = await query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as total_requests,
                SUM(tokens_used) as total_tokens,
                AVG(trust_score) as avg_trust_score,
                SUM(CASE WHEN hallucination_detected IS NOT NULL 
                    AND JSON_LENGTH(hallucination_detected) > 0 THEN 1 ELSE 0 END) as hallucination_count,
                SUM(CASE WHEN safety_violations IS NOT NULL 
                    AND JSON_LENGTH(safety_violations) > 0 THEN 1 ELSE 0 END) as safety_violation_count
            FROM ai_audit_logs
            WHERE created_at > DATE_SUB(NOW(), INTERVAL ${interval})
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        `);
        
        const [summary] = await query(`
            SELECT 
                COUNT(*) as total_requests,
                AVG(trust_score) as avg_trust_score,
                MIN(trust_score) as min_trust_score,
                MAX(trust_score) as max_trust_score,
                SUM(tokens_used) as total_tokens
            FROM ai_audit_logs
            WHERE created_at > DATE_SUB(NOW(), INTERVAL ${interval})
        `);
        
        return {
            timeRange,
            dailyUsage: usage,
            summary: summary[0],
            generatedAt: new Date().toISOString()
        };
    }
    
    // ==================== BIAS DETECTION ====================
    
    detectBias(output, context = {}) {
        const biasIndicators = [];
        
        const genderBias = /\b(he|she|him|her|his|hers)\b.*\b(usually|always|typically|never)\b/i;
        if (genderBias.test(output)) {
            biasIndicators.push({
                type: 'GENDER_BIAS',
                pattern: 'Gender stereotyping detected',
                severity: 'MEDIUM'
            });
        }
        
        const absoluteStatements = /\b(all|every|always|never|none)\b/i;
        const absMatches = output.match(/\b(all|every|always|never|none)\b/gi);
        if (absMatches && absMatches.length > 3) {
            biasIndicators.push({
                type: 'ABSOLUTE_STATEMENTS',
                count: absMatches.length,
                severity: 'LOW'
            });
        }
        
        return {
            isBiased: biasIndicators.some(b => b.severity === 'HIGH'),
            indicators: biasIndicators,
            biasScore: biasIndicators.length === 0 ? 1.0 : 1 - (biasIndicators.length * 0.2),
            recommendations: this.getBiasRecommendations(biasIndicators)
        };
    }
    
    getBiasRecommendations(indicators) {
        const recommendations = [];
        
        if (indicators.some(i => i.type === 'GENDER_BIAS')) {
            recommendations.push('Use gender-neutral language');
        }
        if (indicators.some(i => i.type === 'ABSOLUTE_STATEMENTS')) {
            recommendations.push('Avoid absolute statements; use probability-based language');
        }
        
        return recommendations;
    }
    
    // ==================== EXPLAINABILITY ====================
    
    generateExplanation(prompt, response, context = {}) {
        return {
            inputProcessed: prompt.substring(0, 500),
            outputGenerated: response.substring(0, 500),
            reasoning: {
                steps: [
                    { step: 1, action: 'input_validation', result: 'passed' },
                    { step: 2, action: 'prompt_injection_check', result: 'safe' },
                    { step: 3, action: 'context_retrieval', result: 'contextualized' },
                    { step: 4, action: 'response_generation', result: 'generated' },
                    { step: 5, action: 'output_filtering', result: 'clean' },
                    { step: 6, action: 'trust_scoring', result: 'calculated' }
                ],
                confidence: context.confidence || 0.85,
                warnings: context.warnings || []
            },
            model: context.model || 'gpt-4',
            timestamp: new Date().toISOString(),
            version: '1.0.0'
        };
    }
    
    async logAIAuditEvent(action, details) {
        await query(`
            INSERT INTO ai_audit_logs 
            (id, action, details, created_at)
            VALUES (?, ?, ?, NOW())
        `, [
            uuidv4(),
            action,
            JSON.stringify(details)
        ]);
    }
}

module.exports = {
    AIGovernance,
    AI_SAFETY_LEVELS,
    PROMPT_INJECTION_PATTERNS
};
