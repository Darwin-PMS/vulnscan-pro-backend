/**
 * Queue-Based Scan Engine
 * Bull queue with Redis for async scan processing
 * Supports multiple scanner types and worker scaling
 */

const Queue = require('bull');
const { v4: uuidv4 } = require('uuid');

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

class ScanQueueEngine {
    constructor() {
        this.queues = {
            dast: new Queue('vulnscan-dast', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 3,
                    backoff: { type: 'exponential', delay: 2000 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            sast: new Queue('vulnscan-sast', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 3,
                    backoff: { type: 'exponential', delay: 2000 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            sca: new Queue('vulnscan-sca', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 3,
                    backoff: { type: 'exponential', delay: 2000 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            api: new Queue('vulnscan-api', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 2,
                    backoff: { type: 'exponential', delay: 1000 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            cloud: new Queue('vulnscan-cloud', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 2,
                    backoff: { type: 'linear', delay: 1000 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            container: new Queue('vulnscan-container', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 2,
                    backoff: { type: 'linear', delay: 1000 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            secret: new Queue('vulnscan-secret', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 2,
                    backoff: { type: 'linear', delay: 500 },
                    removeOnComplete: 100,
                    removeOnFail: 500
                }
            }),
            malware: new Queue('vulnscan-malware', REDIS_URL, {
                defaultJobOptions: {
                    attempts: 1,
                    removeOnComplete: 50,
                    removeOnFail: 200
                }
            })
        };
        
        this.scanProcessors = new Map();
        this.initializeProcessors();
    }

    initializeProcessors() {
        for (const [type, queue] of Object.entries(this.queues)) {
            queue.process(async (job) => {
                console.log(`Processing ${type} scan job ${job.id}`);
                return await this.processScanJob(type, job.data);
            });

            queue.on('completed', (job, result) => {
                console.log(`Job ${job.id} completed successfully`);
                this.handleJobCompletion(type, result);
            });

            queue.on('failed', (job, err) => {
                console.error(`Job ${job.id} failed:`, err.message);
                this.handleJobFailure(type, job, err);
            });

            queue.on('progress', (job, progress) => {
                this.updateJobProgress(type, job.id, progress);
            });
        }
    }

    async processScanJob(type, data) {
        const { scanId, target, options, modules } = data;
        
        const scanner = this.getScannerForType(type);
        
        if (!scanner) {
            throw new Error(`No scanner available for type: ${type}`);
        }

        const result = await scanner.scanTarget(target, scanId, options);
        
        return {
            scanId,
            type,
            target,
            status: 'completed',
            result,
            completedAt: new Date().toISOString()
        };
    }

    getScannerForType(type) {
        const scanners = {
            dast: () => require('../scanner/owaspScanner'),
            sast: () => require('../scanner/owaspScanner'),
            sca: () => require('../scanner/scaScanner'),
            api: () => require('../scanner/apiSecurityScanner'),
            cloud: () => require('../scanner/cloudSecurityScanner'),
            container: () => require('../scanner/containerSecurityScanner'),
            secret: () => require('../scanner/secretScanner'),
            malware: () => require('../scanner/malwareScanner')
        };

        const factory = scanners[type];
        if (factory) {
            const ScannerClass = factory();
            return new ScannerClass();
        }

        return null;
    }

    async enqueueScan(type, data, priority = 'normal') {
        const queue = this.queues[type];
        
        if (!queue) {
            throw new Error(`Invalid scan type: ${type}`);
        }

        const jobOptions = {
            priority: priority === 'high' ? 1 : priority === 'low' ? 3 : 2,
            timeout: this.getTimeoutForType(type)
        };

        const job = await queue.add(data, jobOptions);

        return {
            jobId: job.id,
            scanId: data.scanId,
            type,
            status: 'queued',
            position: await job.getPosition()
        };
    }

    async enqueueMultiScan(scanId, target, modules, options = {}) {
        const jobs = [];
        
        for (const module of modules) {
            const job = await this.enqueueScan(module, {
                scanId: `${scanId}_${module}`,
                target,
                options,
                parentScanId: scanId
            });
            
            jobs.push({ module, jobId: job.jobId });
        }

        return {
            scanId,
            totalModules: modules.length,
            jobs
        };
    }

    getTimeoutForType(type) {
        const timeouts = {
            dast: 30 * 60 * 1000,
            sast: 20 * 60 * 1000,
            sca: 10 * 60 * 1000,
            api: 15 * 60 * 1000,
            cloud: 15 * 60 * 1000,
            container: 10 * 60 * 1000,
            secret: 5 * 60 * 1000,
            malware: 10 * 60 * 1000
        };

        return timeouts[type] || 10 * 60 * 1000;
    }

    async getJobStatus(jobId, type) {
        const queue = this.queues[type];
        
        if (!queue) {
            return { error: 'Invalid type' };
        }

        const job = await queue.getJob(jobId);
        
        if (!job) {
            return { error: 'Job not found' };
        }

        return {
            id: job.id,
            status: job.status,
            progress: job.progress(),
            data: job.data,
            result: job.returnvalue,
            failedReason: job.failedReason,
            attempts: job.attemptsMade,
            created: job.timestamp,
            processed: job.processedOn,
            finished: job.finishedOn
        };
    }

    async getQueueStats(type) {
        const queue = this.queues[type];
        
        if (!queue) {
            return { error: 'Invalid type' };
        }

        const [waiting, active, completed, failed, delayed] = await Promise.all([
            queue.getWaitingCount(),
            queue.getActiveCount(),
            queue.getCompletedCount(),
            queue.getFailedCount(),
            queue.getDelayedCount()
        ]);

        return {
            waiting,
            active,
            completed,
            failed,
            delayed,
            total: waiting + active + delayed
        };
    }

    async getAllQueueStats() {
        const stats = {};
        
        for (const type of Object.keys(this.queues)) {
            stats[type] = await this.getQueueStats(type);
        }

        return stats;
    }

    async cancelJob(jobId, type) {
        const queue = this.queues[type];
        
        if (!queue) {
            throw new Error(`Invalid scan type: ${type}`);
        }

        const job = await queue.getJob(jobId);
        
        if (!job) {
            throw new Error('Job not found');
        }

        await job.remove();
        
        return { cancelled: true, jobId };
    }

    async pauseQueue(type) {
        const queue = this.queues[type];
        
        if (!queue) {
            throw new Error(`Invalid scan type: ${type}`);
        }

        await queue.pause();
        
        return { paused: true, type };
    }

    async resumeQueue(type) {
        const queue = this.queues[type];
        
        if (!queue) {
            throw new Error(`Invalid scan type: ${type}`);
        }

        await queue.resume();
        
        return { resumed: true, type };
    }

    async clearQueue(type, status = 'completed') {
        const queue = this.queues[type];
        
        if (!queue) {
            throw new Error(`Invalid scan type: ${type}`);
        }

        let count = 0;
        
        if (status === 'completed') {
            await queue.empty();
            count = await queue.getCompletedCount();
        } else if (status === 'failed') {
            await queue.clean(0, 'failed');
            count = await queue.getFailedCount();
        }

        return { cleared: true, type, count };
    }

    handleJobCompletion(type, result) {
        console.log(`[${type}] Scan completed:`, result.scanId);
        
        if (result.parentScanId) {
            this.checkMultiScanCompletion(result.parentScanId);
        }
    }

    handleJobFailure(type, job, error) {
        console.error(`[${type}] Scan failed:`, job.data.scanId, error.message);
    }

    updateJobProgress(type, jobId, progress) {
        console.log(`[${type}] Job ${jobId} progress:`, progress);
    }

    async checkMultiScanCompletion(parentScanId) {
        console.log('Checking multi-scan completion for:', parentScanId);
    }

    async getWorkerHealth() {
        const stats = await this.getAllQueueStats();
        
        const health = {
            overall: 'healthy',
            timestamp: new Date().toISOString(),
            queues: {},
            alerts: []
        };

        for (const [type, queueStats] of Object.entries(stats)) {
            health.queues[type] = queueStats;

            if (queueStats.failed > 10) {
                health.alerts.push({
                    type: 'high_failure_rate',
                    queue: type,
                    count: queueStats.failed
                });
            }

            if (queueStats.waiting > 50) {
                health.alerts.push({
                    type: 'queue_backlog',
                    queue: type,
                    count: queueStats.waiting
                });
            }
        }

        if (health.alerts.length > 0) {
            health.overall = 'degraded';
        }

        return health;
    }
}

module.exports = { ScanQueueEngine };