// monitoring.js
// Comprehensive monitoring and logging system for security and performance

/**
 * Security and Performance Monitoring System
 */
class SecurityMonitor {
    constructor() {
        this.eventLog = [];
        this.performanceMetrics = new Map();
        this.securityEvents = new Map();
        this.resourceUsage = new Map();
        this.maxLogSize = 1000;
        this.alertThresholds = {
            failedLogins: 5,
            requestTimeout: 30000,
            memoryUsage: 50 * 1024 * 1024, // 50MB
            errorRate: 0.1 // 10%
        };
        
        this.initializeMonitoring();
    }

    initializeMonitoring() {
        // Start periodic monitoring
        this.monitoringInterval = setInterval(() => {
            this.collectResourceMetrics();
            this.analyzeSecurityEvents();
            this.cleanupOldLogs();
        }, 60000); // Every minute

        // Monitor unhandled errors
        if (typeof window !== 'undefined') {
            window.addEventListener('error', (event) => {
                this.logSecurityEvent('UNHANDLED_ERROR', {
                    message: event.message,
                    filename: event.filename,
                    lineno: event.lineno,
                    colno: event.colno,
                    stack: event.error?.stack
                });
            });

            window.addEventListener('unhandledrejection', (event) => {
                this.logSecurityEvent('UNHANDLED_REJECTION', {
                    reason: event.reason,
                    promise: event.promise
                });
            });
        }
    }

    /**
     * Log security events with context and metadata
     * @param {string} eventType - Type of security event
     * @param {Object} details - Event details
     * @param {string} severity - Event severity (low, medium, high, critical)
     */
    logSecurityEvent(eventType, details = {}, severity = 'medium') {
        const event = {
            id: this.generateEventId(),
            timestamp: Date.now(),
            type: eventType,
            severity: severity,
            details: details,
            userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
            url: typeof window !== 'undefined' ? window.location.href : 'unknown'
        };

        this.eventLog.push(event);
        
        // Update security event counters
        const key = `${eventType}_${severity}`;
        this.securityEvents.set(key, (this.securityEvents.get(key) || 0) + 1);

        // Check for security alerts
        this.checkSecurityAlerts(eventType, event);

        // Limit log size
        if (this.eventLog.length > this.maxLogSize) {
            this.eventLog = this.eventLog.slice(-this.maxLogSize);
        }

        console.log(`[SECURITY] ${eventType} (${severity}):`, details);
    }

    /**
     * Log performance metrics
     * @param {string} operation - Operation name
     * @param {number} duration - Duration in milliseconds
     * @param {Object} metadata - Additional metadata
     */
    logPerformance(operation, duration, metadata = {}) {
        const metric = {
            timestamp: Date.now(),
            operation: operation,
            duration: duration,
            metadata: metadata
        };

        if (!this.performanceMetrics.has(operation)) {
            this.performanceMetrics.set(operation, []);
        }

        const metrics = this.performanceMetrics.get(operation);
        metrics.push(metric);

        // Keep only recent metrics (last 100 per operation)
        if (metrics.length > 100) {
            metrics.splice(0, metrics.length - 100);
        }

        // Check for performance alerts
        if (duration > this.alertThresholds.requestTimeout) {
            this.logSecurityEvent('PERFORMANCE_SLOW', {
                operation: operation,
                duration: duration,
                threshold: this.alertThresholds.requestTimeout
            }, 'medium');
        }

        console.log(`[PERFORMANCE] ${operation}: ${duration}ms`, metadata);
    }

    /**
     * Monitor authentication attempts
     * @param {boolean} success - Whether login was successful
     * @param {string} username - Username attempted
     * @param {string} reason - Failure reason if applicable
     */
    logAuthAttempt(success, username = 'unknown', reason = null) {
        const eventType = success ? 'AUTH_SUCCESS' : 'AUTH_FAILURE';
        const severity = success ? 'low' : 'medium';
        
        this.logSecurityEvent(eventType, {
            username: username,
            success: success,
            reason: reason,
            timestamp: Date.now()
        }, severity);

        // Track failed login attempts for rate limiting
        if (!success) {
            const failureKey = `auth_failures_${username}`;
            const failures = this.securityEvents.get(failureKey) || 0;
            this.securityEvents.set(failureKey, failures + 1);

            // Alert on too many failures
            if (failures >= this.alertThresholds.failedLogins) {
                this.logSecurityEvent('AUTH_BRUTE_FORCE', {
                    username: username,
                    attempts: failures + 1
                }, 'high');
            }
        }
    }

    /**
     * Monitor network requests
     * @param {string} url - Request URL
     * @param {string} method - HTTP method
     * @param {number} status - Response status code
     * @param {number} duration - Request duration
     */
    logNetworkRequest(url, method, status, duration) {
        const isError = status >= 400;
        const eventType = isError ? 'NETWORK_ERROR' : 'NETWORK_REQUEST';
        const severity = status >= 500 ? 'high' : (isError ? 'medium' : 'low');

        this.logSecurityEvent(eventType, {
            url: url,
            method: method,
            status: status,
            duration: duration
        }, severity);

        this.logPerformance(`network_${method.toLowerCase()}`, duration, {
            url: url,
            status: status
        });
    }

    /**
     * Monitor data integrity events
     * @param {string} dataType - Type of data being verified
     * @param {boolean} valid - Whether data integrity check passed
     * @param {Object} details - Additional details
     */
    logDataIntegrity(dataType, valid, details = {}) {
        const eventType = valid ? 'DATA_INTEGRITY_OK' : 'DATA_INTEGRITY_FAIL';
        const severity = valid ? 'low' : 'high';

        this.logSecurityEvent(eventType, {
            dataType: dataType,
            valid: valid,
            ...details
        }, severity);
    }

    /**
     * Collect resource usage metrics
     */
    collectResourceMetrics() {
        try {
            // Memory usage (if available)
            if (typeof performance !== 'undefined' && performance.memory) {
                const memoryInfo = {
                    used: performance.memory.usedJSHeapSize,
                    total: performance.memory.totalJSHeapSize,
                    limit: performance.memory.jsHeapSizeLimit
                };

                this.resourceUsage.set('memory', memoryInfo);

                // Alert on high memory usage
                if (memoryInfo.used > this.alertThresholds.memoryUsage) {
                    this.logSecurityEvent('HIGH_MEMORY_USAGE', memoryInfo, 'medium');
                }
            }

            // Storage usage
            if (typeof chrome !== 'undefined' && chrome.storage) {
                chrome.storage.local.getBytesInUse(null, (bytesInUse) => {
                    this.resourceUsage.set('storage', { bytes: bytesInUse });
                });
            }

            // Connection status
            if (typeof navigator !== 'undefined' && 'connection' in navigator) {
                const connection = navigator.connection;
                this.resourceUsage.set('connection', {
                    effectiveType: connection.effectiveType,
                    downlink: connection.downlink,
                    rtt: connection.rtt
                });
            }
        } catch (error) {
            this.logSecurityEvent('MONITORING_ERROR', {
                error: error.message,
                stack: error.stack
            }, 'low');
        }
    }

    /**
     * Analyze security events for patterns
     */
    analyzeSecurityEvents() {
        const recentEvents = this.getRecentEvents(300000); // Last 5 minutes
        
        // Analyze error rates
        const totalEvents = recentEvents.length;
        const errorEvents = recentEvents.filter(e => 
            e.severity === 'high' || e.severity === 'critical'
        ).length;

        if (totalEvents > 10) {
            const errorRate = errorEvents / totalEvents;
            if (errorRate > this.alertThresholds.errorRate) {
                this.logSecurityEvent('HIGH_ERROR_RATE', {
                    errorRate: errorRate,
                    totalEvents: totalEvents,
                    errorEvents: errorEvents
                }, 'high');
            }
        }

        // Look for suspicious patterns
        this.detectSuspiciousPatterns(recentEvents);
    }

    /**
     * Detect suspicious patterns in security events
     * @param {Array} events - Recent security events
     */
    detectSuspiciousPatterns(events) {
        // Rapid succession of failed auth attempts
        const authFailures = events.filter(e => e.type === 'AUTH_FAILURE');
        if (authFailures.length >= 3) {
            const timeSpan = Math.max(...authFailures.map(e => e.timestamp)) - 
                           Math.min(...authFailures.map(e => e.timestamp));
            
            if (timeSpan < 60000) { // Within 1 minute
                this.logSecurityEvent('SUSPICIOUS_AUTH_PATTERN', {
                    failures: authFailures.length,
                    timespan: timeSpan
                }, 'high');
            }
        }

        // Multiple error types in short period
        const errorTypes = new Set(
            events.filter(e => e.severity === 'high').map(e => e.type)
        );
        
        if (errorTypes.size >= 3) {
            this.logSecurityEvent('MULTIPLE_ERROR_TYPES', {
                errorTypes: Array.from(errorTypes),
                count: errorTypes.size
            }, 'medium');
        }
    }

    /**
     * Check for security alerts based on thresholds
     * @param {string} eventType - Type of event
     * @param {Object} event - Event object
     */
    checkSecurityAlerts(eventType, event) {
        switch (eventType) {
            case 'AUTH_FAILURE':
                // Already handled in logAuthAttempt
                break;
                
            case 'NETWORK_ERROR':
                if (event.details.status >= 500) {
                    this.logSecurityEvent('SERVER_ERROR_ALERT', event.details, 'high');
                }
                break;
                
            case 'DATA_INTEGRITY_FAIL':
                this.logSecurityEvent('CRITICAL_INTEGRITY_ALERT', event.details, 'critical');
                break;
        }
    }

    /**
     * Get recent events within specified time window
     * @param {number} timeWindow - Time window in milliseconds
     * @returns {Array} Recent events
     */
    getRecentEvents(timeWindow = 300000) {
        const cutoff = Date.now() - timeWindow;
        return this.eventLog.filter(event => event.timestamp >= cutoff);
    }

    /**
     * Get performance statistics for an operation
     * @param {string} operation - Operation name
     * @returns {Object} Performance statistics
     */
    getPerformanceStats(operation) {
        const metrics = this.performanceMetrics.get(operation);
        if (!metrics || metrics.length === 0) {
            return null;
        }

        const durations = metrics.map(m => m.duration);
        durations.sort((a, b) => a - b);

        return {
            count: durations.length,
            min: durations[0],
            max: durations[durations.length - 1],
            avg: durations.reduce((a, b) => a + b, 0) / durations.length,
            median: durations[Math.floor(durations.length / 2)],
            p95: durations[Math.floor(durations.length * 0.95)]
        };
    }

    /**
     * Generate security report
     * @param {number} timeWindow - Time window for report in milliseconds
     * @returns {Object} Security report
     */
    generateSecurityReport(timeWindow = 86400000) { // 24 hours
        const recentEvents = this.getRecentEvents(timeWindow);
        
        const report = {
            timestamp: Date.now(),
            timeWindow: timeWindow,
            totalEvents: recentEvents.length,
            eventsByType: {},
            eventsBySeverity: {},
            topEvents: [],
            performanceMetrics: {},
            resourceUsage: Object.fromEntries(this.resourceUsage),
            alerts: recentEvents.filter(e => e.severity === 'high' || e.severity === 'critical')
        };

        // Group events by type and severity
        recentEvents.forEach(event => {
            report.eventsByType[event.type] = (report.eventsByType[event.type] || 0) + 1;
            report.eventsBySeverity[event.severity] = (report.eventsBySeverity[event.severity] || 0) + 1;
        });

        // Get top events
        report.topEvents = Object.entries(report.eventsByType)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .map(([type, count]) => ({ type, count }));

        // Get performance metrics
        for (const [operation, metrics] of this.performanceMetrics.entries()) {
            report.performanceMetrics[operation] = this.getPerformanceStats(operation);
        }

        return report;
    }

    /**
     * Clean up old logs and metrics
     */
    cleanupOldLogs() {
        const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days
        
        // Clean event log
        this.eventLog = this.eventLog.filter(event => event.timestamp >= cutoff);
        
        // Clean performance metrics
        for (const [operation, metrics] of this.performanceMetrics.entries()) {
            this.performanceMetrics.set(
                operation,
                metrics.filter(metric => metric.timestamp >= cutoff)
            );
        }
        
        // Clean security event counters (reset daily counters)
        const dailyCutoff = Date.now() - (24 * 60 * 60 * 1000);
        for (const [key, value] of this.securityEvents.entries()) {
            if (key.includes('auth_failures_')) {
                // Reset auth failure counters daily
                this.securityEvents.set(key, 0);
            }
        }
    }

    /**
     * Generate unique event ID
     * @returns {string} Unique event ID
     */
    generateEventId() {
        return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Export logs for analysis
     * @param {string} format - Export format ('json' or 'csv')
     * @returns {string} Exported data
     */
    exportLogs(format = 'json') {
        if (format === 'json') {
            return JSON.stringify({
                events: this.eventLog,
                performanceMetrics: Object.fromEntries(this.performanceMetrics),
                securityEvents: Object.fromEntries(this.securityEvents),
                resourceUsage: Object.fromEntries(this.resourceUsage)
            }, null, 2);
        }
        
        // CSV format for events
        if (format === 'csv') {
            const headers = ['timestamp', 'type', 'severity', 'details'];
            const rows = this.eventLog.map(event => [
                new Date(event.timestamp).toISOString(),
                event.type,
                event.severity,
                JSON.stringify(event.details)
            ]);
            
            return [headers, ...rows].map(row => row.join(',')).join('\n');
        }
        
        throw new Error('Unsupported export format');
    }

    /**
     * Cleanup monitoring resources
     */
    cleanup() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }
    }
}

// Global monitoring instance
let globalMonitor = null;

/**
 * Initialize global monitoring system
 * @returns {SecurityMonitor} Monitor instance
 */
function initializeMonitoring() {
    if (!globalMonitor) {
        globalMonitor = new SecurityMonitor();
    }
    return globalMonitor;
}

/**
 * Get global monitor instance
 * @returns {SecurityMonitor} Monitor instance
 */
function getMonitor() {
    return globalMonitor || initializeMonitoring();
}

// Performance timing wrapper
function withPerformanceLogging(operation, fn) {
    return async (...args) => {
        const start = Date.now();
        const monitor = getMonitor();
        
        try {
            const result = await fn(...args);
            const duration = Date.now() - start;
            monitor.logPerformance(operation, duration, { success: true });
            return result;
        } catch (error) {
            const duration = Date.now() - start;
            monitor.logPerformance(operation, duration, { success: false, error: error.message });
            monitor.logSecurityEvent('OPERATION_ERROR', {
                operation: operation,
                error: error.message,
                stack: error.stack
            }, 'medium');
            throw error;
        }
    };
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SecurityMonitor,
        initializeMonitoring,
        getMonitor,
        withPerformanceLogging
    };
}