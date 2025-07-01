// Sentinel API Server for Render Cloud Platform
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const crypto = require('crypto');
const multer = require('multer');
const compression = require('compression');
const winston = require('winston');
const AntiCloneSDK = require('anticlone-sdk');
const fs = require('fs').promises;
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Test database connection
pool.on('connect', () => {
    logger.info('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
    logger.error('Database connection error:', err);
});

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
}));
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// More restrictive rate limiting for fingerprint uploads
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // limit each IP to 10 uploads per hour
    message: 'Too many uploads from this IP, please try again later.'
});

// File upload configuration
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/vnd.android.package-archive', 'application/octet-stream'];
        if (allowedTypes.includes(file.mimetype) || file.originalname.endsWith('.apk') || file.originalname.endsWith('.ipa')) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only APK and IPA files are allowed.'));
        }
    }
});

// Utility functions
function hashContent(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Authentication middleware
async function authenticateRequest(req, res, next) {
    try {
        const developerId = req.headers['x-developer-id'];
        const apiKey = req.headers['x-api-key'];
        
        if (!developerId || !apiKey) {
            return res.status(401).json({
                success: false,
                error: 'Missing authentication headers'
            });
        }

        const apiKeyHash = hashContent(apiKey);
        
        const result = await pool.query(
            'SELECT id, developer_name, verification_status, is_active FROM developers WHERE developer_id = $1 AND api_key_hash = $2',
            [developerId, apiKeyHash]
        );

        if (result.rows.length === 0) {
            await logSecurityEvent('unauthorized_access', 'medium', {
                developer_id: developerId,
                endpoint: req.path,
                ip: req.ip
            });
            
            return res.status(401).json({
                success: false,
                error: 'Invalid credentials'
            });
        }

        const developer = result.rows[0];
        
        if (!developer.is_active) {
            return res.status(403).json({
                success: false,
                error: 'Developer account is inactive'
            });
        }

        if (developer.verification_status !== 'verified') {
            return res.status(403).json({
                success: false,
                error: 'Developer account is not verified'
            });
        }

        req.developer = developer;
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
}

// Log API usage
async function logApiUsage(req, res, next) {
    const startTime = Date.now();
    
    res.on('finish', async () => {
        const executionTime = Date.now() - startTime;
        
        try {
            await pool.query(
                `INSERT INTO api_usage (developer_id, endpoint, method, response_status, 
                 execution_time, ip_address, user_agent, timestamp) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [
                    req.developer?.id || null,
                    req.path,
                    req.method,
                    res.statusCode,
                    executionTime,
                    req.ip,
                    req.get('User-Agent'),
                    new Date()
                ]
            );
        } catch (error) {
            logger.error('Error logging API usage:', error);
        }
    });
    
    next();
}

// Log security events
async function logSecurityEvent(eventType, severity, eventData, fingerprintId = null, developerId = null) {
    try {
        await pool.query(
            `INSERT INTO security_events (event_type, severity, event_data, fingerprint_id, developer_id, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [eventType, severity, JSON.stringify(eventData), fingerprintId, developerId, new Date()]
        );
    } catch (error) {
        logger.error('Error logging security event:', error);
    }
}

// API Routes

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Get API documentation
app.get('/api/docs', (req, res) => {
    res.json({
        name: 'Sentinel API',
        version: '1.0.0',
        description: 'API for app fingerprint management and verification',
        endpoints: {
            'POST /api/fingerprints': 'Upload app fingerprint',
            'POST /api/fingerprints/generate': 'Generate fingerprint from APK/IPA file',
            'GET /api/fingerprints/verify': 'Verify app fingerprint',
            'GET /api/fingerprints/scan': 'Scan app for credibility',
            'POST /api/developers/register': 'Register new developer',
            'GET /api/developers/profile': 'Get developer profile'
        }
    });
});

// Upload fingerprint
app.post('/api/fingerprints', uploadLimiter, authenticateRequest, logApiUsage, async (req, res) => {
    try {
        const { fingerprint } = req.body;
        
        if (!fingerprint) {
            return res.status(400).json({
                success: false,
                error: 'Fingerprint data is required'
            });
        }

        // Validate required fields
        const requiredFields = ['appId', 'appName', 'version', 'overallHash', 'fingerprints'];
        for (const field of requiredFields) {
            if (!fingerprint[field]) {
                return res.status(400).json({
                    success: false,
                    error: `Missing required field: ${field}`
                });
            }
        }

        // Check for duplicate fingerprint
        const existingFingerprint = await pool.query(
            'SELECT id FROM app_fingerprints WHERE developer_id = $1 AND app_id = $2 AND version = $3',
            [req.developer.id, fingerprint.appId, fingerprint.version]
        );

        if (existingFingerprint.rows.length > 0) {
            return res.status(409).json({
                success: false,
                error: 'Fingerprint for this app version already exists'
            });
        }

        // Insert fingerprint
        const result = await pool.query(
            `INSERT INTO app_fingerprints 
             (developer_id, app_id, app_name, package_name, version, file_type, file_name,
              overall_hash, fingerprint_data, metadata)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id`,
            [
                req.developer.id,
                fingerprint.appId,
                fingerprint.appName,
                fingerprint.packageName || fingerprint.appId,
                fingerprint.version,
                fingerprint.fileType || 'project',
                fingerprint.fileName || null,
                fingerprint.overallHash,
                JSON.stringify(fingerprint.fingerprints),
                JSON.stringify(fingerprint.metadata || {})
            ]
        );

        logger.info(`Fingerprint uploaded successfully for app ${fingerprint.appId} v${fingerprint.version}`);

        res.json({
            success: true,
            id: result.rows[0].id,
            message: 'Fingerprint uploaded successfully'
        });

    } catch (error) {
        logger.error('Error uploading fingerprint:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Generate fingerprint from a file

const fingerprintSDK = new AntiCloneSDK();
fingerprintSDK.setCredentials('dev-12345', 'ABCD2025');

// Generate fingerprint from uploaded file
app.post('/api/fingerprints/generate', upload.single('file'), limiter, logApiUsage, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'File is required'
            });
        }

        const { appId, appName, version, packageName } = req.body;
        
        if (!appId || !appName || !version) {
            return res.status(400).json({
                success: false,
                error: 'appId, appName, and version are required'
            });
        }

        // Validate file type
        const fileExt = path.extname(req.file.originalname).toLowerCase();
        if (!['.apk', '.ipa'].includes(fileExt)) {
            return res.status(400).json({
                success: false,
                error: 'Only APK and IPA files are supported'
            });
        }

        // Create temporary file
        const tempDir = path.join(__dirname, 'temp');
        await fs.mkdir(tempDir, { recursive: true });
        const tempFilePath = path.join(tempDir, `${Date.now()}-${req.file.originalname}`);
        
        try {
            // Write uploaded file to temp location
            await fs.writeFile(tempFilePath, req.file.buffer);

            const appInfo = {
                appId,
                appName,
                version,
                packageName: packageName || appId
            };

            // Generate fingerprint using SDK
            const fingerprint = await fingerprintSDK.generateFingerprintFromFile(tempFilePath, appInfo);

            // Remove developer credentials from response (keep only hash for verification)
            const responseFingerprint = {
                ...fingerprint,
                developerCredentials: {
                    credentialHash: fingerprint.developerCredentials.credentialHash
                }
            };

            logger.info(`Fingerprint generated for ${appId} v${version}`);

            res.json({
                success: true,
                fingerprint: responseFingerprint,
                message: 'Fingerprint generated successfully'
            });

        } finally {
            // Clean up temp file
            try {
                await fs.unlink(tempFilePath);
            } catch (error) {
                logger.warn('Failed to delete temp file:', tempFilePath);
            }
        }

    } catch (error) {
        logger.error('Error generating fingerprint:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to generate fingerprint'
        });
    }
});

// Verify fingerprint
app.post('/api/fingerprints/verify', logApiUsage, async (req, res) => {
    console.log('Verify request received:', req.body);
    console.log('Headers:', req.headers); 
    try {
        const { overallHash, appId, packageName, scannerInfo } = req.body;
        
        if (!overallHash) {
            return res.status(400).json({
                success: false,
                error: 'Overall hash is required for verification'
            });
        }

        // Find matching fingerprints
        const matchingFingerprints = await pool.query(
            'SELECT * FROM find_matching_fingerprints($1, $2, $3)',
            [overallHash, appId || null, packageName || null]
        );

        const isAuthentic = matchingFingerprints.rows.length > 0 && 
                          matchingFingerprints.rows[0].match_confidence >= 0.80;

        // Log verification attempt
        if (matchingFingerprints.rows.length > 0) {
            await pool.query(
                `INSERT INTO verification_logs 
                 (fingerprint_id, verification_type, scanner_info, input_hash, match_result, 
                  confidence_score, verification_details, ip_address, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                [
                    matchingFingerprints.rows[0].fingerprint_id,
                    'api_verify',
                    JSON.stringify(scannerInfo || {}),
                    overallHash,
                    isAuthentic,
                    matchingFingerprints.rows[0].match_confidence,
                    JSON.stringify(matchingFingerprints.rows[0]),
                    req.ip,
                    req.get('User-Agent')
                ]
            );
        }

        // Log potential clone detection
        if (!isAuthentic && appId) {
            await logSecurityEvent('potential_clone_detected', 'medium', {
                input_hash: overallHash,
                app_id: appId,
                package_name: packageName,
                scanner_info: scannerInfo,
                ip: req.ip
            });
        }

        res.json({
            success: true,
            isAuthentic,
            message: isAuthentic ? "It's certainly the authentic app" : "It may be a clone app",
            matchDetails: isAuthentic ? {
                appName: matchingFingerprints.rows[0].app_name,
                version: matchingFingerprints.rows[0].version,
                developer: matchingFingerprints.rows[0].developer_name,
                company: matchingFingerprints.rows[0].company_name,
                confidence: matchingFingerprints.rows[0].match_confidence
            } : null
        });

    } catch (error) {
        logger.error('Error verifying fingerprint:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Scan app for credibility
app.post('/api/fingerprints/scan', limiter, logApiUsage, async (req, res) => {
    try {
        const { appData, analysisType = 'full' } = req.body;
        
        if (!appData) {
            return res.status(400).json({
                success: false,
                error: 'App data is required for credibility scan'
            });
        }

        const appHash = hashContent(JSON.stringify(appData));
        
        // Check for cached analysis
        const cachedAnalysis = await pool.query(
            'SELECT * FROM credibility_analysis WHERE app_hash = $1 AND cache_expires_at > $2',
            [appHash, new Date()]
        );

        if (cachedAnalysis.rows.length > 0 && analysisType !== 'force') {
            return res.json({
                success: true,
                cached: true,
                analysis: cachedAnalysis.rows[0]
            });
        }

        // Perform credibility analysis
        const analysis = await performCredibilityAnalysis(appData);
        
        // Store analysis results
        await pool.query(
            `INSERT INTO credibility_analysis 
             (app_hash, risk_score, risk_level, analysis_results, flags, recommendations)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
                appHash,
                analysis.riskScore,
                analysis.riskLevel,
                JSON.stringify(analysis.results),
                JSON.stringify(analysis.flags),
                JSON.stringify(analysis.recommendations)
            ]
        );

        // Log high-risk apps
        if (analysis.riskLevel === 'high' || analysis.riskLevel === 'critical') {
            await logSecurityEvent('high_risk_app_detected', analysis.riskLevel, {
                app_hash: appHash,
                risk_score: analysis.riskScore,
                flags: analysis.flags,
                ip: req.ip
            });
        }

        res.json({
            success: true,
            cached: false,
            analysis: {
                riskScore: analysis.riskScore,
                riskLevel: analysis.riskLevel,
                results: analysis.results,
                flags: analysis.flags,
                recommendations: analysis.recommendations,
                analyzedAt: new Date().toISOString()
            }
        });

    } catch (error) {
        logger.error('Error scanning app credibility:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Register new developer
app.post('/api/developers/register', limiter, async (req, res) => {
    try {
        const { developerName, companyName, email, contactInfo, verificationDocuments } = req.body;
        
        if (!developerName || !email) {
            return res.status(400).json({
                success: false,
                error: 'Developer name and email are required'
            });
        }

        // Check if email already exists
        const existingDeveloper = await pool.query(
            'SELECT id FROM developers WHERE email = $1',
            [email]
        );

        if (existingDeveloper.rows.length > 0) {
            return res.status(409).json({
                success: false,
                error: 'Developer with this email already exists'
            });
        }

        // Generate developer ID and credentials
        const developerId = `dev-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const passkey = crypto.randomBytes(32).toString('hex');
        const apiKey = generateApiKey();
        
        const passkeyHash = hashContent(passkey);
        const apiKeyHash = hashContent(apiKey);

        // Insert new developer
        const result = await pool.query(
            `INSERT INTO developers 
             (developer_id, developer_name, company_name, email, passkey_hash, api_key_hash, 
              contact_info, verification_documents)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id`,
            [
                developerId,
                developerName,
                companyName || null,
                email,
                passkeyHash,
                apiKeyHash,
                JSON.stringify(contactInfo || {}),
                JSON.stringify(verificationDocuments || {})
            ]
        );

        logger.info(`New developer registered: ${email} (${developerId})`);

        res.json({
            success: true,
            developerId: result.rows[0].id,
            message: 'Developer registration successful. Please wait for verification.',
            credentials: {
                developerId,
                passkey,
                apiKey
            },
            note: 'Please store these credentials securely. They will not be shown again.'
        });

    } catch (error) {
        logger.error('Error registering developer:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Get developer profile
app.get('/api/developers/profile', authenticateRequest, logApiUsage, async (req, res) => {
    try {
        const developer = await pool.query(
            `SELECT developer_id, developer_name, company_name, email, verification_status,
                    registration_date, last_activity, contact_info,
                    (SELECT COUNT(*) FROM app_fingerprints WHERE developer_id = $1) as app_count
             FROM developers WHERE id = $1`,
            [req.developer.id]
        );

        res.json({
            success: true,
            profile: developer.rows[0]
        });

    } catch (error) {
        logger.error('Error fetching developer profile:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Get developer's fingerprints
app.get('/api/developers/fingerprints', authenticateRequest, logApiUsage, async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;

        const fingerprints = await pool.query(
            `SELECT id, app_id, app_name, version, file_type, overall_hash, 
                    upload_timestamp, verification_status
             FROM app_fingerprints 
             WHERE developer_id = $1 AND is_active = true
             ORDER BY upload_timestamp DESC
             LIMIT $2 OFFSET $3`,
            [req.developer.id, limit, offset]
        );

        const total = await pool.query(
            'SELECT COUNT(*) FROM app_fingerprints WHERE developer_id = $1 AND is_active = true',
            [req.developer.id]
        );

        res.json({
            success: true,
            fingerprints: fingerprints.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: parseInt(total.rows[0].count),
                pages: Math.ceil(total.rows[0].count / limit)
            }
        });

    } catch (error) {
        logger.error('Error fetching fingerprints:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Credibility analysis function
async function performCredibilityAnalysis(appData) {
    const analysis = {
        riskScore: 0,
        riskLevel: 'low',
        results: {},
        flags: [],
        recommendations: []
    };

    // Check for sensitive data requests
    const sensitivePatterns = [
        { pattern: /credit\s*card|debit\s*card|card\s*number/i, risk: 25, flag: 'requests_card_details' },
        { pattern: /cvv|cvc|security\s*code/i, risk: 20, flag: 'requests_cvv' },
        { pattern: /account\s*number|bank\s*account/i, risk: 30, flag: 'requests_account_number' },
        { pattern: /aadhar|aadhaar|passport\s*number/i, risk: 35, flag: 'requests_id_documents' },
        { pattern: /password|pin\s*code|login\s*credentials/i, risk: 40, flag: 'requests_passwords' },
        { pattern: /social\s*security|ssn/i, risk: 45, flag: 'requests_ssn' }
    ];

    const appContent = JSON.stringify(appData).toLowerCase();
    
    for (const { pattern, risk, flag } of sensitivePatterns) {
        if (pattern.test(appContent)) {
            analysis.riskScore += risk;
            analysis.flags.push(flag);
            analysis.results[flag] = true;
        }
    }

    // Check for suspicious permissions
    const suspiciousPermissions = [
        { permission: 'SEND_SMS', risk: 15, flag: 'sends_sms' },
        { permission: 'READ_SMS', risk: 20, flag: 'reads_sms' },
        { permission: 'WRITE_SETTINGS', risk: 10, flag: 'modifies_settings' },
        { permission: 'DEVICE_ADMIN', risk: 30, flag: 'device_admin' },
        { permission: 'CAMERA', risk: 5, flag: 'uses_camera' },
        { permission: 'RECORD_AUDIO', risk: 10, flag: 'records_audio' },
        { permission: 'ACCESS_FINE_LOCATION', risk: 8, flag: 'tracks_location' }
    ];

    const permissions = appData.permissions || [];
    for (const { permission, risk, flag } of suspiciousPermissions) {
        if (permissions.includes(permission)) {
            analysis.riskScore += risk;
            analysis.flags.push(flag);
            analysis.results[flag] = true;
        }
    }

    // Check for missing developer information
    if (!appData.developerInfo || !appData.developerInfo.name) {
        analysis.riskScore += 20;
        analysis.flags.push('missing_developer_info');
        analysis.results.missing_developer_info = true;
    }

    if (!appData.developerInfo || !appData.developerInfo.contact) {
        analysis.riskScore += 15;
        analysis.flags.push('missing_contact_info');
        analysis.results.missing_contact_info = true;
    }

    // Check for insecure connections
    if (appData.networkRequests) {
        const insecureConnections = appData.networkRequests.filter(url => 
            url.startsWith('http://') && !url.includes('localhost')
        );
        
        if (insecureConnections.length > 0) {
            analysis.riskScore += 25;
            analysis.flags.push('insecure_connections');
            analysis.results.insecure_connections = insecureConnections;
        }
    }

    // Determine risk level
    if (analysis.riskScore >= 80) {
        analysis.riskLevel = 'critical';
    } else if (analysis.riskScore >= 60) {
        analysis.riskLevel = 'high';
    } else if (analysis.riskScore >= 30) {
        analysis.riskLevel = 'medium';
    } else {
        analysis.riskLevel = 'low';
    }

    // Generate recommendations
    if (analysis.flags.includes('requests_card_details')) {
        analysis.recommendations.push('Verify if payment processing is necessary and ensure PCI DSS compliance');
    }
    if (analysis.flags.includes('requests_id_documents')) {
        analysis.recommendations.push('Question the necessity of identity document collection');
    }
    if (analysis.flags.includes('missing_developer_info')) {
        analysis.recommendations.push('Verify developer identity and legitimacy');
    }
    if (analysis.flags.includes('insecure_connections')) {
        analysis.recommendations.push('All network communications should use HTTPS');
    }

    return analysis;
}

// Error handling middleware
app.use((error, req, res, next) => {
    logger.error('Unhandled error:', error);
    
    if (error instanceof multer.MulterError) {
        return res.status(400).json({
            success: false,
            error: `File upload error: ${error.message}`
        });
    }
    
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    logger.info('SIGINT received, shutting down gracefully');
    await pool.end();
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    logger.info(`Sentinel API server running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
