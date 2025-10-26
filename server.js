const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
const csv = require('csv-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

// PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, done) => {
    if (err) {
        console.error('Database connection error:', err.stack);
    } else {
        console.log('Connected to PostgreSQL database');
        done();
    }
});

// ENHANCED CORS - Properly handle Authorization header
app.use((req, res, next) => {
    const origin = req.headers.origin || '*';
    
    // Set CORS headers
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    res.header('Access-Control-Expose-Headers', 'Authorization');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
        return res.sendStatus(200);
    }
    
    next();
});

// Middleware to normalize headers (case-insensitive)
app.use((req, res, next) => {
    // Normalize authorization header - some clients send it as 'Authorization' or 'authorization'
    if (!req.headers.authorization) {
        // Check for different cases
        const authKeys = Object.keys(req.headers).filter(key => key.toLowerCase() === 'authorization');
        if (authKeys.length > 0) {
            req.headers.authorization = req.headers[authKeys[0]];
        }
    }
    next();
});

// Enhanced request logging middleware
app.use((req, res, next) => {
    console.log(`\n[${new Date().toISOString()}] ${req.method} ${req.path}`);
    console.log('[Headers] Origin:', req.headers.origin || 'none');
    console.log('[Headers] Content-Type:', req.headers['content-type'] || 'none');
    console.log('[Headers] Authorization:', req.headers.authorization ? 'Bearer token present' : 'NO AUTH HEADER');
    
    // Log all headers for debugging (remove in production)
    if (req.path.includes('/admin/') && !req.headers.authorization) {
        console.log('[Debug] All headers:', JSON.stringify(req.headers, null, 2));
    }
    
    next();
});

// Tally API Configuration
const TALLY_API_KEY = process.env.TALLY_API_KEY || 'tly-H4VtyzbbaNnLkFOVWHuMgmugPpm1W8DW';
const TALLY_API_BASE = 'https://api.tally.so';
const JWT_SECRET = process.env.JWT_SECRET || 'alex123';

// Create tables
async function initializeDatabase() {
    try {
        // Create admins table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create briefs table - Updated with google_sheet_url
        await pool.query(`
            CREATE TABLE IF NOT EXISTS briefs (
                id SERIAL PRIMARY KEY,
                tally_form_id VARCHAR(255) UNIQUE NOT NULL,
                tally_form_name VARCHAR(255),
                title VARCHAR(255) NOT NULL,
                location VARCHAR(255),
                tier VARCHAR(50),
                requirements TEXT,
                dates VARCHAR(255),
                status VARCHAR(50) DEFAULT 'live',
                google_sheet_url VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Add google_sheet_url column if it doesn't exist
        await pool.query(`
            ALTER TABLE briefs 
            ADD COLUMN IF NOT EXISTS google_sheet_url VARCHAR(500)
        `);

        // Create applications table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS applications (
                id SERIAL PRIMARY KEY,
                brief_id INTEGER REFERENCES briefs(id),
                tally_submission_id VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) NOT NULL,
                instagram VARCHAR(255),
                portfolio VARCHAR(255),
                content_proposal TEXT,
                status VARCHAR(50) DEFAULT 'submitted',
                admin_feedback TEXT,
                submitted_at TIMESTAMP,
                raw_tally_data TEXT
            )
        `);

        // Create indexes
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_applications_email ON applications(email)`);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_applications_brief_id ON applications(brief_id)`);

        // Insert default admin user (admin/admin123)
        const defaultPassword = await bcrypt.hash('admin123', 10);
        await pool.query(
            `INSERT INTO admins (username, password_hash) 
             VALUES ($1, $2) 
             ON CONFLICT (username) DO NOTHING`,
            ['admin', defaultPassword]
        );

        console.log('Database initialized successfully');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
}

// Initialize database on startup
initializeDatabase();

// Helper function to make Tally API requests
async function tallyAPI(endpoint, method = 'GET', data = null) {
    try {
        const config = {
            method,
            url: `${TALLY_API_BASE}${endpoint}`,
            headers: {
                'Authorization': `Bearer ${TALLY_API_KEY}`,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        };

        if (data) {
            config.data = data;
        }
        
        const response = await axios(config);
        return response.data;
    } catch (error) {
        console.error('Tally API Error:', error.response?.data || error.message);
        throw error;
    }
}

// Helper function to detect column types based on content
function detectColumnType(values) {
    // Remove empty values and take a sample
    const sampleValues = values.filter(v => v && v.toString().trim()).slice(0, 10);
    if (sampleValues.length === 0) return 'unknown';
    
    // Email pattern
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const emailMatches = sampleValues.filter(v => emailPattern.test(v.toString().trim()));
    if (emailMatches.length > sampleValues.length * 0.6) return 'email';
    
    // URL patterns (portfolio, website)
    const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;
    const urlMatches = sampleValues.filter(v => urlPattern.test(v.toString().trim()));
    if (urlMatches.length > sampleValues.length * 0.6) return 'url';
    
    // Social media patterns
    const socialPatterns = [
        /instagram\.com/i,
        /tiktok\.com/i,
        /twitter\.com/i,
        /youtube\.com/i,
        /@[\w]+/  // Social media handles
    ];
    const socialMatches = sampleValues.filter(v => 
        socialPatterns.some(pattern => pattern.test(v.toString()))
    );
    if (socialMatches.length > sampleValues.length * 0.5) return 'social';
    
    // Name pattern (mostly alphabetic with possible spaces)
    const namePattern = /^[a-zA-Z\s\-'\.]+$/;
    const nameMatches = sampleValues.filter(v => 
        namePattern.test(v.toString().trim()) && 
        v.toString().trim().length > 2 &&
        v.toString().trim().length < 50
    );
    if (nameMatches.length > sampleValues.length * 0.7) return 'name';
    
    // Date patterns
    const datePatterns = [
        /^\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}$/,
        /^\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}$/,
        /^\w+ \d{1,2}, \d{4}$/
    ];
    const dateMatches = sampleValues.filter(v =>
        datePatterns.some(pattern => pattern.test(v.toString().trim()))
    );
    if (dateMatches.length > sampleValues.length * 0.6) return 'date';
    
    // Number pattern (follower counts, etc.)
    const numberPattern = /^[\d,]+$/;
    const numberMatches = sampleValues.filter(v => numberPattern.test(v.toString().trim()));
    if (numberMatches.length > sampleValues.length * 0.7) return 'number';
    
    // Long text (proposals, descriptions)
    const avgLength = sampleValues.reduce((sum, v) => sum + v.toString().length, 0) / sampleValues.length;
    if (avgLength > 100) return 'text_long';
    if (avgLength > 30) return 'text_medium';
    
    return 'text_short';
}

// Smart column mapping function
function mapColumns(submissions) {
    if (!submissions || submissions.length === 0) return {};
    
    const firstRows = submissions.slice(0, 10);
    const columns = Object.keys(firstRows[0]);
    const columnMapping = {};
    
    console.log('[Smart Import] Analyzing columns...');
    
    columns.forEach(column => {
        const values = firstRows.map(row => row[column]);
        const columnType = detectColumnType(values);
        const columnLower = column.toLowerCase();
        
        console.log(`[Smart Import] Column "${column}" detected as: ${columnType}`);
        
        // Map based on detected type and column name hints
        if (columnType === 'email' || columnLower.includes('email') || columnLower.includes('mail')) {
            columnMapping.email = column;
        } else if (columnType === 'social' || 
                   columnLower.includes('instagram') || 
                   columnLower.includes('tiktok') || 
                   columnLower.includes('social')) {
            columnMapping.social = column;
        } else if (columnType === 'url' || 
                   columnLower.includes('portfolio') || 
                   columnLower.includes('website') || 
                   columnLower.includes('link')) {
            columnMapping.portfolio = column;
        } else if (columnType === 'name' || 
                   columnLower.includes('name') || 
                   columnLower === 'full name') {
            columnMapping.name = column;
        } else if (columnType === 'date' || 
                   columnLower.includes('date') || 
                   columnLower.includes('time')) {
            columnMapping.date = column;
        } else if (columnType === 'number' && 
                   (columnLower.includes('follower') || columnLower.includes('count'))) {
            columnMapping.followers = column;
        } else if (columnType === 'text_long' || 
                   columnLower.includes('proposal') || 
                   columnLower.includes('description') || 
                   columnLower.includes('content')) {
            columnMapping.proposal = column;
        } else if (columnLower.includes('location') || 
                   columnLower.includes('country') || 
                   columnLower.includes('city')) {
            columnMapping.location = column;
        } else if (columnLower.includes('engagement') || columnLower.includes('rate')) {
            columnMapping.engagement = column;
        } else if (columnLower.includes('style') || columnLower.includes('content type')) {
            columnMapping.style = column;
        } else if (columnLower.includes('availability') || columnLower.includes('available')) {
            columnMapping.availability = column;
        } else if (columnLower.includes('travel') || columnLower.includes('companion')) {
            columnMapping.travel = column;
        }
    });
    
    console.log('[Smart Import] Column mapping:', columnMapping);
    return columnMapping;
}

// Helper function to parse Google Sheets CSV
async function parseGoogleSheetCSV(sheetUrl) {
    try {
        // Convert Google Sheets URL to CSV export URL
        let csvUrl = sheetUrl;
        
        // If it's a regular Google Sheets URL, convert it to CSV export
        if (sheetUrl.includes('docs.google.com/spreadsheets')) {
            const sheetIdMatch = sheetUrl.match(/\/d\/([a-zA-Z0-9-_]+)/);
            if (sheetIdMatch) {
                const sheetId = sheetIdMatch[1];
                csvUrl = `https://docs.google.com/spreadsheets/d/${sheetId}/export?format=csv`;
            }
        }
        
        console.log('[Google Sheets] Fetching CSV from:', csvUrl);
        
        const response = await axios.get(csvUrl, {
            responseType: 'stream',
            timeout: 30000
        });
        
        const results = [];
        
        return new Promise((resolve, reject) => {
            response.data
                .pipe(csv())
                .on('data', (data) => results.push(data))
                .on('end', () => {
                    console.log(`[Google Sheets] Parsed ${results.length} rows`);
                    resolve(results);
                })
                .on('error', (error) => {
                    console.error('[Google Sheets] Parse error:', error);
                    reject(error);
                });
        });
    } catch (error) {
        console.error('[Google Sheets] Error fetching CSV:', error);
        throw error;
    }
}

// Auth Middleware with enhanced debugging
function authenticateAdmin(req, res, next) {
    // Get authorization header - handle different formats
    let authHeader = req.headers.authorization || req.headers.Authorization;
    
    console.log('[Auth] Request path:', req.path);
    console.log('[Auth] Auth header received:', authHeader ? 'Yes' : 'No');
    
    if (!authHeader) {
        console.log('[Auth] No authorization header found');
        console.log('[Auth] All headers:', Object.keys(req.headers));
        return res.status(401).json({ 
            error: 'No authorization header provided',
            message: 'Please include Authorization: Bearer <token> in headers',
            headers: Object.keys(req.headers) // Debug info
        });
    }
    
    // Extract token - handle "Bearer " prefix
    let token;
    if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else {
        token = authHeader;
    }
    
    if (!token || token === 'null' || token === 'undefined') {
        console.log('[Auth] Invalid or missing token');
        return res.status(401).json({ 
            error: 'Invalid authorization format',
            message: 'Authorization header should be: Bearer <token>',
            received: authHeader
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.adminId = decoded.adminId;
        console.log('[Auth] Token valid for admin ID:', decoded.adminId);
        next();
    } catch (error) {
        console.log('[Auth] Token verification failed:', error.message);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                error: 'Token expired',
                message: 'Please login again',
                expiredAt: error.expiredAt
            });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ 
                error: 'Invalid token',
                message: error.message,
                tokenLength: token ? token.length : 0
            });
        }
        return res.status(401).json({ 
            error: 'Token verification failed',
            message: error.message
        });
    }
}

// ==================== TEST ENDPOINTS ====================

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        corsTest: {
            origin: req.headers.origin || 'no origin header',
            authHeader: req.headers.authorization ? 'present' : 'missing'
        }
    });
});

// Verify token endpoint - helps debug authentication issues
app.get('/api/verify-token', (req, res) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    
    console.log('[Verify] Headers received:', Object.keys(req.headers));
    console.log('[Verify] Auth header:', authHeader);
    
    if (!authHeader) {
        return res.status(401).json({ 
            valid: false, 
            error: 'No authorization header',
            headersReceived: Object.keys(req.headers)
        });
    }

    let token;
    if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else {
        token = authHeader;
    }
    
    if (!token || token === 'null' || token === 'undefined') {
        return res.status(401).json({ 
            valid: false, 
            error: 'Invalid token format',
            authHeader: authHeader
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ 
            valid: true, 
            adminId: decoded.adminId,
            issuedAt: new Date(decoded.iat * 1000).toISOString(),
            expiresAt: new Date(decoded.exp * 1000).toISOString(),
            tokenLength: token.length
        });
    } catch (error) {
        res.status(401).json({ 
            valid: false, 
            error: error.message,
            tokenProvided: !!token,
            tokenLength: token ? token.length : 0,
            errorType: error.name
        });
    }
});

// Debug endpoint to see raw Tally forms response
app.get('/api/admin/tally/debug', authenticateAdmin, async (req, res) => {
    try {
        const response = await tallyAPI('/forms?limit=50');
        res.json({
            total: response.total,
            page: response.page,
            limit: response.limit,
            hasMore: response.hasMore,
            formCount: response.items ? response.items.length : 0,
            formNames: response.items ? response.items.map(f => ({ id: f.id, name: f.name })) : []
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== ADMIN ENDPOINTS ====================

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        // Check if body exists
        if (!req.body) {
            console.error('[Login] No request body received');
            return res.status(400).json({ error: 'No data received' });
        }

        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        const admin = result.rows[0];

        if (!admin) {
            console.log('[Login] User not found:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, admin.password_hash);
        
        if (!validPassword) {
            console.log('[Login] Invalid password for user:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ adminId: admin.id }, JWT_SECRET, { expiresIn: '24h' });
        console.log('[Login] Successful login for:', username);
        res.json({ 
            token, 
            username: admin.username,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        });
    } catch (err) {
        console.error('[Login Error]', err);
        return res.status(500).json({ error: 'Database error during login' });
    }
});

// Get all Tally forms - with pagination handling
app.get('/api/admin/tally/forms', authenticateAdmin, async (req, res) => {
    try {
        let allForms = [];
        let page = 1;
        let hasMore = true;
        
        // Fetch all pages of forms
        while (hasMore) {
            console.log(`[Tally Forms] Fetching page ${page}...`);
            const response = await tallyAPI(`/forms?page=${page}&limit=50`);
            
            const forms = response?.items || response?.data || [];
            allForms = allForms.concat(forms);
            
            hasMore = response?.hasMore || false;
            page++;
            
            // Safety limit to prevent infinite loops
            if (page > 10) break;
        }
        
        console.log(`[Tally Forms] Total forms fetched: ${allForms.length}`);
        
        // Get existing form IDs that are already connected to briefs
        const result = await pool.query('SELECT tally_form_id FROM briefs');
        const connectedFormIds = result.rows.map(b => b.tally_form_id);
        
        const formsWithStatus = allForms.map(form => ({
            ...form,
            isConnected: connectedFormIds.includes(form.id)
        }));
        
        res.json({ forms: formsWithStatus });
    } catch (error) {
        console.error('Error fetching forms:', error);
        res.status(500).json({ 
            error: 'Failed to fetch Tally forms',
            details: error.message
        });
    }
});

// Create new brief with Google Sheet link
app.post('/api/admin/briefs', authenticateAdmin, async (req, res) => {
    const { tallyFormId, tallyFormName, title, location, tier, requirements, dates, googleSheetUrl } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Create brief
        const briefResult = await client.query(
            `INSERT INTO briefs (tally_form_id, tally_form_name, title, location, tier, requirements, dates, google_sheet_url) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
             RETURNING id`,
            [tallyFormId, tallyFormName, title, location, tier, requirements, dates, googleSheetUrl]
        );

        const briefId = briefResult.rows[0].id;
        let importedCount = 0;

        // If Google Sheet URL provided, import submissions
        if (googleSheetUrl) {
            try {
                console.log('[Import] Importing from Google Sheet:', googleSheetUrl);
                const submissions = await parseGoogleSheetCSV(googleSheetUrl);
                
                if (submissions.length > 0) {
                    // Smart column detection
                    const mapping = mapColumns(submissions);
                    
                    if (!mapping.email) {
                        console.log('[Import] Warning: No email column detected');
                    }
                    
                    for (let i = 0; i < submissions.length; i++) {
                        const submission = submissions[i];
                        
                        // Use smart mapping to extract fields
                        const email = mapping.email ? submission[mapping.email] : '';
                        const instagram = mapping.social ? submission[mapping.social] : '';
                        const portfolio = mapping.portfolio ? submission[mapping.portfolio] : '';
                        const name = mapping.name ? submission[mapping.name] : '';
                        const followers = mapping.followers ? submission[mapping.followers] : '';
                        const engagement = mapping.engagement ? submission[mapping.engagement] : '';
                        const style = mapping.style ? submission[mapping.style] : '';
                        const location = mapping.location ? submission[mapping.location] : '';
                        const availability = mapping.availability ? submission[mapping.availability] : '';
                        const travel = mapping.travel ? submission[mapping.travel] : '';
                        
                        // Build content proposal from available fields
                        const proposalParts = [];
                        if (name) proposalParts.push(`Name: ${name}`);
                        if (style) proposalParts.push(`Style: ${style}`);
                        if (followers) proposalParts.push(`Followers: ${followers}`);
                        if (engagement) proposalParts.push(`Engagement: ${engagement}`);
                        if (location) proposalParts.push(`Location: ${location}`);
                        if (availability) proposalParts.push(`Availability: ${availability}`);
                        if (travel) proposalParts.push(`Travel: ${travel}`);
                        
                        // If we have a proposal column, add it at the end
                        if (mapping.proposal && submission[mapping.proposal]) {
                            proposalParts.push(`\nProposal: ${submission[mapping.proposal]}`);
                        }
                        
                        const proposal = proposalParts.join('\n') || 'No additional information provided';
                        
                        if (!email || !email.trim()) {
                            console.log(`[Import] Skipping row ${i + 1}: no email found`);
                            continue;
                        }
                        
                        try {
                            await client.query(
                                `INSERT INTO applications 
                                 (brief_id, tally_submission_id, email, instagram, portfolio, content_proposal, submitted_at, raw_tally_data) 
                                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                                 ON CONFLICT (tally_submission_id) DO NOTHING`,
                                [
                                    briefId,
                                    submission['Submission ID'] || `${tallyFormId}_row_${i + 1}`,
                                    email.trim(),
                                    instagram || '',
                                    portfolio || '',
                                    proposal,
                                    mapping.date && submission[mapping.date] ? submission[mapping.date] : new Date(),
                                    JSON.stringify(submission)
                                ]
                            );
                            importedCount++;
                        } catch (insertError) {
                            console.error(`[Import] Failed to insert row ${i + 1}:`, insertError.message);
                        }
                    }
                } else {
                    console.log('[Import] No submissions found in the sheet');
                }
                
                console.log(`[Import] Successfully imported ${importedCount} submissions`);
            } catch (importError) {
                console.error('[Import] Error importing from Google Sheet:', importError);
                // Continue even if import fails - brief is still created
            }
        }

        await client.query('COMMIT');
        res.json({ 
            success: true, 
            briefId,
            importedCount
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error creating brief:', error);
        if (error.constraint === 'briefs_tally_form_id_key') {
            return res.status(400).json({ error: 'This form is already connected to a brief' });
        }
        res.status(500).json({ 
            error: 'Failed to create brief',
            details: error.message
        });
    } finally {
        client.release();
    }
});

// Import submissions from Google Sheet for existing brief
app.post('/api/admin/brief/:id/import-sheet', authenticateAdmin, async (req, res) => {
    const { googleSheetUrl } = req.body;
    const briefId = req.params.id;
    
    try {
        // Update the brief with the new sheet URL
        await pool.query(
            'UPDATE briefs SET google_sheet_url = $1 WHERE id = $2',
            [googleSheetUrl, briefId]
        );
        
        // Get brief info
        const briefResult = await pool.query('SELECT * FROM briefs WHERE id = $1', [briefId]);
        const brief = briefResult.rows[0];
        
        if (!brief) {
            return res.status(404).json({ error: 'Brief not found' });
        }
        
        // Import submissions
        const submissions = await parseGoogleSheetCSV(googleSheetUrl);
        let importedCount = 0;
        let skippedCount = 0;
        
        if (submissions.length > 0) {
            // Smart column detection
            const mapping = mapColumns(submissions);
            
            if (!mapping.email) {
                console.log('[Import] Warning: No email column detected');
                console.log('[Import] Available columns:', Object.keys(submissions[0]));
                return res.status(400).json({ 
                    error: 'No email column detected in the sheet',
                    availableColumns: Object.keys(submissions[0])
                });
            }
            
            console.log(`[Import] Processing ${submissions.length} rows with smart mapping`);
            
            for (let i = 0; i < submissions.length; i++) {
                const submission = submissions[i];
                
                // Use smart mapping to extract fields
                const email = mapping.email ? submission[mapping.email] : '';
                const instagram = mapping.social ? submission[mapping.social] : '';
                const portfolio = mapping.portfolio ? submission[mapping.portfolio] : '';
                const name = mapping.name ? submission[mapping.name] : '';
                const followers = mapping.followers ? submission[mapping.followers] : '';
                const engagement = mapping.engagement ? submission[mapping.engagement] : '';
                const style = mapping.style ? submission[mapping.style] : '';
                const location = mapping.location ? submission[mapping.location] : '';
                const availability = mapping.availability ? submission[mapping.availability] : '';
                const travel = mapping.travel ? submission[mapping.travel] : '';
                
                // Build content proposal from available fields
                const proposalParts = [];
                if (name) proposalParts.push(`Name: ${name}`);
                if (style) proposalParts.push(`Style: ${style}`);
                if (followers) proposalParts.push(`Followers: ${followers}`);
                if (engagement) proposalParts.push(`Engagement: ${engagement}`);
                if (location) proposalParts.push(`Location: ${location}`);
                if (availability) proposalParts.push(`Availability: ${availability}`);
                if (travel) proposalParts.push(`Travel: ${travel}`);
                
                // If we have a proposal column, add it at the end
                if (mapping.proposal && submission[mapping.proposal]) {
                    proposalParts.push(`\nProposal: ${submission[mapping.proposal]}`);
                }
                
                const proposal = proposalParts.join('\n') || 'No additional information provided';
                
                if (!email || !email.trim()) {
                    skippedCount++;
                    continue;
                }
                
                try {
                    await pool.query(
                        `INSERT INTO applications 
                         (brief_id, tally_submission_id, email, instagram, portfolio, content_proposal, submitted_at, raw_tally_data) 
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                         ON CONFLICT (tally_submission_id) 
                         DO UPDATE SET 
                            email = EXCLUDED.email,
                            instagram = EXCLUDED.instagram,
                            portfolio = EXCLUDED.portfolio,
                            content_proposal = EXCLUDED.content_proposal`,
                        [
                            briefId,
                            submission['Submission ID'] || `${brief.tally_form_id}_row_${i + 1}`,
                            email.trim(),
                            instagram || '',
                            portfolio || '',
                            proposal,
                            mapping.date && submission[mapping.date] ? submission[mapping.date] : new Date(),
                            JSON.stringify(submission)
                        ]
                    );
                    importedCount++;
                } catch (insertError) {
                    console.error(`[Import] Failed to insert row ${i + 1}:`, insertError.message);
                    skippedCount++;
                }
            }
        }
        
        console.log(`[Import] Import complete: ${importedCount} imported, ${skippedCount} skipped`);
        
        res.json({ 
            success: true, 
            importedCount,
            skippedCount,
            totalRows: submissions.length,
            detectedColumns: mapping
        });
    } catch (error) {
        console.error('Error importing from sheet:', error);
        res.status(500).json({ 
            error: 'Failed to import from Google Sheet',
            details: error.message
        });
    }
});

// Get all briefs
app.get('/api/admin/briefs', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT b.*, COUNT(a.id)::int as application_count 
             FROM briefs b 
             LEFT JOIN applications a ON b.id = a.brief_id 
             GROUP BY b.id 
             ORDER BY b.created_at DESC`
        );
        res.json({ briefs: result.rows });
    } catch (err) {
        console.error('Error fetching briefs:', err);
        return res.status(500).json({ 
            error: 'Database error',
            message: 'Failed to fetch briefs'
        });
    }
});

// Update brief status
app.put('/api/admin/brief/:id/status', authenticateAdmin, async (req, res) => {
    const { status } = req.body;
    
    if (!['live', 'expired'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status. Must be "live" or "expired"' });
    }
    
    try {
        const result = await pool.query(
            'UPDATE briefs SET status = $1 WHERE id = $2 RETURNING id',
            [status, req.params.id]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Brief not found' });
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error('Error updating brief status:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// Get all applications with filters
app.get('/api/admin/applications', authenticateAdmin, async (req, res) => {
    const { briefId, status, tier } = req.query;
    
    let query = `
        SELECT a.*, b.title as brief_title, b.tier 
        FROM applications a 
        JOIN briefs b ON a.brief_id = b.id 
        WHERE 1=1
    `;
    const params = [];
    let paramCount = 0;

    if (briefId && briefId !== 'all') {
        paramCount++;
        query += ` AND a.brief_id = $${paramCount}`;
        params.push(briefId);
    }
    
    if (status && status !== 'all') {
        paramCount++;
        query += ` AND a.status = $${paramCount}`;
        params.push(status);
    }
    
    if (tier && tier !== 'all') {
        paramCount++;
        query += ` AND b.tier = $${paramCount}`;
        params.push(tier);
    }

    query += ' ORDER BY a.submitted_at DESC';

    try {
        const result = await pool.query(query, params);
        res.json({ applications: result.rows });
    } catch (err) {
        console.error('Error fetching applications:', err);
        return res.status(500).json({ 
            error: 'Database error',
            message: 'Failed to fetch applications'
        });
    }
});

// Update application status
app.put('/api/admin/application/:id', authenticateAdmin, async (req, res) => {
    const { status, adminFeedback } = req.body;
    
    if (!['submitted', 'accepted', 'unsuccessful'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }
    
    try {
        const result = await pool.query(
            'UPDATE applications SET status = $1, admin_feedback = $2 WHERE id = $3 RETURNING id',
            [status, adminFeedback, req.params.id]
        );
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Application not found' });
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error('Error updating application:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// Bulk update applications
app.post('/api/admin/applications/bulk-update', authenticateAdmin, async (req, res) => {
    const { applicationIds, status } = req.body;
    
    if (!applicationIds || applicationIds.length === 0) {
        return res.status(400).json({ error: 'No applications selected' });
    }

    if (!['submitted', 'accepted', 'unsuccessful'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    const placeholders = applicationIds.map((_, i) => `$${i + 2}`).join(',');
    
    try {
        const result = await pool.query(
            `UPDATE applications SET status = $1 WHERE id IN (${placeholders})`,
            [status, ...applicationIds]
        );
        res.json({ success: true, updatedCount: result.rowCount });
    } catch (err) {
        console.error('Error bulk updating applications:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ==================== USER ENDPOINTS ====================

// User login
app.post('/api/user/login', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
    
    try {
        const result = await pool.query(
            'SELECT * FROM applications WHERE email = $1',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No applications found with this email' });
        }
        
        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ 
            token, 
            email,
            applicationCount: result.rows.length 
        });
    } catch (err) {
        console.error('User login error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// Get user's applications
app.get('/api/user/applications', async (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;
        
        const result = await pool.query(
            `SELECT a.*, b.title as brief_title, b.location, b.tier 
             FROM applications a 
             JOIN briefs b ON a.brief_id = b.id 
             WHERE a.email = $1 
             ORDER BY a.submitted_at DESC`,
            [email]
        );
        
        res.json({ applications: result.rows });
    } catch (error) {
        console.error('Error fetching user applications:', error);
        return res.status(401).json({ error: 'Invalid token' });
    }
});

// ==================== STATS ENDPOINT ====================

// Dashboard statistics
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                COUNT(DISTINCT b.id)::int as total_briefs,
                COUNT(DISTINCT CASE WHEN b.status = 'live' THEN b.id END)::int as live_briefs,
                COUNT(DISTINCT CASE WHEN b.status = 'expired' THEN b.id END)::int as expired_briefs,
                COUNT(a.id)::int as total_applications,
                COUNT(CASE WHEN a.status = 'submitted' THEN 1 END)::int as pending_applications,
                COUNT(CASE WHEN a.status = 'accepted' THEN 1 END)::int as accepted_applications,
                COUNT(CASE WHEN a.status = 'unsuccessful' THEN 1 END)::int as unsuccessful_applications
            FROM briefs b
            LEFT JOIN applications a ON b.id = a.brief_id
        `);
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching stats:', err);
        return res.status(500).json({ 
            error: 'Database error',
            message: 'Failed to fetch statistics'
        });
    }
});

// Keep-alive endpoint
app.get('/api/keep-alive', (req, res) => {
    res.json({ 
        status: 'alive',
        timestamp: new Date().toISOString()
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        database: pool.totalCount > 0 ? 'connected' : 'disconnected'
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    console.log('[404] Not found:', req.method, req.path);
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Admin login: admin / admin123`);
    console.log(`API Base URL: http://localhost:${PORT}/api`);
});

// Graceful shutdown
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

async function shutdown() {
    console.log('Shutting down gracefully...');
    try {
        await pool.end();
        console.log('Database pool closed.');
    } catch (err) {
        console.error('Error during shutdown:', err);
    }
    process.exit(0);
}
