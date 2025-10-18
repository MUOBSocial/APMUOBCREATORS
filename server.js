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

// SIMPLIFIED CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Tally API Configuration
const TALLY_API_KEY = process.env.TALLY_API_KEY || 'tly-H4VtyzbbaNnLkFOVWHuMgmugPpm1W8DW';
const TALLY_API_BASE = 'https://api.tally.so';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

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

// Auth Middleware
function authenticateAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.adminId = decoded.adminId;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// ==================== TEST ENDPOINTS ====================

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'Server is running',
        timestamp: new Date().toISOString()
    });
});

// ==================== ADMIN ENDPOINTS ====================

// Admin login
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        const admin = result.rows[0];

        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, admin.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ adminId: admin.id }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: admin.username });
    } catch (err) {
        console.error('[Login Error]', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// Get all Tally forms
app.get('/api/admin/tally/forms', authenticateAdmin, async (req, res) => {
    try {
        const forms = await tallyAPI('/forms');
        
        // Get existing form IDs that are already connected to briefs
        const result = await pool.query('SELECT tally_form_id FROM briefs');
        const connectedFormIds = result.rows.map(b => b.tally_form_id);
        
        // Tally API returns forms in 'items'
        const formsList = forms?.items || forms?.data || [];
        
        const formsWithStatus = formsList.map(form => ({
            ...form,
            isConnected: connectedFormIds.includes(form.id)
        }));
        
        res.json({ forms: formsWithStatus });
    } catch (error) {
        console.error('Error fetching forms:', error);
        res.status(500).json({ error: 'Failed to fetch Tally forms' });
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
                
                for (let i = 0; i < submissions.length; i++) {
                    const submission = submissions[i];
                    
                    // Map common field names (adjust based on your form)
                    const email = submission.Email || submission.email || submission['Email Address'] || '';
                    const instagram = submission.Instagram || submission['Instagram Handle'] || submission['Instagram handle'] || '';
                    const portfolio = submission.Portfolio || submission['Portfolio Link'] || submission['Portfolio Links'] || '';
                    const proposal = submission['Content Proposal'] || submission['Content proposal'] || submission.Proposal || '';
                    
                    if (!email) {
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
                                `${tallyFormId}_row_${i + 1}`, // Create unique ID from form ID and row number
                                email,
                                instagram,
                                portfolio,
                                proposal,
                                submission.Timestamp || new Date(),
                                JSON.stringify(submission)
                            ]
                        );
                        importedCount++;
                    } catch (insertError) {
                        console.error(`[Import] Failed to insert row ${i + 1}:`, insertError.message);
                    }
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
        res.status(500).json({ error: 'Failed to create brief' });
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
        
        for (let i = 0; i < submissions.length; i++) {
            const submission = submissions[i];
            
            const email = submission.Email || submission.email || submission['Email Address'] || '';
            const instagram = submission.Instagram || submission['Instagram Handle'] || '';
            const portfolio = submission.Portfolio || submission['Portfolio Link'] || '';
            const proposal = submission['Content Proposal'] || submission.Proposal || '';
            
            if (!email) continue;
            
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
                        `${brief.tally_form_id}_row_${i + 1}`,
                        email,
                        instagram,
                        portfolio,
                        proposal,
                        submission.Timestamp || new Date(),
                        JSON.stringify(submission)
                    ]
                );
                importedCount++;
            } catch (insertError) {
                console.error(`Failed to insert row ${i + 1}:`, insertError.message);
            }
        }
        
        res.json({ 
            success: true, 
            importedCount,
            totalRows: submissions.length 
        });
    } catch (error) {
        console.error('Error importing from sheet:', error);
        res.status(500).json({ error: 'Failed to import from Google Sheet' });
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
        return res.status(500).json({ error: 'Database error' });
    }
});

// Update brief status
app.put('/api/admin/brief/:id/status', authenticateAdmin, async (req, res) => {
    const { status } = req.body;
    
    try {
        await pool.query(
            'UPDATE briefs SET status = $1 WHERE id = $2',
            [status, req.params.id]
        );
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
        return res.status(500).json({ error: 'Database error' });
    }
});

// Update application status
app.put('/api/admin/application/:id', authenticateAdmin, async (req, res) => {
    const { status, adminFeedback } = req.body;
    
    try {
        await pool.query(
            'UPDATE applications SET status = $1, admin_feedback = $2 WHERE id = $3',
            [status, adminFeedback, req.params.id]
        );
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
    
    try {
        const result = await pool.query(
            'SELECT * FROM applications WHERE email = $1',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No applications found with this email' });
        }
        
        const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, email });
    } catch (err) {
        console.error('User login error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
});

// Get user's applications
app.get('/api/user/applications', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    
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
        return res.status(500).json({ error: 'Database error' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin login: admin / admin123`);
});

// Graceful shutdown
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

async function shutdown() {
    console.log('Shutting down gracefully...');
    await pool.end();
    console.log('Database pool closed.');
    process.exit(0);
}
