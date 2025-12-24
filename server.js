const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'location-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// FIXED: More permissive CORS configuration
app.use(cors({
    origin: '*', // Allow all origins for development
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Handle preflight requests
app.options('*', cors());

app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(uploadsDir));

// Configure email transporter (SMTP) - set via env vars
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || `no-reply@localhost`;

let mailTransporter = null;
if (SMTP_HOST && SMTP_USER) {
    mailTransporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465, // true for 465, false for other ports
        auth: {
            user: SMTP_USER,
            pass: SMTP_PASS
        }
    });
    // Verify transporter
    mailTransporter.verify().then(() => {
        console.log('✓ SMTP transporter verified');
    }).catch(err => {
        console.warn('SMTP transporter verification failed:', err && err.message);
    });
} else {
    console.log('SMTP not configured - forgot password emails will be logged to console');
}

// Database connection pool and config (Postgres)
let pool;
const DB_CONFIG = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'bulan_locator',
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 20000,
    // Relax SSL by default for cloud providers (override by setting DB_SSL=false)
    ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
};

function replacePlaceholders(sql) {
    // Replace each ? with $1, $2, ... for pg parameterized queries
    let i = 0;
    return sql.replace(/\?/g, () => `$${++i}`);
}

async function dbQuery(text, params = []) {
    const t = replacePlaceholders(text);
    return pool.query(t, params);
}

async function recreatePool() {
    try {
        if (pool) {
            try { await pool.end(); } catch (e) { console.warn('Error ending old pool:', e && e.message); }
        }
    } finally {
        pool = new Pool(DB_CONFIG);
        console.log('Created new Postgres pool');
    }
}

// FIXED: Add missing columns for PostgreSQL
async function addMissingColumnsPostgres() {
    try {
        console.log('Checking for missing columns in PostgreSQL...');
        
        // Check if locations table exists
        const tableCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'locations'
            );
        `);
        
        if (!tableCheck.rows[0].exists) {
            console.log('Creating locations table...');
            await dbQuery(`
                CREATE TABLE locations (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    address TEXT NOT NULL,
                    lat DECIMAL(10, 8) NOT NULL,
                    lng DECIMAL(11, 8) NOT NULL,
                    contact VARCHAR(100),
                    operating_hours VARCHAR(255),
                    fuel_types VARCHAR(255),
                    services_offered TEXT,
                    description TEXT,
                    image VARCHAR(500),
                    views INTEGER DEFAULT 0,
                    visits INTEGER DEFAULT 0,
                    is_archived BOOLEAN DEFAULT FALSE,
                    archived_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Locations table created successfully');
            return;
        }

        // Get all existing columns
        const columnsCheck = await dbQuery(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'locations'
        `);
        
        const existingColumns = columnsCheck.rows.map(row => row.column_name);
        const requiredColumns = {
            'is_archived': 'ADD COLUMN is_archived BOOLEAN DEFAULT FALSE',
            'archived_at': 'ADD COLUMN archived_at TIMESTAMP',
            'image': 'ADD COLUMN image VARCHAR(500)',
            'contact': 'ADD COLUMN contact VARCHAR(100)',
            'operating_hours': 'ADD COLUMN operating_hours VARCHAR(255)',
            'fuel_types': 'ADD COLUMN fuel_types VARCHAR(255)',
            'services_offered': 'ADD COLUMN services_offered TEXT',
            'description': 'ADD COLUMN description TEXT',
            'views': 'ADD COLUMN views INTEGER DEFAULT 0',
            'visits': 'ADD COLUMN visits INTEGER DEFAULT 0'
        };

        const missingColumns = Object.entries(requiredColumns)
            .filter(([column]) => !existingColumns.includes(column));

        if (missingColumns.length > 0) {
            console.log('Adding missing columns to locations table...');
            
            try {
                for (const [column, addStatement] of missingColumns) {
                    console.log(`Adding column: ${column}`);
                    await dbQuery(`ALTER TABLE locations ${addStatement}`);
                }
                
                console.log('✓ Missing columns added successfully');
            } catch (error) {
                console.error('Error adding columns:', error);
                throw error;
            }
        } else {
            console.log('✓ All required columns already exist');
        }
    } catch (error) {
        console.error('Error checking/adding columns:', error);
    }
}

// FIXED: Update location schema for PostgreSQL
async function updateLocationSchemaPostgres() {
    try {
        console.log('Updating location schema with new fields...');
        
        // Check if new columns exist
        const columns = await dbQuery(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'locations'
        `);
        
        const existingColumns = columns.rows.map(col => col.column_name);
        const newColumns = [
            'contact',
            'operating_hours', 
            'fuel_types',
            'services_offered',
            'description'
        ];
        
        for (const column of newColumns) {
            if (!existingColumns.includes(column)) {
                console.log(`Adding column: ${column}`);
                let columnType = 'VARCHAR(500)';
                if (column === 'description') {
                    columnType = 'TEXT';
                }
                
                await dbQuery(`
                    ALTER TABLE locations 
                    ADD COLUMN ${column} ${columnType}
                `);
            }
        }
        
        console.log('✓ Location schema updated successfully');
    } catch (error) {
        console.error('Error updating location schema:', error);
    }
}

async function initializeDatabase() {
    try {
        pool = new Pool(DB_CONFIG);

        // Simple connectivity check
        const res = await pool.query('SELECT NOW()');
        console.log('✓ Connected to Postgres database:', DB_CONFIG.database, 'Server time:', res.rows[0].now);

        // Check and add missing columns for archive functionality
        await addMissingColumnsPostgres();
        
    } catch (error) {
        console.error('Database initialization failed:', error);
        process.exit(1);
    }
}

// FIXED: Optional authentication middleware
function optionalAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                req.user = user;
            }
        });
    }
    next();
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Middleware to verify admin JWT token
function authenticateAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || !user.isAdmin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        req.user = user;
        next();
    });
}

// FIXED: Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// User registration
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const results = (await dbQuery('SELECT id FROM users WHERE email = $1', [email])).rows;
        if (results.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const insertResult = await dbQuery(
            'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
            [name, email, hashedPassword]
        );

        const userId = insertResult.rows[0].id;

        const token = jwt.sign(
            { id: userId, email, name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: userId, name, email }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const results = (await dbQuery('SELECT * FROM users WHERE email = $1', [email])).rows;
        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }
        
        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email, name: user.name },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Forgot password
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        const results = (await dbQuery('SELECT id FROM users WHERE email = $1', [email])).rows;
        if (results.length === 0) {
            return res.json({ message: 'If the email exists, a reset code has been sent' });
        }
        
        const resetToken = crypto.randomInt(100000, 999999).toString();
        const resetTokenExpiry = new Date(Date.now() + 1 * 60 * 60 * 1000);
        
        await dbQuery(
            'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
            [resetToken, resetTokenExpiry, email]
        );
        
        console.log(`Password reset token for ${email}: ${resetToken}`);

        // Try to send email if transporter available
        if (mailTransporter) {
            try {
                await mailTransporter.sendMail({
                    from: SMTP_FROM,
                    to: email,
                    subject: 'MOONRIDER Password Reset Code',
                    text: `Your password reset code is: ${resetToken}. It expires in 1 hour. If you did not request this, ignore this email.`,
                    html: `<p>Your password reset code is: <strong>${resetToken}</strong></p><p>This code expires in 1 hour.</p>`
                });
            } catch (mailErr) {
                console.error('Failed to send reset email:', mailErr);
                // Do not expose mail errors to the client; fall back to logging
            }
        } else {
            // Fallback: already logged the code to console above
        }

        res.json({ 
            message: 'If the email exists, a reset code has been generated and sent if possible'
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        
        if (!email || !code || !newPassword) {
            return res.status(400).json({ error: 'Email, code, and new password are required' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        
        const results = (await dbQuery(
            'SELECT id, reset_token_expiry FROM users WHERE email = $1 AND reset_token = $2',
            [email, code]
        )).rows;
        
        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired reset code' });
        }
        
        const user = results[0];
        if (new Date(user.reset_token_expiry) < new Date()) {
            return res.status(400).json({ error: 'Reset code has expired' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await dbQuery(
            'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE email = $2',
            [hashedPassword, email]
        );
        
        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin login
app.post('/api/admin-login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        const results = (await dbQuery('SELECT * FROM admins WHERE username = $1', [username])).rows;
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const admin = results[0];
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: admin.id, username: admin.username, isAdmin: true },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Admin login successful',
            token,
            admin: { id: admin.id, username: admin.username }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all locations - UPDATED with new fields
app.get('/api/locations', async (req, res) => {
    try {
        const { type } = req.query;
        
        let query = `
            SELECT 
                id, name, type, lat, lng, address, 
                contact, operating_hours, fuel_types, services_offered,
                description, image, views, visits, created_at
            FROM locations 
            WHERE is_archived = FALSE
        `;
        let params = [];
        
        if (type && type !== 'all') {
            query += ' AND type = $1';
            params.push(type);
        }
        
        const locations = (await dbQuery(query, params)).rows;

        res.json({ 
            locations: locations.map(loc => ({
                ...loc,
                lat: parseFloat(loc.lat),
                lng: parseFloat(loc.lng)
            }))
        });
    } catch (error) {
        console.error('Get locations error:', error);
        res.status(500).json({ error: 'Failed to fetch locations' });
    }
});

// NEW: Get locations for admin panel
app.get('/api/admin/locations', authenticateAdmin, async (req, res) => {
    try {
        const { type } = req.query;
        
        let query = `
            SELECT * FROM locations 
            WHERE is_archived = FALSE
        `;
        let params = [];
        
        if (type && type !== 'all') {
            // Handle both frontend and backend type names
            let dbType = type;
            if (type === 'station') dbType = 'gasoline';
            if (type === 'shop') dbType = 'repair';
            
            query += ' AND type = $1';
            params.push(dbType);
        }
        
        const locations = (await dbQuery(query, params)).rows;

        res.json({ 
            locations: locations.map(loc => ({
                ...loc,
                lat: parseFloat(loc.lat),
                lng: parseFloat(loc.lng)
            }))
        });
    } catch (error) {
        console.error('Get admin locations error:', error);
        res.status(500).json({ error: 'Failed to fetch locations' });
    }
});

// Get user favorites
app.get('/api/favorites', authenticateToken, async (req, res) => {
    try {
        const results = (await dbQuery(
            'SELECT location_id FROM favorites WHERE user_id = $1',
            [req.user.id]
        )).rows;
        res.json(results.map(row => ({ location_id: row.location_id })));
    } catch (error) {
        console.error('Get favorites error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Add to favorites
app.post('/api/favorites', authenticateToken, async (req, res) => {
    try {
        const { location_id } = req.body;
        await dbQuery(
            'INSERT INTO favorites (user_id, location_id) VALUES ($1, $2)',
            [req.user.id, location_id]
        );
        res.json({ message: 'Added to favorites' });
    } catch (error) {
        // Postgres duplicate key error is 23505. Keep MySQL code for compatibility.
        if (error.code === '23505' || error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Already in favorites' });
        }
        console.error('Add favorite error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Remove from favorites
app.delete('/api/favorites/:locationId', authenticateToken, async (req, res) => {
    try {
        const result = await dbQuery(
            'DELETE FROM favorites WHERE user_id = $1 AND location_id = $2',
            [req.user.id, req.params.locationId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Favorite not found' });
        }
        res.json({ message: 'Removed from favorites' });
    } catch (error) {
        console.error('Remove favorite error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Record location visit - FIXED to use optional auth
app.post('/api/locations/:id/visit', optionalAuth, async (req, res) => {
    try {
        const userId = req.user ? req.user.id : null;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(replacePlaceholders('INSERT INTO location_visits (user_id, location_id) VALUES (?, ?)'), [userId, req.params.id]);
            await client.query(replacePlaceholders('UPDATE locations SET visits = visits + 1 WHERE id = ?'), [req.params.id]);
            await client.query('COMMIT');
            res.json({ message: 'Visit recorded' });
        } catch (err) {
            try { await client.query('ROLLBACK'); } catch (e) { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Record visit error:', error);
        // If the error looks like a transient connection reset, try to recreate the pool once
        if (error && (error.code === 'ECONNRESET' || error.errno === 'ECONNRESET')) {
            console.warn('Transient DB connection error detected, recreating pool and retrying on next request');
            try { await recreatePool(); } catch (e) { console.error('Failed to recreate DB pool:', e); }
        }
        res.status(500).json({ error: 'Database error' });
    }
});

// Record location view
app.post('/api/locations/:id/view', optionalAuth, async (req, res) => {
    try {
        const userId = req.user ? req.user.id : null;
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(replacePlaceholders('INSERT INTO location_views (user_id, location_id) VALUES (?, ?)'), [userId, req.params.id]);
            await client.query(replacePlaceholders('UPDATE locations SET views = views + 1 WHERE id = ?'), [req.params.id]);
            await client.query('COMMIT');
            res.json({ message: 'View recorded' });
        } catch (err) {
            try { await client.query('ROLLBACK'); } catch (e) { /* ignore */ }
            throw err;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('Record view error:', error);
        if (error && (error.code === 'ECONNRESET' || error.errno === 'ECONNRESET')) {
            console.warn('Transient DB connection error detected, recreating pool');
            try { await recreatePool(); } catch (e) { console.error('Failed to recreate DB pool:', e); }
        }
        res.status(500).json({ error: 'Database error' });
    }
});

// Get reviews for a location
app.get('/api/locations/:id/reviews', async (req, res) => {
    try {
        const locationId = req.params.id;
        
        const reviews = (await dbQuery(`
            SELECT r.*, u.name as user_name 
            FROM reviews r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.location_id = $1 
            ORDER BY r.created_at DESC
        `, [locationId])).rows;
        
        const avgResult = (await dbQuery(`
            SELECT AVG(rating) as average_rating, COUNT(*) as review_count 
            FROM reviews 
            WHERE location_id = $1
        `, [locationId])).rows;
        
        const averageRating = avgResult[0].average_rating ? parseFloat(avgResult[0].average_rating).toFixed(1) : 0;
        const reviewCount = avgResult[0].review_count;
        
        res.json({
            reviews: reviews.map(review => ({
                id: review.id,
                user_id: review.user_id,
                user_name: review.user_name,
                location_id: review.location_id,
                rating: review.rating,
                comment: review.comment,
                created_at: review.created_at
            })),
            average_rating: parseFloat(averageRating),
            review_count: reviewCount
        });
    } catch (error) {
        console.error('Get reviews error:', error);
        res.status(500).json({ error: 'Failed to fetch reviews' });
    }
});

// Submit a review
app.post('/api/locations/:id/reviews', authenticateToken, async (req, res) => {
    try {
        const locationId = req.params.id;
        const { rating, comment } = req.body;
        const userId = req.user.id;
        
        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Rating must be between 1 and 5' });
        }
        
        const existingReview = (await dbQuery('SELECT id FROM reviews WHERE user_id = $1 AND location_id = $2', [userId, locationId])).rows;

        if (existingReview.length > 0) {
            await dbQuery('UPDATE reviews SET rating = $1, comment = $2 WHERE user_id = $3 AND location_id = $4', [rating, comment, userId, locationId]);
            
            return res.json({ message: 'Review updated successfully' });
        }
        
        await dbQuery(
            'INSERT INTO reviews (user_id, location_id, rating, comment) VALUES ($1, $2, $3, $4)',
            [userId, locationId, rating, comment]
        );
        
        res.status(201).json({ message: 'Review submitted successfully' });
    } catch (error) {
        console.error('Submit review error:', error);
        res.status(500).json({ error: 'Failed to submit review' });
    }
});

// Admin: Get statistics
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
    try {
    const userCount = (await dbQuery('SELECT COUNT(*) as count FROM users')).rows;
    const stationCount = (await dbQuery('SELECT COUNT(*) as count FROM locations WHERE type = $1 AND is_archived = FALSE', ['gasoline'])).rows;
    const shopCount = (await dbQuery('SELECT COUNT(*) as count FROM locations WHERE type = $1 AND is_archived = FALSE', ['repair'])).rows;
    const visitCount = (await dbQuery('SELECT COUNT(*) as count FROM location_visits')).rows;

    const locations = (await dbQuery('SELECT * FROM locations WHERE is_archived = FALSE')).rows;

    const stations = locations.filter(loc => loc.type === 'gasoline');
    const repairShops = locations.filter(loc => loc.type === 'repair');
        
        res.json({
            totalStations: stationCount[0].count,
            totalRepairShops: shopCount[0].count,
            registeredUsers: userCount[0].count,
            totalVisits: visitCount[0].count,
            stations,
            repairShops
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin: Get single location
app.get('/api/admin/locations/:id', authenticateAdmin, async (req, res) => {
    try {
        const locationId = req.params.id;
        
        const location = (await dbQuery('SELECT * FROM locations WHERE id = $1', [locationId])).rows;

        if (location.length === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }

        const locationData = location[0];
        res.json({
            location: {
                id: locationData.id,
                name: locationData.name,
                type: locationData.type,
                lat: parseFloat(locationData.lat),
                lng: parseFloat(locationData.lng),
                address: locationData.address,
                contact: locationData.contact,
                operating_hours: locationData.operating_hours,
                fuel_types: locationData.fuel_types,
                services_offered: locationData.services_offered,
                description: locationData.description,
                image: locationData.image,
                views: locationData.views,
                visits: locationData.visits,
                is_archived: locationData.is_archived,
                created_at: locationData.created_at
            }
        });
    } catch (error) {
        console.error('Get location error:', error);
        res.status(500).json({ error: 'Failed to fetch location' });
    }
});

// Admin: Add location
app.post('/api/admin/locations', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        // When using multipart/form-data, multer populates req.body (strings) and req.file
        const {
            name,
            address,
            lat,
            lng,
            type,
            contact,
            operating_hours,
            fuel_types,
            services_offered,
            description
        } = req.body;

        if (!name || !address || !lat || !lng || !type) {
            return res.status(400).json({ error: 'All required fields are missing' });
        }

        // Accept frontend synonyms: 'station' -> 'gasoline', 'shop' -> 'repair'
        let normalizedType = type;
        if (type === 'station') normalizedType = 'gasoline';
        if (type === 'shop') normalizedType = 'repair';

        if (!['gasoline', 'repair'].includes(normalizedType)) {
            return res.status(400).json({ error: 'Type must be either "gasoline" or "repair"' });
        }

        const latNum = parseFloat(lat);
        const lngNum = parseFloat(lng);
        if (isNaN(latNum) || isNaN(lngNum)) {
            return res.status(400).json({ error: 'Invalid coordinates' });
        }

        // If an image file was uploaded, multer provides req.file
        let imageUrl = null;
        if (req.file) {
            imageUrl = `/uploads/${req.file.filename}`;
        }

        const result = await dbQuery(
            `INSERT INTO locations (name, address, lat, lng, type, contact, operating_hours, fuel_types, services_offered, description, image) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
            [name, address, latNum, lngNum, normalizedType, contact, operating_hours, fuel_types, services_offered, description || null, imageUrl]
        );

        const newId = result.rows[0].id;
        const newLocation = (await dbQuery('SELECT * FROM locations WHERE id = $1', [newId])).rows[0];

        res.status(201).json({ 
            message: 'Location added successfully',
            location: newLocation,
            id: newId
        });
    } catch (error) {
        console.error('Add location error:', error);
        res.status(500).json({ error: 'Failed to add location' });
    }
});

// Admin: Update location
app.put('/api/admin/locations/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const locationId = req.params.id;
        const {
            name,
            address,
            lat,
            lng,
            type,
            contact,
            operating_hours,
            fuel_types,
            services_offered,
            description
        } = req.body;

        if (!name || !address || !lat || !lng || !type) {
            return res.status(400).json({ error: 'All required fields are missing' });
        }

        // Accept frontend synonyms: 'station' -> 'gasoline', 'shop' -> 'repair'
        let normalizedType = type;
        if (type === 'station') normalizedType = 'gasoline';
        if (type === 'shop') normalizedType = 'repair';

        if (!['gasoline', 'repair'].includes(normalizedType)) {
            return res.status(400).json({ error: 'Type must be either "gasoline" or "repair"' });
        }

        const latNum = parseFloat(lat);
        const lngNum = parseFloat(lng);
        if (isNaN(latNum) || isNaN(lngNum)) {
            return res.status(400).json({ error: 'Invalid coordinates' });
        }

        // If an image file was uploaded, multer provides req.file
        let imageUrl = null;
        if (req.file) {
            imageUrl = `/uploads/${req.file.filename}`;
        }

        // Build update query; include image if provided
        let query = `UPDATE locations SET 
                name = $1, address = $2, lat = $3, lng = $4, type = $5,
                contact = $6, operating_hours = $7, fuel_types = $8, services_offered = $9, description = $10`;
        const params = [name, address, latNum, lngNum, normalizedType, contact, operating_hours, fuel_types, services_offered, description || null];

        if (imageUrl) {
            query += `, image = $11`;
            params.push(imageUrl);
            query += ` WHERE id = $12`;
            params.push(locationId);
        } else {
            query += ` WHERE id = $11`;
            params.push(locationId);
        }

        const result = await dbQuery(query, params);

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }

        res.json({ 
            message: 'Location updated successfully'
        });
    } catch (error) {
        console.error('Update location error:', error);
        res.status(500).json({ error: 'Failed to update location' });
    }
});

// FIXED: Helper functions for archive/unarchive - PostgreSQL compatible
async function archiveLocationHandler(req, res) {
    try {
        const locationId = req.params.id;
        const result = await dbQuery(
            'UPDATE locations SET is_archived = TRUE, archived_at = CURRENT_TIMESTAMP WHERE id = $1',
            [locationId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }

        res.json({ message: 'Location archived successfully' });
    } catch (error) {
        console.error('Archive location error:', error);
        res.status(500).json({ error: 'Failed to archive location' });
    }
}

async function unarchiveLocationHandler(req, res) {
    try {
        const locationId = req.params.id;
        const result = await dbQuery(
            'UPDATE locations SET is_archived = FALSE, archived_at = NULL WHERE id = $1',
            [locationId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }

        res.json({ message: 'Location unarchived successfully' });
    } catch (error) {
        console.error('Unarchive location error:', error);
        res.status(500).json({ error: 'Failed to unarchive location' });
    }
}

// Archive location (both PUT and POST)
app.put('/api/admin/locations/:id/archive', authenticateAdmin, archiveLocationHandler);
app.post('/api/admin/locations/:id/archive', authenticateAdmin, archiveLocationHandler);

// Unarchive location (both PUT and POST)
app.put('/api/admin/locations/:id/unarchive', authenticateAdmin, unarchiveLocationHandler);
app.post('/api/admin/locations/:id/unarchive', authenticateAdmin, unarchiveLocationHandler);

// FIXED: Admin: Get archived locations - PostgreSQL compatible
app.get('/api/admin/locations/archived', authenticateAdmin, async (req, res) => {
    try {
        const { type } = req.query;

        let query, params;

        if (type && (type === 'gasoline' || type === 'repair')) {
            query = 'SELECT * FROM locations WHERE is_archived = TRUE AND type = $1';
            params = [type];
        } else if (type === 'station') {
            query = 'SELECT * FROM locations WHERE is_archived = TRUE AND type = $1';
            params = ['gasoline'];
        } else if (type === 'shop') {
            query = 'SELECT * FROM locations WHERE is_archived = TRUE AND type = $1';
            params = ['repair'];
        } else {
            query = 'SELECT * FROM locations WHERE is_archived = TRUE';
            params = [];
        }

        const result = await dbQuery(query, params);
        const locations = result.rows;

        // For backward compatibility with frontend
        if (type && (type === 'gasoline' || type === 'station')) {
            return res.json({ 
                locations: locations,
                archivedStations: locations 
            });
        } else if (type && (type === 'repair' || type === 'shop')) {
            return res.json({ 
                locations: locations,
                archivedShops: locations 
            });
        }

        // If no specific type requested, return both
        const archivedStations = locations.filter(loc => loc.type === 'gasoline');
        const archivedShops = locations.filter(loc => loc.type === 'repair');

        res.json({
            locations: locations,
            archivedStations,
            archivedShops
        });
    } catch (error) {
        console.error('Get archived locations error:', error);
        res.status(500).json({ error: 'Failed to fetch archived locations' });
    }
});

// Admin: Upload location image
app.post('/api/admin/locations/:id/image', authenticateAdmin, upload.single('image'), async (req, res) => {
    try {
        const locationId = req.params.id;

        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        const imageUrl = `/uploads/${req.file.filename}`;

        const result = await dbQuery(
            'UPDATE locations SET image = $1 WHERE id = $2',
            [imageUrl, locationId]
        );

        if (result.rowCount === 0) {
            // Delete the uploaded file if location not found
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ error: 'Location not found' });
        }

        res.json({ 
            message: 'Image uploaded successfully',
            imageUrl: imageUrl
        });
    } catch (error) {
        console.error('Upload image error:', error);
        // Delete the uploaded file if there was an error
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Failed to upload image' });
    }
});

// Admin: Delete location (permanent deletion)
app.delete('/api/admin/locations/:id', authenticateAdmin, async (req, res) => {
    try {
        const locationId = req.params.id;

        // First get the location to check if it has an image
        const location = (await dbQuery('SELECT image FROM locations WHERE id = $1', [locationId])).rows;

        const client = await pool.connect();
        await client.query('BEGIN');

        try {
            await client.query(replacePlaceholders('DELETE FROM reviews WHERE location_id = ?'), [locationId]);
            await client.query(replacePlaceholders('DELETE FROM favorites WHERE location_id = ?'), [locationId]);
            await client.query(replacePlaceholders('DELETE FROM location_visits WHERE location_id = ?'), [locationId]);
            await client.query(replacePlaceholders('DELETE FROM location_views WHERE location_id = ?'), [locationId]);
            
            const result = await client.query(replacePlaceholders('DELETE FROM locations WHERE id = ? RETURNING id'), [locationId]);
            
            if (result.rowCount === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Location not found' });
            }

            await client.query('COMMIT');

            // Delete the image file if it exists
            if (location.length > 0 && location[0].image) {
                const imagePath = path.join(__dirname, location[0].image);
                if (fs.existsSync(imagePath)) {
                    fs.unlinkSync(imagePath);
                }
            }

            res.json({ message: 'Location deleted successfully' });

        } catch (transactionError) {
            await client.query('ROLLBACK');
            throw transactionError;
        } finally {
            client.release();
        }

    } catch (error) {
        console.error('Delete location error:', error);
        res.status(500).json({ error: 'Failed to delete location' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Multer error handling
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
        }
    }
    next(err);
});

// Start server
initializeDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('='.repeat(50));
        console.log(`✓ Server running on http://localhost:${PORT}`);
        console.log(`✓ Admin Panel: http://localhost:${PORT}/admin.html`);
        console.log(`✓ Main App: http://localhost:${PORT}/index.html`);
        console.log('='.repeat(50));
        console.log('Admin Credentials:');
        console.log('  Username: admin');
        console.log('  Password: admin123');
        console.log('='.repeat(50));
    });
}).catch(err => {
    console.error('Failed to start server:', err);
    process.exit(1);
});

// Global handlers for unexpected errors
process.on('unhandledRejection', (reason, p) => {
    console.error('Unhandled Rejection at:', p, 'reason:', reason);
    if (reason && (reason.code === 'ECONNRESET' || reason.errno === 'ECONNRESET')) {
        console.warn('Unhandled rejection due to ECONNRESET — recreating pool');
        recreatePool().catch(e => console.error('Failed to recreate pool after unhandledRejection:', e));
    }
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    if (err && (err.code === 'ECONNRESET' || err.errno === 'ECONNRESET')) {
        console.warn('Uncaught exception ECONNRESET — recreating pool');
        recreatePool().catch(e => console.error('Failed to recreate pool after uncaughtException:', e));
    }
    // Do not exit automatically in dev — allow process to continue if possible
});
