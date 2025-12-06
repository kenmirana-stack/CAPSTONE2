require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

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

// Configure email transporter (SMTP) for Gmail
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587;
const SMTP_USER = process.env.SMTP_USER || 'kengotladeramirana@gmail.com';
const SMTP_PASS = process.env.SMTP_PASS || 'vjiptextuwtetwom'; // Use Gmail App Password
const SMTP_FROM = process.env.SMTP_FROM || 'kengotladeramirana@gmail.com';

let mailTransporter = null;
if (SMTP_USER && SMTP_PASS && SMTP_PASS.length > 5) {
    mailTransporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465, // true for 465, false for other ports
        auth: {
            user: SMTP_USER,
            pass: SMTP_PASS
        },
        tls: {
            rejectUnauthorized: false
        }
    });
    
    // Verify transporter with better error handling
    mailTransporter.verify().then(() => {
        console.log('✓ Gmail SMTP transporter verified and ready');
        console.log('✓ From:', SMTP_FROM);
    }).catch(err => {
        console.error('❌ Gmail SMTP verification failed:', err.message);
        console.log('⚠ Please check:');
        console.log('  - Gmail address and App Password in .env file');
        console.log('  - 2-Step Verification is enabled in Google Account');
        console.log('  - App Password is generated for "Mail"');
    });
} else {
    console.log('⚠ Gmail SMTP not configured - check .env file');
    console.log('  - SMTP_USER:', SMTP_USER ? '✓ set' : '✗ missing');
    console.log('  - SMTP_PASS:', SMTP_PASS ? `✓ set (${SMTP_PASS.length} chars)` : '✗ missing');
    console.log('  - SMTP_FROM:', SMTP_FROM);
    console.log('Forgot password emails will be logged to console only');
}

// Database connection pool and config (Postgres)
let pool; //FIXED: Use DATABASE_URL for Render and increase connection timeout
const DB_CONFIG = process.env.DATABASE_URL ? {
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    },
    connectionTimeoutMillis: 60000, // 60 second timeout for cloud environments
    idleTimeoutMillis: 30000,
    max: 10,
    statement_timeout: 60000
} : {
    host: process.env.DB_HOST || 'localhost', // Fallback for local development
    port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'bulan_locator',
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 60000,
    statement_timeout: 60000,
    ssl: process.env.DB_SSL === 'false' ? false : (process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined)
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

// Check and create all required tables
async function checkAllTables() {
    try {
        console.log('Checking all required tables...');
        
        // Check and create users table
        const usersCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
            );
        `);
        
        if (!usersCheck.rows[0].exists) {
            console.log('Creating users table...');
            await dbQuery(`
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    reset_token VARCHAR(100),
                    reset_token_expiry TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Users table created');
        }
        
        // Check and create locations table
        const locationsCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'locations'
            );
        `);
        
        if (!locationsCheck.rows[0].exists) {
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
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Locations table created');
        }
        
        // Check and create admins table
        const adminsCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'admins'
            );
        `);
        
        if (!adminsCheck.rows[0].exists) {
            console.log('Creating admins table...');
            await dbQuery(`
                CREATE TABLE admins (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            
            // Create default admin account
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await dbQuery(
                'INSERT INTO admins (username, password) VALUES ($1, $2)',
                ['admin', hashedPassword]
            );
            
            console.log('✓ Admins table created with default admin (username: admin, password: admin123)');
        }
        
        // Check and create favorites table
        const favoritesCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'favorites'
            );
        `);
        
        if (!favoritesCheck.rows[0].exists) {
            console.log('Creating favorites table...');
            await dbQuery(`
                CREATE TABLE favorites (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, location_id)
                )
            `);
            console.log('✓ Favorites table created');
        }
        
        // Check and create reviews table
        const reviewsCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'reviews'
            );
        `);
        
        if (!reviewsCheck.rows[0].exists) {
            console.log('Creating reviews table...');
            await dbQuery(`
                CREATE TABLE reviews (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                    comment TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, location_id)
                )
            `);
            console.log('✓ Reviews table created');
        }
        
        // Check and create location_visits table
        const visitsCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'location_visits'
            );
        `);
        
        if (!visitsCheck.rows[0].exists) {
            console.log('Creating location_visits table...');
            await dbQuery(`
                CREATE TABLE location_visits (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Location visits table created');
        }
        
        // Check and create location_views table
        const viewsCheck = await dbQuery(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'location_views'
            );
        `);
        
        if (!viewsCheck.rows[0].exists) {
            console.log('Creating location_views table...');
            await dbQuery(`
                CREATE TABLE location_views (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
            console.log('✓ Location views table created');
        }
        
        console.log('✓ All required tables are ready');
        
    } catch (error) {
        console.error('Error checking/creating tables:', error);
    }
}

// Create indexes for better performance
async function createIndexes() {
    try {
        console.log('Creating indexes for better performance...');
        
        // Index for locations type queries
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_locations_type ON locations(type)');
        
        // Index for location searches
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_locations_name ON locations(name)');
        
        // Index for user-specific data
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_favorites_user ON favorites(user_id)');
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_reviews_user ON reviews(user_id)');
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_reviews_location ON reviews(location_id)');
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_visits_location ON location_visits(location_id)');
        await dbQuery('CREATE INDEX IF NOT EXISTS idx_views_location ON location_views(location_id)');
        
        console.log('✓ Database indexes created');
    } catch (error) {
        console.error('Error creating indexes:', error);
    }
}

// Add sample data for testing
async function addSampleData() {
    try {
        // Check if there are already locations
        const countResult = await dbQuery('SELECT COUNT(*) as count FROM locations');
        const locationCount = parseInt(countResult.rows[0].count);
        
        if (locationCount === 0) {
            console.log('Adding sample data...');
            
            // Sample gas stations
            const stations = [
                {
                    name: 'Shell Station Main',
                    type: 'gasoline',
                    address: '123 Main Street, Manila',
                    lat: 14.5995,
                    lng: 120.9842,
                    contact: '09171234567',
                    operating_hours: '24/7',
                    fuel_types: 'Diesel, Premium, Unleaded',
                    views: 150,
                    visits: 45
                },
                {
                    name: 'Petron Express',
                    type: 'gasoline',
                    address: '456 Quezon Avenue, Quezon City',
                    lat: 14.6500,
                    lng: 121.0300,
                    contact: '09221234567',
                    operating_hours: '6:00 AM - 10:00 PM',
                    fuel_types: 'Diesel, Premium, Super',
                    views: 120,
                    visits: 30
                },
                {
                    name: 'Caltex Station',
                    type: 'gasoline',
                    address: '789 EDSA, Mandaluyong',
                    lat: 14.5800,
                    lng: 121.0400,
                    contact: '09331234567',
                    operating_hours: '5:00 AM - 11:00 PM',
                    fuel_types: 'Diesel, Premium, Unleaded, Gasoline',
                    views: 95,
                    visits: 28
                }
            ];
            
            // Sample repair shops
            const shops = [
                {
                    name: 'Quick Fix Auto Repair',
                    type: 'repair',
                    address: '789 Makati Avenue, Makati',
                    lat: 14.5500,
                    lng: 121.0200,
                    contact: '09441234567',
                    operating_hours: '8:00 AM - 8:00 PM',
                    services_offered: 'Oil Change, Brake Repair, Tire Service',
                    views: 90,
                    visits: 25
                },
                {
                    name: 'Precision Auto Care',
                    type: 'repair',
                    address: '321 Ortigas Center, Pasig',
                    lat: 14.5900,
                    lng: 121.0600,
                    contact: '09551234567',
                    operating_hours: '7:00 AM - 7:00 PM',
                    services_offered: 'Engine Repair, Electrical System, Aircon Service',
                    views: 75,
                    visits: 18
                }
            ];
            
            // Insert stations
            for (const station of stations) {
                await dbQuery(
                    `INSERT INTO locations (name, type, address, lat, lng, contact, operating_hours, fuel_types, services_offered, views, visits)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                    [
                        station.name, station.type, station.address, station.lat, station.lng,
                        station.contact, station.operating_hours, station.fuel_types, '', 
                        station.views, station.visits
                    ]
                );
            }
            
            // Insert shops
            for (const shop of shops) {
                await dbQuery(
                    `INSERT INTO locations (name, type, address, lat, lng, contact, operating_hours, fuel_types, services_offered, views, visits)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                    [
                        shop.name, shop.type, shop.address, shop.lat, shop.lng,
                        shop.contact, shop.operating_hours, '', shop.services_offered,
                        shop.views, shop.visits
                    ]
                );
            }
            
            console.log('✓ Sample data added successfully');
        }
    } catch (error) {
        console.error('Error adding sample data:', error);
    }
}

// FIXED: Add missing columns for PostgreSQL
async function addMissingColumnsPostgres() {
    try {
        console.log('Checking for missing columns in PostgreSQL...');
        
        // Get all existing columns
        const columnsCheck = await dbQuery(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_schema = 'public' 
            AND table_name = 'locations'
        `);
        
        const existingColumns = columnsCheck.rows.map(row => row.column_name);
        const requiredColumns = {
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
        console.log('🔄 Initializing database connection...');
        console.log('Using DATABASE_URL:', process.env.DATABASE_URL ? '✓ Yes' : '✗ No (using individual DB_* vars)');
        
        pool = new Pool(DB_CONFIG);

        // Simple connectivity check with timeout
        const res = await Promise.race([
            pool.query('SELECT NOW()'),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Database connection timeout after 15s')), 15000))
        ]);
        
        console.log('✓ Connected to Postgres database - Server time:', res.rows[0].now);

        // Check and create all required tables
        await checkAllTables();
        
        // Create indexes for performance
        await createIndexes();
        
        // Check and add missing columns to locations
        await addMissingColumnsPostgres();
        
        // Add sample data if empty
        await addSampleData();
        
    } catch (error) {
        console.error('❌ Database initialization failed:', error.message);
        console.error('\n🔧 Troubleshooting:');
        
        if (process.env.DATABASE_URL) {
            console.error('1. Check DATABASE_URL is valid: ' + (process.env.DATABASE_URL.substring(0, 30) + '...'));
        } else {
            console.error('1. DB_HOST:', process.env.DB_HOST);
            console.error('2. DB_PORT:', process.env.DB_PORT);
            console.error('3. DB_NAME:', process.env.DB_NAME);
        }
        
        console.error('\n2. Verify Postgres is running and accessible');
        console.error('3. Check network/firewall settings');
        console.error('\nWill retry on next request...\n');
        
        // Don't exit - allow server to start and retry on first request
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
app.get('/api/health', async (req, res) => {
    try {
        // Try to verify database connection
        if (!pool) {
            return res.status(503).json({ 
                status: 'DEGRADED',
                message: 'Database pool not initialized',
                database: 'NOT CONNECTED'
            });
        }
        
        const result = await Promise.race([
            pool.query('SELECT NOW()'),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000))
        ]);
        
        res.json({ 
            status: 'OK', 
            message: 'Server is running',
            database: 'CONNECTED',
            timestamp: result.rows[0].now
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'DEGRADED', 
            message: 'Database connection failed',
            database: 'ERROR: ' + error.message,
            error: error.message
        });
    }
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

// Get all locations - UPDATED without archive filters
app.get('/api/locations', async (req, res) => {
    try {
        const { type } = req.query;
        
        let query = `
            SELECT 
                id, name, type, lat, lng, address, 
                contact, operating_hours, fuel_types, services_offered,
                description, image, views, visits, created_at
            FROM locations 
            WHERE 1=1
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

// Get locations for admin panel
app.get('/api/admin/locations', authenticateAdmin, async (req, res) => {
    try {
        const { type } = req.query;
        
        let query = `
            SELECT * FROM locations 
            WHERE 1=1
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
        const stationCount = (await dbQuery('SELECT COUNT(*) as count FROM locations WHERE type = $1', ['gasoline'])).rows;
        const shopCount = (await dbQuery('SELECT COUNT(*) as count FROM locations WHERE type = $1', ['repair'])).rows;
        const visitCount = (await dbQuery('SELECT COUNT(*) as count FROM location_visits')).rows;

        const locations = (await dbQuery('SELECT * FROM locations')).rows;

        const stations = locations.filter(loc => loc.type === 'gasoline');
        const repairShops = locations.filter(loc => loc.type === 'repair');
        
        res.json({
            totalStations: parseInt(stationCount[0].count),
            totalRepairShops: parseInt(shopCount[0].count),
            registeredUsers: parseInt(userCount[0].count),
            totalVisits: parseInt(visitCount[0].count),
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
                views: locationData.views,
                visits: locationData.visits,
                created_at: locationData.created_at
            }
        });
    } catch (error) {
        console.error('Get location error:', error);
        res.status(500).json({ error: 'Failed to fetch location' });
    }
});

// Admin: Add location with enhanced validation
app.post('/api/admin/locations', authenticateAdmin, async (req, res) => {
    try {
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

        // Validation
        const errors = [];
        
        if (!name || name.trim().length < 2) {
            errors.push('Name must be at least 2 characters');
        }
        
        if (!address || address.trim().length < 5) {
            errors.push('Address must be at least 5 characters');
        }
        
        if (!lat || !lng) {
            errors.push('Coordinates are required');
        }
        
        const latNum = parseFloat(lat);
        const lngNum = parseFloat(lng);
        if (isNaN(latNum) || isNaN(lngNum)) {
            errors.push('Invalid coordinates');
        } else {
            if (latNum < -90 || latNum > 90) {
                errors.push('Latitude must be between -90 and 90');
            }
            if (lngNum < -180 || lngNum > 180) {
                errors.push('Longitude must be between -180 and 180');
            }
        }
        
        if (!type) {
            errors.push('Type is required');
        }
        
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(', ') });
        }

        // Accept frontend synonyms: 'station' -> 'gasoline', 'shop' -> 'repair'
        let normalizedType = type;
        if (type === 'station') normalizedType = 'gasoline';
        if (type === 'shop') normalizedType = 'repair';

        if (!['gasoline', 'repair'].includes(normalizedType)) {
            return res.status(400).json({ error: 'Type must be either "gasoline" or "repair"' });
        }

        // Type-specific validation
        if (normalizedType === 'gasoline' && (!fuel_types || fuel_types.trim().length < 2)) {
            errors.push('Fuel types are required for gas stations');
        }
        
        if (normalizedType === 'repair' && (!services_offered || services_offered.trim().length < 2)) {
            errors.push('Services offered are required for repair shops');
        }
        
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(', ') });
        }

        const result = await dbQuery(
            `INSERT INTO locations (name, address, lat, lng, type, contact, operating_hours, fuel_types, services_offered, description) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
            [
                name.trim(),
                address.trim(),
                latNum,
                lngNum,
                normalizedType,
                contact ? contact.trim() : null,
                operating_hours ? operating_hours.trim() : null,
                fuel_types ? fuel_types.trim() : null,
                services_offered ? services_offered.trim() : null,
                description ? description.trim() : null
            ]
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

// Admin: Update location with enhanced validation
app.put('/api/admin/locations/:id', authenticateAdmin, async (req, res) => {
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

        // Validation
        const errors = [];
        
        if (!name || name.trim().length < 2) {
            errors.push('Name must be at least 2 characters');
        }
        
        if (!address || address.trim().length < 5) {
            errors.push('Address must be at least 5 characters');
        }
        
        if (!lat || !lng) {
            errors.push('Coordinates are required');
        }
        
        const latNum = parseFloat(lat);
        const lngNum = parseFloat(lng);
        if (isNaN(latNum) || isNaN(lngNum)) {
            errors.push('Invalid coordinates');
        } else {
            if (latNum < -90 || latNum > 90) {
                errors.push('Latitude must be between -90 and 90');
            }
            if (lngNum < -180 || lngNum > 180) {
                errors.push('Longitude must be between -180 and 180');
            }
        }
        
        if (!type) {
            errors.push('Type is required');
        }
        
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(', ') });
        }

        // Accept frontend synonyms: 'station' -> 'gasoline', 'shop' -> 'repair'
        let normalizedType = type;
        if (type === 'station') normalizedType = 'gasoline';
        if (type === 'shop') normalizedType = 'repair';

        if (!['gasoline', 'repair'].includes(normalizedType)) {
            return res.status(400).json({ error: 'Type must be either "gasoline" or "repair"' });
        }

        // Type-specific validation
        if (normalizedType === 'gasoline' && (!fuel_types || fuel_types.trim().length < 2)) {
            errors.push('Fuel types are required for gas stations');
        }
        
        if (normalizedType === 'repair' && (!services_offered || services_offered.trim().length < 2)) {
            errors.push('Services offered are required for repair shops');
        }
        
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(', ') });
        }

        // Check if location exists
        const existingLocation = (await dbQuery('SELECT id FROM locations WHERE id = $1', [locationId])).rows;
        if (existingLocation.length === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }

        // Build update query
        let query = `UPDATE locations SET 
                name = $1, address = $2, lat = $3, lng = $4, type = $5,
                contact = $6, operating_hours = $7, fuel_types = $8, services_offered = $9, description = $10
                WHERE id = $11`;
        const params = [
            name.trim(),
            address.trim(),
            latNum,
            lngNum,
            normalizedType,
            contact ? contact.trim() : null,
            operating_hours ? operating_hours.trim() : null,
            fuel_types ? fuel_types.trim() : null,
            services_offered ? services_offered.trim() : null,
            description ? description.trim() : null,
            locationId
        ];

        const result = await dbQuery(query, params);

        res.json({ 
            message: 'Location updated successfully'
        });
    } catch (error) {
        console.error('Update location error:', error);
        res.status(500).json({ error: 'Failed to update location' });
    }
});

// Admin: Delete location (permanent deletion)
app.delete('/api/admin/locations/:id', authenticateAdmin, async (req, res) => {
    try {
        const locationId = req.params.id;
        
        // Check if location exists
        const existingLocation = (await dbQuery('SELECT id FROM locations WHERE id = $1', [locationId])).rows;
        if (existingLocation.length === 0) {
            return res.status(404).json({ error: 'Location not found' });
        }
        
        const result = await dbQuery('DELETE FROM locations WHERE id = $1', [locationId]);

        res.json({ 
            message: 'Location deleted successfully'
        });
    } catch (error) {
        console.error('Delete location error:', error);
        res.status(500).json({ error: 'Failed to delete location' });
    }
});

// Get nearby locations
app.get('/api/nearby', async (req, res) => {
    try {
        const { lat, lng, radius = 5, type } = req.query;
        
        if (!lat || !lng) {
            return res.status(400).json({ error: 'Latitude and longitude are required' });
        }
        
        const userLat = parseFloat(lat);
        const userLng = parseFloat(lng);
        const searchRadius = parseFloat(radius);
        
        if (isNaN(userLat) || isNaN(userLng)) {
            return res.status(400).json({ error: 'Invalid coordinates' });
        }
        
        // Calculate bounding box for approximate filtering
        const earthRadius = 6371; // kilometers
        const latDelta = searchRadius / earthRadius * (180 / Math.PI);
        const lngDelta = searchRadius / (earthRadius * Math.cos(userLat * Math.PI / 180)) * (180 / Math.PI);
        
        let query = `
            SELECT 
                id, name, type, lat, lng, address, 
                contact, operating_hours, fuel_types, services_offered,
                description, image, views, visits,
                (6371 * acos(cos(radians($1)) * cos(radians(lat)) * cos(radians(lng) - radians($2)) + sin(radians($1)) * sin(radians(lat)))) AS distance
            FROM locations 
            WHERE 
                lat BETWEEN $3 AND $4
                AND lng BETWEEN $5 AND $6
        `;
        
        let params = [
            userLat, userLng,
            userLat - latDelta, userLat + latDelta,
            userLng - lngDelta, userLng + lngDelta
        ];
        
        if (type && type !== 'all') {
            query += ' AND type = $7';
            params.push(type);
        }
        
        query += ' HAVING distance <= $8 ORDER BY distance LIMIT 20';
        params.push(searchRadius);
        
        const locations = (await dbQuery(query, params)).rows;
        
        res.json({ 
            locations: locations.map(loc => ({
                ...loc,
                lat: parseFloat(loc.lat),
                lng: parseFloat(loc.lng),
                distance: parseFloat(loc.distance).toFixed(2)
            }))
        });
    } catch (error) {
        console.error('Get nearby locations error:', error);
        res.status(500).json({ error: 'Failed to fetch nearby locations' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
initializeDatabase().catch(err => {
    console.warn('⚠️ Database initialization encountered issues - server starting anyway:', err.message);
}).finally(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('='.repeat(50));
        console.log(`✓ Server running on http://localhost:${PORT}`);
        console.log(`✓ Admin Panel: http://localhost:${PORT}/admin.html`);
        console.log(`✓ Main App: http://localhost:${PORT}/index.html`);
        console.log(`✓ Health Check: http://localhost:${PORT}/api/health`);
        console.log('='.repeat(50));
        console.log('Admin Credentials:');
        console.log('  Username: admin');
        console.log('  Password: admin123');
        console.log('='.repeat(50));
    });
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
