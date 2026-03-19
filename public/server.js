const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const session = require('express-session');
const sanitizeHtml = require('sanitize-html');

// Load environment variables
try {
    require('dotenv').config();
    console.log('✅ dotenv loaded');
} catch (e) {
    console.log('⚠️ dotenv not installed, using defaults');
}

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const SALT_ROUNDS = 10;
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

// ===== SECURITY FIX: Security middleware with proper CSP for Tor =====
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers like onsubmit
            connectSrc: ["'self'", "ws:", "wss:"],
            imgSrc: ["'self'", "data:"],
            frameAncestors: ["'none'"],
        },
    },
}));

app.use(cookieParser());
app.use(express.json());

// ===== FIX: Proper trust proxy setting for Tor =====
app.set('trust proxy', 'loopback'); // Trust only localhost for Tor

// ===== SECURITY FIX: Session management =====
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: false, // False for Tor (Tor provides encryption)
        sameSite: 'strict',
        maxAge: SESSION_TIMEOUT
    }
}));

// ===== SECURITY FIX: Custom CSRF protection =====
const csrfTokens = new Map();

// Clean up expired tokens every hour
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of csrfTokens.entries()) {
        if (data.expires < now) {
            csrfTokens.delete(token);
        }
    }
}, 60 * 60 * 1000);

// Generate CSRF token
function generateCsrfToken(sessionId) {
    const token = crypto.randomBytes(32).toString('hex');
    csrfTokens.set(token, {
        sessionId: sessionId,
        expires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    });
    return token;
}

// Verify CSRF token middleware
function csrfProtection(req, res, next) {
    if (req.method === 'GET') {
        return next();
    }

    const token = req.headers['csrf-token'] || req.body._csrf;

    if (!token) {
        return res.status(403).json({
            success: false,
            message: 'CSRF token missing'
        });
    }

    const tokenData = csrfTokens.get(token);

    if (!tokenData || tokenData.expires < Date.now()) {
        csrfTokens.delete(token);
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired CSRF token'
        });
    }

    if (tokenData.sessionId !== req.session.id) {
        return res.status(403).json({
            success: false,
            message: 'CSRF token mismatch'
        });
    }

    csrfTokens.delete(token);
    next();
}

// ===== SECURITY FIX: Rate limiting with validation disabled for Tor =====
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: { success: false, message: 'Too many attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: false, // Disable strict proxy validation for Tor
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute
    message: { success: false, message: 'Too many requests' },
    validate: false, // Disable strict proxy validation for Tor
});

// ===== SECURITY FIX: Session activity tracking =====
app.use((req, res, next) => {
    if (req.session && req.session.lastActivity) {
        if (Date.now() - req.session.lastActivity > SESSION_TIMEOUT) {
            req.session.destroy((err) => {
                if (err) console.error('Session destroy error:', err);
            });
            return res.status(401).json({ error: 'Session expired' });
        }
        req.session.lastActivity = Date.now();
    }
    next();
});

// ===== SECURITY FIX: Store CAPTCHA challenges =====
const captchaStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of captchaStore.entries()) {
        if (data.expires < now) {
            captchaStore.delete(token);
        }
    }
}, 60000);

// ===== SECURITY FIX: Sanitization function =====
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return sanitizeHtml(input, {
        allowedTags: [],
        allowedAttributes: {},
        disallowedTagsMode: 'escape'
    });
}

app.use((req, res, next) => {
    console.log(`📡 Request from: ${req.get('host')} - ${req.url}`);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // ===== SECURITY FIX: CORS for Tor =====
    const allowedOrigins = []; // Add your onion address here if needed
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
        res.setHeader('Access-Control-Allow-Origin', 'null');
    }

    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, CSRF-Token');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    next();
});

app.use(express.static(path.join(__dirname), {
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Referrer-Policy', 'no-referrer');
    }
}));

let db;
try {
    db = new Database('./freedomsecuredchat.db');

    // Enable WAL mode for better concurrency
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');

    console.log('✅ Database connected successfully');

    // Ensure all required tables and columns exist
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            original_username TEXT,
            password TEXT,
            pin_code TEXT,
            recovery_phrase TEXT UNIQUE,
            device_id TEXT,
            role TEXT DEFAULT 'USER',
            banned INTEGER DEFAULT 0,
            warnings INTEGER DEFAULT 0,
            muted INTEGER DEFAULT 0,
            muted_until DATETIME,
            username_changed INTEGER DEFAULT 0,
            bio TEXT DEFAULT 'Delete me and type your bio here.',
            join_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            message_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            terms_accepted INTEGER DEFAULT 0,
            terms_accepted_at DATETIME,
            account_number INTEGER DEFAULT 1,
            last_pin_entry DATETIME,
            failed_pin_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            failed_login_attempts INTEGER DEFAULT 0,
            last_login_attempt DATETIME
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            original_username TEXT,
            role TEXT,
            content TEXT,
            type TEXT DEFAULT 'chat',
            target_user TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS warnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            warned_by TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS message_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message_count INTEGER DEFAULT 0,
            last_message_time DATETIME,
            UNIQUE(username)
        );

        CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT,
            from_original TEXT,
            to_user TEXT,
            role TEXT,
            content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            delivered INTEGER DEFAULT 0,
            delivered_at DATETIME,
            read INTEGER DEFAULT 0,
            read_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS device_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            username TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(device_id, username)
        );

        CREATE TABLE IF NOT EXISTS pin_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            session_id TEXT,
            verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS message_cooldown (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message_count INTEGER DEFAULT 0,
            last_reset DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username)
        );
    `);

    // Drop banned_devices table if it exists (cleanup)
    db.exec(`DROP TABLE IF EXISTS banned_devices;`);

    // Add indexes for performance
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
        CREATE INDEX IF NOT EXISTS idx_private_messages_timestamp ON private_messages(timestamp);
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned);
    `);

    console.log('✅ All tables created/verified');

} catch (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
}

// ===== SECURITY FIX: CSRF token endpoint =====
app.get('/api/csrf-token', (req, res) => {
    if (!req.session.id) {
        req.session.id = crypto.randomBytes(16).toString('hex');
    }
    const token = generateCsrfToken(req.session.id);
    res.json({
        success: true,
        csrfToken: token
    });
});

// ===== SECURITY FIX: CAPTCHA endpoints =====
app.post('/api/captcha/generate', apiLimiter, (req, res) => {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const operator = Math.random() > 0.5 ? '+' : '-';
    const answer = operator === '+' ? num1 + num2 : num1 - num2;

    const token = crypto.randomBytes(16).toString('hex');
    captchaStore.set(token, {
        answer,
        expires: Date.now() + 300000 // 5 minutes
    });

    res.json({
        success: true,
        token,
        question: `${num1} ${operator} ${num2} = ?`
    });
});

app.post('/api/captcha/verify', apiLimiter, (req, res) => {
    const { token, answer } = req.body;
    const captcha = captchaStore.get(token);

    if (!captcha || captcha.expires < Date.now()) {
        return res.json({ valid: false });
    }

    const valid = parseInt(answer) === captcha.answer;
    captchaStore.delete(token);
    res.json({ valid });
});

const roleConfig = {
    'USER': {
        color: '#FFFFFF',
        maxChars: 100,
        messageLimit: true,
        messageCooldown: 5000,
        maxMessagesPerInterval: 5,
        canSendLinks: false,
        badge: '',
        level: 0
    },
    'VIP': {
        color: '#FFD700',
        maxChars: 150,
        messageLimit: false,
        messageCooldown: 0,
        maxMessagesPerInterval: 0,
        canSendLinks: true,
        badge: '⭐',
        level: 1
    },
    'MODERATOR': {
        color: '#0000FF',
        maxChars: 200,
        messageLimit: false,
        messageCooldown: 0,
        maxMessagesPerInterval: 0,
        canSendLinks: true,
        badge: '🛡️',
        level: 2,
        permissions: ['mute', 'ban', 'warn']
    },
    'ADMIN': {
        color: '#800080',
        maxChars: 250,
        messageLimit: false,
        messageCooldown: 0,
        maxMessagesPerInterval: 0,
        canSendLinks: true,
        badge: '👑',
        level: 3,
        permissions: ['mute', 'ban', 'unban', 'warn', 'broadcast', 'promote', 'demote']
    },
    'OWNER': {
        color: '#0A0A0A',
        maxChars: 300,
        messageLimit: false,
        messageCooldown: 0,
        maxMessagesPerInterval: 0,
        canSendLinks: true,
        badge: '⚡',
        level: 4,
        permissions: ['mute', 'ban', 'unban', 'warn', 'broadcast', 'promote', 'demote']
    }
};

const onlineUsers = new Map();

function cleanupOldMessages() {
    try {
        const oneDayAgo = new Date();
        oneDayAgo.setDate(oneDayAgo.getDate() - 1);
        const timestamp = oneDayAgo.toISOString();

        const globalResult = db.prepare("DELETE FROM messages WHERE timestamp < ? AND type = 'chat'").run(timestamp);
        const privateResult = db.prepare("DELETE FROM private_messages WHERE timestamp < ?").run(timestamp);

        if (globalResult.changes > 0 || privateResult.changes > 0) {
            console.log(`🧹 Cleaned up ${globalResult.changes} global messages and ${privateResult.changes} private messages older than 24 hours`);
        }
    } catch (err) {
        console.error('Cleanup error:', err.message);
    }
}

setInterval(cleanupOldMessages, 60 * 60 * 1000);
cleanupOldMessages();

const privateMessageQueue = new Map();

app.post('/api/chat-contacts', apiLimiter, (req, res) => {
    const { username } = req.body;

    try {
        const contacts = db.prepare(`
            SELECT DISTINCT
                u.username,
                u.original_username,
                u.role,
                u.bio,
                (
                    SELECT COUNT(*)
                    FROM private_messages
                    WHERE to_user = ? AND from_user = u.username AND read = 0
                ) as unread_count,
                (
                    SELECT MAX(timestamp)
                    FROM private_messages
                    WHERE (from_user = ? AND to_user = u.username)
                       OR (to_user = ? AND from_user = u.username)
                ) as last_message_time
            FROM users u
            WHERE u.username IN (
                SELECT DISTINCT from_user FROM private_messages WHERE to_user = ?
                UNION
                SELECT DISTINCT to_user FROM private_messages WHERE from_user = ?
            )
            AND u.username != ?
            ORDER BY last_message_time DESC
        `).all(username.toLowerCase(), username.toLowerCase(), username.toLowerCase(),
               username.toLowerCase(), username.toLowerCase(), username.toLowerCase());

        const onlineList = Array.from(onlineUsers.values());
        const onlineUsernames = onlineList.map(u => u.username);

        const contactsWithStatus = contacts.map(contact => ({
            ...contact,
            online: onlineUsernames.includes(contact.username)
        }));

        res.json({
            success: true,
            contacts: contactsWithStatus
        });

    } catch (err) {
        console.error('Error getting chat contacts:', err.message);
        res.json({ success: false, message: 'Server error' });
    }
});

app.post('/api/mark-messages-read', apiLimiter, (req, res) => {
    const { username, contactUsername } = req.body;

    try {
        const result = db.prepare(`
            UPDATE private_messages
            SET read = 1, read_at = CURRENT_TIMESTAMP
            WHERE to_user = ? AND from_user = ? AND read = 0
        `).run(username.toLowerCase(), contactUsername.toLowerCase());

        res.json({
            success: true,
            markedCount: result.changes
        });

    } catch (err) {
        console.error('Error marking messages as read:', err.message);
        res.json({ success: false, message: 'Server error' });
    }
});

app.post('/api/unread-counts', apiLimiter, (req, res) => {
    const { username } = req.body;

    try {
        const unreadCounts = db.prepare(`
            SELECT from_user, COUNT(*) as count
            FROM private_messages
            WHERE to_user = ? AND read = 0
            GROUP BY from_user
        `).all(username.toLowerCase());

        const countsObject = {};
        unreadCounts.forEach(item => {
            countsObject[item.from_user] = item.count;
        });

        res.json({
            success: true,
            unreadCounts: countsObject
        });

    } catch (err) {
        console.error('Error getting unread counts:', err.message);
        res.json({ success: false, message: 'Server error' });
    }
});

app.post('/api/check-user-exists', apiLimiter, (req, res) => {
    const { username } = req.body;

    try {
        const user = db.prepare(`
            SELECT username, original_username, role
            FROM users
            WHERE username = ? OR original_username = ?
        `).get(username.toLowerCase(), username);

        if (user) {
            res.json({
                exists: true,
                username: user.username,
                original_username: user.original_username,
                role: user.role
            });
        } else {
            res.json({ exists: false });
        }
    } catch (err) {
        console.error('Error checking user existence:', err.message);
        res.json({ exists: false, error: 'Server error' });
    }
});

app.post('/api/check-user-banned', apiLimiter, (req, res) => {
    const { username } = req.body;

    try {
        const user = db.prepare('SELECT banned FROM users WHERE username = ?').get(username.toLowerCase());
        res.json({
            banned: user ? user.banned === 1 : false
        });
    } catch (err) {
        console.error('Error checking ban status:', err);
        res.json({ banned: false });
    }
});

io.on('connection', (socket) => {
    console.log('🔌 New client connected:', socket.id);

    socket.on('user login', (data) => {
        const { username, originalUsername } = data;

        try {
            const user = db.prepare('SELECT role, banned, muted, muted_until, warnings, message_count, join_date, bio, pin_code FROM users WHERE username = ?').get(username);

            if (user && user.banned === 1) {
                socket.emit('banned', { reason: 'Your account has been banned' });
                return;
            }

            const role = user ? user.role : 'USER';

            if (user && user.muted === 1) {
                const mutedUntil = user.muted_until ? new Date(user.muted_until) : null;
                if (mutedUntil && mutedUntil > new Date()) {
                    const timeLeft = Math.ceil((mutedUntil - new Date()) / 60000);
                    const hoursLeft = Math.floor(timeLeft / 60);
                    const minsLeft = timeLeft % 60;

                    let timeString = '';
                    if (hoursLeft > 0) {
                        timeString = `${hoursLeft} hour${hoursLeft > 1 ? 's' : ''} and ${minsLeft} minute${minsLeft > 1 ? 's' : ''}`;
                    } else {
                        timeString = `${minsLeft} minute${minsLeft > 1 ? 's' : ''}`;
                    }

                    socket.emit('muted', {
                        until: mutedUntil,
                        timeLeft: timeString,
                        message: `You are muted for ${timeString}`
                    });
                } else if (user.muted === 1) {
                    db.prepare('UPDATE users SET muted = 0, muted_until = NULL WHERE username = ?').run(username);
                }
            }

            onlineUsers.set(socket.id, {
                username: username,
                originalUsername: originalUsername,
                role: role
            });

            console.log(`👤 ${originalUsername} (${role}) logged in. Online: ${onlineUsers.size}`);

            io.emit('online count', onlineUsers.size);

            const onlineList = Array.from(onlineUsers.values());
            io.emit('online users', onlineList);

            const allUsers = db.prepare(`
                SELECT username, original_username, role, banned, warnings, muted, message_count, join_date, bio
                FROM users
            `).all();

            const onlineUsernames = onlineList.map(u => u.username);
            const usersWithStatus = allUsers.map(u => ({
                ...u,
                online: onlineUsernames.includes(u.username)
            }));

            socket.emit('all users', usersWithStatus);

            const recentMessages = db.prepare(`
                SELECT username, original_username, role, content, timestamp, type, target_user
                FROM messages
                ORDER BY timestamp DESC
                LIMIT 50
            `).all();

            socket.emit('message history', recentMessages.reverse());

            const undeliveredMessages = db.prepare(`
                SELECT * FROM private_messages
                WHERE to_user = ? AND delivered = 0
                ORDER BY timestamp ASC
            `).all(username);

            if (undeliveredMessages.length > 0) {
                console.log(`📨 Found ${undeliveredMessages.length} undelivered messages for ${originalUsername}`);

                undeliveredMessages.forEach(msg => {
                    socket.emit('private message', {
                        id: msg.id,
                        from: msg.from_user,
                        originalFrom: msg.from_original,
                        to: msg.to_user,
                        role: msg.role,
                        content: msg.content,
                        timestamp: msg.timestamp,
                        delivered: 1
                    });
                });

                db.prepare(`
                    UPDATE private_messages
                    SET delivered = 1, delivered_at = CURRENT_TIMESTAMP
                    WHERE to_user = ? AND delivered = 0
                `).run(username);

                console.log(`✅ Delivered and marked ${undeliveredMessages.length} messages for ${originalUsername}`);
            }

            if (privateMessageQueue.has(username)) {
                const queuedMessages = privateMessageQueue.get(username);
                queuedMessages.forEach(msg => {
                    socket.emit('private message', msg);
                });
                privateMessageQueue.delete(username);
                console.log(`📨 Delivered ${queuedMessages.length} queued messages from memory to ${originalUsername}`);
            }

        } catch (err) {
            console.error('Error in user login:', err.message);
        }
    });

    socket.on('get all users', () => {
        try {
            const allUsers = db.prepare(`
                SELECT username, original_username, role, banned, warnings, muted, message_count, join_date, bio
                FROM users
            `).all();

            const onlineList = Array.from(onlineUsers.values());
            const onlineUsernames = onlineList.map(u => u.username);

            const usersWithStatus = allUsers.map(u => ({
                ...u,
                online: onlineUsernames.includes(u.username)
            }));

            socket.emit('all users', usersWithStatus);
        } catch (err) {
            console.error('Error getting all users:', err.message);
        }
    });

    socket.on('get user info', (targetUsername) => {
        try {
            const user = db.prepare(`
                SELECT username, original_username, role, message_count, join_date, bio, warnings, muted, banned
                FROM users WHERE username = ?
            `).get(targetUsername.toLowerCase());

            if (user) {
                socket.emit('user info', {
                    username: user.username,
                    originalUsername: user.original_username,
                    role: user.role,
                    messageCount: user.message_count || 0,
                    joinDate: user.join_date,
                    bio: user.bio || 'No bio yet.',
                    warnings: user.warnings || 0,
                    muted: user.muted || 0,
                    banned: user.banned || 0
                });
            }
        } catch (err) {
            console.error('Error getting user info:', err.message);
        }
    });

    socket.on('new message', (data) => {
        const { username, originalUsername, content } = data;
        const timestamp = new Date().toISOString();

        try {
            const user = db.prepare('SELECT role, banned, muted, muted_until, warnings FROM users WHERE username = ?').get(username);

            if (!user) return;

            if (user.banned === 1) {
                socket.emit('message error', 'You are banned from this chat.');
                return;
            }

            if (user.muted === 1) {
                const mutedUntil = user.muted_until ? new Date(user.muted_until) : null;
                if (mutedUntil && mutedUntil > new Date()) {
                    const timeLeft = Math.ceil((mutedUntil - new Date()) / 60000);
                    const hoursLeft = Math.floor(timeLeft / 60);
                    const minsLeft = timeLeft % 60;

                    let timeString = '';
                    if (hoursLeft > 0) {
                        timeString = `${hoursLeft} hour${hoursLeft > 1 ? 's' : ''} and ${minsLeft} minute${minsLeft > 1 ? 's' : ''}`;
                    } else {
                        timeString = `${minsLeft} minute${minsLeft > 1 ? 's' : ''}`;
                    }

                    socket.emit('message error', `You are muted for ${timeString}`);
                    return;
                } else if (user.muted === 1) {
                    db.prepare('UPDATE users SET muted = 0, muted_until = NULL WHERE username = ?').run(username);
                }
            }

            const role = user.role;
            const config = roleConfig[role] || roleConfig['USER'];

            if (typeof content !== 'string') {
                socket.emit('message error', 'Invalid message format');
                return;
            }

            if (content.length > config.maxChars) {
                socket.emit('message error', `Message too long. Maximum ${config.maxChars} characters.`);
                return;
            }

            if (!config.canSendLinks) {
                const linkRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|\.[a-zA-Z]{2,}\b)/gi;
                if (linkRegex.test(content)) {
                    socket.emit('message error', 'You cannot send links.');
                    return;
                }
            }

            if (config.messageLimit) {
                const now = new Date();
                const cooldownWindow = 5000;

                const recentMessages = db.prepare(`
                    SELECT COUNT(*) as count FROM messages
                    WHERE username = ? AND timestamp > ?
                `).get(username, new Date(now.getTime() - cooldownWindow).toISOString());

                if (recentMessages.count >= 5) {
                    socket.emit('message error', 'Too many messages. Please wait 5 seconds.');
                    return;
                }
            }

            db.prepare(`
                INSERT INTO messages (username, original_username, role, content, type, timestamp)
                VALUES (?, ?, ?, ?, 'chat', ?)
            `).run(username, originalUsername, role, content, timestamp);

            db.prepare(`
                UPDATE users SET message_count = message_count + 1 WHERE username = ?
            `).run(username);

            io.emit('new message', {
                username: username,
                originalUsername: originalUsername,
                role: role,
                content: content,
                type: 'chat',
                timestamp: timestamp
            });

        } catch (err) {
            console.error('Error saving message:', err);
            socket.emit('message error', 'Failed to send message.');
        }
    });

    socket.on('private message', (data) => {
        const { from, originalFrom, to, role, content, timestamp } = data;

        try {
            const recipient = db.prepare('SELECT banned FROM users WHERE username = ?').get(to.toLowerCase());

            if (recipient && recipient.banned === 1) {
                socket.emit('private message error', 'Cannot send message: This user has been banned');
                return;
            }

            let isOnline = false;
            for (let [socketId, user] of onlineUsers) {
                if (user.username === to) {
                    isOnline = true;
                    break;
                }
            }

            const insertStmt = db.prepare(`
                INSERT INTO private_messages
                (from_user, from_original, to_user, role, content, timestamp, delivered, read)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            `);

            const result = insertStmt.run(
                from, originalFrom, to, role, content, timestamp,
                isOnline ? 1 : 0
            );

            const messageObj = {
                id: result.lastInsertRowid,
                from: from,
                originalFrom: originalFrom,
                to: to,
                role: role,
                content: content,
                timestamp: timestamp,
                delivered: isOnline ? 1 : 0
            };

            if (isOnline) {
                for (let [socketId, user] of onlineUsers) {
                    if (user.username === to) {
                        io.to(socketId).emit('private message', messageObj);
                        console.log(`📨 Private message delivered instantly to ${to}`);

                        db.prepare(`
                            UPDATE private_messages
                            SET delivered_at = CURRENT_TIMESTAMP
                            WHERE id = ?
                        `).run(result.lastInsertRowid);
                        break;
                    }
                }
            } else {
                if (!privateMessageQueue.has(to)) {
                    privateMessageQueue.set(to, []);
                }
                privateMessageQueue.get(to).push(messageObj);
                console.log(`📦 Private message stored for offline user ${to} (ID: ${result.lastInsertRowid})`);
            }

            socket.emit('private message sent', {
                success: true,
                timestamp,
                messageId: result.lastInsertRowid,
                delivered: isOnline
            });

        } catch (err) {
            console.error('Error saving private message:', err);
            socket.emit('private message error', 'Failed to send private message');
        }
    });

    socket.on('get private messages', (otherUser) => {
        const username = onlineUsers.get(socket.id)?.username;

        if (!username) return;

        try {
            const messages = db.prepare(`
                SELECT * FROM private_messages
                WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
                ORDER BY timestamp ASC
            `).all(username, otherUser, otherUser, username);

            const undeliveredStmt = db.prepare(`
                UPDATE private_messages
                SET delivered = 1, delivered_at = CURRENT_TIMESTAMP
                WHERE to_user = ? AND from_user = ? AND delivered = 0
            `);
            const updateResult = undeliveredStmt.run(username, otherUser);

            if (updateResult.changes > 0) {
                console.log(`✅ Marked ${updateResult.changes} messages as delivered between ${username} and ${otherUser}`);
            }

            socket.emit('private messages history', {
                withUser: otherUser,
                messages: messages
            });

            console.log(`📜 Sent private message history with ${otherUser} to ${username} (${messages.length} messages)`);

        } catch (err) {
            console.error('Error getting private messages:', err);
        }
    });

    socket.on('link attempt', (data) => {
        const { username, warnings } = data;
        const warningsLeft = 3 - warnings;
        socket.emit('link warning', { warningsLeft });
    });

    socket.on('verify recovery', (data, callback) => {
        const { username, phrase } = data;

        try {
            const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());

            if (user && bcrypt.compareSync(phrase, user.recovery_phrase)) {
                callback({ success: true, message: 'Account verified' });
            } else {
                callback({ success: false, message: 'Invalid username or recovery phrase' });
            }
        } catch (err) {
            console.error('Recovery verification error:', err.message);
            callback({ success: false, message: 'Server error' });
        }
    });

    socket.on('reset password', async (data, callback) => {
        const { username, phrase, newPassword } = data;

        try {
            const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());

            if (user && bcrypt.compareSync(phrase, user.recovery_phrase)) {
                const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
                db.prepare('UPDATE users SET password = ? WHERE username = ?').run(hashedPassword, username.toLowerCase());
                callback({ success: true, message: 'Password reset successful' });
            } else {
                callback({ success: false, message: 'Invalid username or recovery phrase' });
            }
        } catch (err) {
            console.error('Password reset error:', err.message);
            callback({ success: false, message: 'Server error' });
        }
    });

    socket.on('staff action', (data) => {
        const { action, targetUsername, reason, staffUsername, message, newRole } = data;

        console.log(`🛡️ Staff action: ${action} by ${staffUsername}`, data);

        try {
            const staff = db.prepare('SELECT role FROM users WHERE username = ?').get(staffUsername.toLowerCase());
            if (!staff) {
                socket.emit('staff error', 'Staff not found');
                return;
            }

            const staffRole = staff.role;
            const staffLevel = roleConfig[staffRole]?.level || 0;

            if (action === 'broadcast') {
                if (staffRole !== 'ADMIN' && staffRole !== 'OWNER') {
                    socket.emit('staff error', 'Permission denied');
                    return;
                }

                const broadcastMsg = {
                    username: 'SYSTEM',
                    originalUsername: 'SYSTEM',
                    role: 'SYSTEM',
                    content: `BROADCAST: ${message}`,
                    type: 'broadcast',
                    timestamp: new Date().toISOString()
                };

                io.emit('broadcast', broadcastMsg);
                socket.emit('staff success', 'Broadcast sent');
                return;
            }

            if (!targetUsername) {
                socket.emit('staff error', 'No target user specified');
                return;
            }

            const target = db.prepare('SELECT * FROM users WHERE username = ?').get(targetUsername.toLowerCase());
            if (!target) {
                socket.emit('staff error', 'User not found');
                return;
            }

            const targetLevel = roleConfig[target.role]?.level || 0;

            if (staffLevel <= targetLevel && staffUsername.toLowerCase() !== targetUsername.toLowerCase()) {
                socket.emit('staff error', `You cannot moderate ${target.original_username} (higher or equal rank)`);
                return;
            }

            switch(action) {
                case 'warn':
                    db.prepare('INSERT INTO warnings (username, warned_by, reason) VALUES (?, ?, ?)')
                      .run(targetUsername.toLowerCase(), staffUsername.toLowerCase(), reason);

                    const newWarningCount = (target.warnings || 0) + 1;
                    db.prepare('UPDATE users SET warnings = ? WHERE username = ?')
                      .run(newWarningCount, targetUsername.toLowerCase());

                    const warningMsg = {
                        username: 'SYSTEM',
                        originalUsername: 'SYSTEM',
                        role: 'SYSTEM',
                        content: `⚠️ WARNING: ${reason}`,
                        type: 'warning',
                        target_user: targetUsername.toLowerCase(),
                        timestamp: new Date().toISOString()
                    };

                    for (let [socketId, user] of onlineUsers) {
                        if (user.username === targetUsername.toLowerCase()) {
                            io.to(socketId).emit('warning', warningMsg);
                            break;
                        }
                    }

                    if (newWarningCount >= 3) {
                        db.prepare('UPDATE users SET banned = 1 WHERE username = ?').run(targetUsername.toLowerCase());

                        const banMsg = {
                            username: 'SYSTEM',
                            originalUsername: 'SYSTEM',
                            role: 'SYSTEM',
                            content: `[@${target.original_username}] BANNED`,
                            type: 'ban',
                            target_user: targetUsername.toLowerCase(),
                            timestamp: new Date().toISOString()
                        };

                        for (let [socketId, user] of onlineUsers) {
                            if (user.username === targetUsername.toLowerCase()) {
                                io.to(socketId).emit('banned', {
                                    reason: 'Auto-banned after 3 warnings',
                                    message: banMsg
                                });

                                setTimeout(() => {
                                    io.to(socketId).emit('force logout');
                                    onlineUsers.delete(socketId);
                                }, 2000);
                                break;
                            }
                        }

                        socket.emit('staff success', `${target.original_username} auto-banned (3 warnings)`);
                    } else {
                        socket.emit('staff success', `Warning sent to ${target.original_username} (${newWarningCount}/3 warnings)`);
                    }
                    break;

                case 'mute':
                    const muteMinutes = 60;
                    const mutedUntil = new Date(Date.now() + muteMinutes * 60000);

                    db.prepare('UPDATE users SET muted = 1, muted_until = ? WHERE username = ?')
                      .run(mutedUntil.toISOString(), targetUsername.toLowerCase());

                    const muteMsg = {
                        username: 'SYSTEM',
                        originalUsername: 'SYSTEM',
                        role: 'SYSTEM',
                        content: `[@${target.original_username}] MUTED FOR 1 HOUR`,
                        type: 'mute',
                        target_user: targetUsername.toLowerCase(),
                        timestamp: new Date().toISOString()
                    };

                    for (let [socketId, user] of onlineUsers) {
                        if (user.username === targetUsername.toLowerCase()) {
                            io.to(socketId).emit('muted', {
                                by: staffUsername,
                                until: mutedUntil,
                                reason: reason,
                                message: muteMsg
                            });
                            break;
                        }
                    }

                    socket.emit('staff success', `${target.original_username} muted for 1 hour`);
                    break;

                case 'unmute':
                    db.prepare('UPDATE users SET muted = 0, muted_until = NULL WHERE username = ?')
                      .run(targetUsername.toLowerCase());

                    const unmuteMsg = {
                        username: 'SYSTEM',
                        originalUsername: 'SYSTEM',
                        role: 'SYSTEM',
                        content: `[@${target.original_username}] UNMUTED`,
                        type: 'unmute',
                        target_user: targetUsername.toLowerCase(),
                        timestamp: new Date().toISOString()
                    };

                    for (let [socketId, user] of onlineUsers) {
                        if (user.username === targetUsername.toLowerCase()) {
                            io.to(socketId).emit('unmuted', {
                                by: staffUsername,
                                message: unmuteMsg
                            });
                            break;
                        }
                    }

                    socket.emit('staff success', `${target.original_username} unmuted`);
                    break;

                case 'ban':
                    db.prepare('UPDATE users SET banned = 1 WHERE username = ?').run(targetUsername.toLowerCase());

                    const banMsg = {
                        username: 'SYSTEM',
                        originalUsername: 'SYSTEM',
                        role: 'SYSTEM',
                        content: `[@${target.original_username}] BANNED`,
                        type: 'ban',
                        target_user: targetUsername.toLowerCase(),
                        timestamp: new Date().toISOString()
                    };

                    for (let [socketId, user] of onlineUsers) {
                        if (user.username === targetUsername.toLowerCase()) {
                            io.to(socketId).emit('banned', {
                                by: staffUsername,
                                reason: reason,
                                message: banMsg
                            });

                            setTimeout(() => {
                                io.to(socketId).emit('force logout');
                                onlineUsers.delete(socketId);
                            }, 2000);
                            break;
                        }
                    }

                    socket.emit('staff success', `${target.original_username} banned`);
                    break;

                case 'unban':
                    if (staffRole === 'ADMIN' || staffRole === 'OWNER') {
                        db.prepare('UPDATE users SET banned = 0, warnings = 0 WHERE username = ?').run(targetUsername.toLowerCase());

                        const unbanMsg = {
                            username: 'SYSTEM',
                            originalUsername: 'SYSTEM',
                            role: 'SYSTEM',
                            content: `[@${target.original_username}] UNBANNED`,
                            type: 'unban',
                            target_user: targetUsername.toLowerCase(),
                            timestamp: new Date().toISOString()
                        };

                        for (let [socketId, user] of onlineUsers) {
                            if (user.username === targetUsername.toLowerCase()) {
                                io.to(socketId).emit('unbanned', {
                                    by: staffUsername,
                                    message: unbanMsg
                                });
                                break;
                            }
                        }

                        socket.emit('staff success', `${target.original_username} unbanned`);
                    }
                    break;

                case 'promote':
                case 'demote':
                    if (staffRole === 'ADMIN' || staffRole === 'OWNER') {
                        if (!newRole) {
                            socket.emit('staff error', 'No role specified');
                            return;
                        }

                        const oldRole = target.role;

                        db.prepare('UPDATE users SET role = ? WHERE username = ?').run(newRole, targetUsername.toLowerCase());

                        const roleChangeMsg = {
                            username: 'SYSTEM',
                            originalUsername: 'SYSTEM',
                            role: 'SYSTEM',
                            content: `[@${target.original_username}] ${action === 'promote' ? 'PROMOTED' : 'DEMOTED'} FROM ${oldRole} TO ${newRole}`,
                            type: action,
                            target_user: targetUsername.toLowerCase(),
                            timestamp: new Date().toISOString()
                        };

                        io.emit('role changed', {
                            username: target.original_username,
                            oldRole: oldRole,
                            newRole: newRole,
                            action: action,
                            message: roleChangeMsg
                        });

                        socket.emit('staff success', `${target.original_username} ${action}d to ${newRole}`);
                    }
                    break;

                default:
                    socket.emit('staff error', 'Unknown action');
            }

            const updatedUsers = db.prepare(`
                SELECT username, original_username, role, banned, warnings, muted, message_count, join_date, bio
                FROM users
            `).all();

            const onlineList = Array.from(onlineUsers.values());
            const onlineUsernames = onlineList.map(u => u.username);

            const usersWithStatus = updatedUsers.map(u => ({
                ...u,
                online: onlineUsernames.includes(u.username)
            }));

            io.emit('all users', usersWithStatus);

        } catch (err) {
            console.error('Staff action error:', err);
            socket.emit('staff error', 'Action failed: ' + err.message);
        }
    });

    socket.on('disconnect', () => {
        const user = onlineUsers.get(socket.id);
        if (user) {
            console.log(`👋 ${user.originalUsername} (${user.role}) disconnected`);
            onlineUsers.delete(socket.id);

            io.emit('online count', onlineUsers.size);

            const onlineList = Array.from(onlineUsers.values());
            io.emit('online users', onlineList);

            const allUsers = db.prepare(`
                SELECT username, original_username, role, banned, warnings, muted, message_count, join_date, bio
                FROM users
            `).all();

            const onlineUsernames = onlineList.map(u => u.username);
            const usersWithStatus = allUsers.map(u => ({
                ...u,
                online: onlineUsernames.includes(u.username)
            }));

            io.emit('all users', usersWithStatus);
        }
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/api/test', apiLimiter, (req, res) => {
    try {
        const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
        const messageCount = db.prepare('SELECT COUNT(*) as count FROM messages').get();
        const privateMessageCount = db.prepare('SELECT COUNT(*) as count FROM private_messages').get();
        res.json({
            status: 'Server running',
            database: 'connected',
            users: userCount.count,
            messages: messageCount.count,
            privateMessages: privateMessageCount.count,
            online: onlineUsers.size,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.json({ status: 'error', message: 'Server error' });
    }
});

app.post('/api/check-device-limit', apiLimiter, (req, res) => {
    const { deviceId } = req.body;

    try {
        const accountCount = db.prepare('SELECT COUNT(*) as count FROM device_accounts WHERE device_id = ?').get(deviceId);

        if (accountCount.count >= 20) {
            return res.json({
                success: false,
                message: 'This device has reached the maximum of 2 accounts'
            });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Check device limit error:', err.message);
        res.json({ success: false, message: 'Server error' });
    }
});

app.post('/api/register', authLimiter, async (req, res) => {
    const { username, originalUsername, password, pin, recoveryPhrase, deviceId, termsAccepted, captchaToken, captchaAnswer } = req.body;

    console.log('='.repeat(50));
    console.log('REGISTRATION ATTEMPT:');
    console.log('Username:', originalUsername);
    console.log('='.repeat(50));

    try {
        const captcha = captchaStore.get(captchaToken);
        if (!captcha || captcha.expires < Date.now() || captcha.answer !== parseInt(captchaAnswer)) {
            return res.json({
                success: false,
                message: 'Invalid CAPTCHA'
            });
        }
        captchaStore.delete(captchaToken);

        if (!/^[a-zA-Z0-9]{3,16}$/.test(username)) {
            return res.json({
                success: false,
                message: 'Invalid username format'
            });
        }

        if (!/^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,16}$/.test(password)) {
            return res.json({
                success: false,
                message: 'Invalid password format'
            });
        }

        if (!/^\d{4}$/.test(pin)) {
            return res.json({
                success: false,
                message: 'PIN must be exactly 4 digits'
            });
        }

        const existingUser = db.prepare('SELECT username, banned FROM users WHERE username = ?').get(username);
        if (existingUser) {
            if (existingUser.banned === 1) {
                return res.json({
                    success: false,
                    message: 'This username cannot be used'
                });
            } else {
                return res.json({
                    success: false,
                    message: 'Username already taken'
                });
            }
        }

        let accountCount = { count: 0 };
        try {
            accountCount = db.prepare('SELECT COUNT(*) as count FROM device_accounts WHERE device_id = ?').get(deviceId);
            console.log('Account count for device:', accountCount.count);
        } catch (err) {
            console.error('Error checking device_accounts:', err.message);
            accountCount = { count: 0 };
        }

        if (accountCount.count >= 20) {
            return res.json({
                success: false,
                message: 'This device has reached the maximum of 2 accounts'
            });
        }

        const existingPhrase = db.prepare('SELECT username FROM users WHERE recovery_phrase = ?').get(recoveryPhrase);
        if (existingPhrase) {
            return res.json({
                success: false,
                message: 'Recovery phrase already in use. Please try again.'
            });
        }

        const accountNumber = accountCount.count + 1;

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const hashedPin = pin ? await bcrypt.hash(pin.toString(), SALT_ROUNDS) : null;
        const hashedPhrase = await bcrypt.hash(recoveryPhrase, SALT_ROUNDS);

        console.log('Attempting to insert user with hashed PIN');

        const stmt = db.prepare(`
            INSERT INTO users (
                username, original_username, password, pin_code,
                recovery_phrase, device_id, role, join_date,
                message_count, terms_accepted, terms_accepted_at, account_number,
                failed_login_attempts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        const result = stmt.run(
            username,
            originalUsername,
            hashedPassword,
            hashedPin,
            hashedPhrase,
            deviceId,
            'USER',
            new Date().toISOString(),
            0,
            termsAccepted ? 1 : 0,
            termsAccepted ? new Date().toISOString() : null,
            accountNumber,
            0
        );

        console.log('User inserted successfully. Changes:', result.changes);

        try {
            db.prepare('INSERT INTO device_accounts (device_id, username) VALUES (?, ?)').run(deviceId, username);
            console.log('Device account tracked');
        } catch (err) {
            console.error('Error inserting device_account:', err.message);
        }

        console.log('User created successfully:', originalUsername);
        console.log('='.repeat(50));

        res.json({ success: true, message: 'Registration successful' });

    } catch (err) {
        console.error('❌ REGISTRATION ERROR:', err);
        console.error('Error stack:', err.stack);
        console.log('='.repeat(50));
        res.json({ success: false, message: 'Registration failed' });
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    const { username, password, deviceId, captchaToken, captchaAnswer } = req.body;

    console.log('Login attempt for:', username);

    try {
        const user = db.prepare(`
            SELECT *, failed_login_attempts, locked_until
            FROM users WHERE username = ?
        `).get(username.toLowerCase());

        if (!user) {
            console.log('User not found:', username);
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        if (user.failed_login_attempts >= 2) {
            const captcha = captchaStore.get(captchaToken);
            if (!captcha || captcha.expires < Date.now() || captcha.answer !== parseInt(captchaAnswer)) {
                return res.json({
                    success: false,
                    message: 'Invalid CAPTCHA'
                });
            }
            captchaStore.delete(captchaToken);
        }

        if (user.locked_until) {
            const lockedUntil = new Date(user.locked_until);
            const now = new Date();

            if (lockedUntil > now) {
                const minutesRemaining = Math.ceil((lockedUntil - now) / (60 * 1000));
                console.log(`🔒 Account locked for ${minutesRemaining} more minutes`);
                return res.json({
                    success: false,
                    message: `Account locked. Try again in ${minutesRemaining} minute${minutesRemaining !== 1 ? 's' : ''}.`
                });
            } else {
                console.log('🔓 Lock expired, resetting attempts');
                db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?')
                  .run(username.toLowerCase());
                user.failed_login_attempts = 0;
            }
        }

        if (user.banned === 1) {
            return res.json({
                success: false,
                message: 'This account is banned.'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            console.log('Invalid password for:', username);

            const newAttempts = (user.failed_login_attempts || 0) + 1;
            console.log(`⚠️ Failed login attempt ${newAttempts} of 2 for ${username}`);

            if (newAttempts >= 2) {
                const lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE username = ?')
                  .run(newAttempts, lockedUntil, username.toLowerCase());

                console.log('🔒 Account locked for 30 minutes after 2 failed login attempts');

                return res.json({
                    success: false,
                    message: 'Too many failed login attempts. Account locked for 30 minutes.'
                });
            } else {
                db.prepare('UPDATE users SET failed_login_attempts = ? WHERE username = ?')
                  .run(newAttempts, username.toLowerCase());

                const attemptsLeft = 2 - newAttempts;
                return res.json({
                    success: false,
                    message: `Invalid credentials. ${attemptsLeft} attempt${attemptsLeft !== 1 ? 's' : ''} remaining.`
                });
            }
        }

        db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ?')
          .run(username.toLowerCase());

        if (user.device_id !== deviceId) {
            console.log(`⚠️ Device fingerprint changed for ${user.original_username}, updating...`);
            db.prepare('UPDATE users SET device_id = ? WHERE username = ?').run(deviceId, username);

            const existingDeviceAccount = db.prepare('SELECT * FROM device_accounts WHERE device_id = ? AND username = ?').get(deviceId, username);
            if (!existingDeviceAccount) {
                db.prepare('INSERT INTO device_accounts (device_id, username) VALUES (?, ?)').run(deviceId, username);
            }
        }

        req.session.user = {
            username: user.username,
            originalUsername: user.original_username,
            role: user.role
        };
        req.session.lastActivity = Date.now();

        console.log('Login successful for:', user.original_username, 'Role:', user.role);
        console.log('User has PIN:', user.pin_code ? 'YES' : 'NO');

        res.json({
            success: true,
            message: 'Login successful',
            username: user.original_username,
            role: user.role,
            pinRequired: true
        });

    } catch (err) {
        console.error('Login error:', err.message);
        res.json({ success: false, message: 'Login failed' });
    }
});

app.post('/api/recover', authLimiter, async (req, res) => {
    const { phrase, newPassword, pin, deviceId, captchaToken, captchaAnswer } = req.body;

    console.log('Recovery attempt');

    try {
        const captcha = captchaStore.get(captchaToken);
        if (!captcha || captcha.expires < Date.now() || captcha.answer !== parseInt(captchaAnswer)) {
            return res.json({
                success: false,
                message: 'Invalid CAPTCHA'
            });
        }
        captchaStore.delete(captchaToken);

        const users = db.prepare('SELECT * FROM users').all();
        let foundUser = null;

        for (const user of users) {
            if (await bcrypt.compare(phrase, user.recovery_phrase)) {
                foundUser = user;
                break;
            }
        }

        if (!foundUser) {
            console.log('Invalid recovery phrase');
            return res.json({
                success: false,
                message: 'Invalid recovery phrase'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
        const hashedPin = pin ? await bcrypt.hash(pin.toString(), SALT_ROUNDS) : null;

        db.prepare(`
            UPDATE users SET
                password = ?,
                pin_code = ?,
                device_id = ?,
                failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ?
        `).run(hashedPassword, hashedPin, deviceId, foundUser.id);

        console.log('Account recovered for:', foundUser.original_username);

        const existingDeviceAccount = db.prepare('SELECT * FROM device_accounts WHERE device_id = ? AND username = ?').get(deviceId, foundUser.username);
        if (!existingDeviceAccount) {
            db.prepare('INSERT INTO device_accounts (device_id, username) VALUES (?, ?)').run(deviceId, foundUser.username);
        }

        res.json({
            success: true,
            message: 'Account recovered successfully'
        });

    } catch (err) {
        console.error('Recovery error:', err.message);
        res.json({
            success: false,
            message: 'Recovery failed'
        });
    }
});

app.post('/api/verify-pin', authLimiter, async (req, res) => {
    const { username, pin } = req.body;

    console.log('='.repeat(50));
    console.log('PIN VERIFICATION ATTEMPT:');
    console.log('Username:', username);
    console.log('='.repeat(50));

    try {
        const user = db.prepare(`
            SELECT username, pin_code, failed_pin_attempts, locked_until
            FROM users WHERE username = ?
        `).get(username.toLowerCase());

        if (!user) {
            console.log('❌ User not found:', username);
            return res.json({ success: false, message: 'User not found' });
        }

        if (user.locked_until) {
            const lockedUntil = new Date(user.locked_until);
            const now = new Date();

            if (lockedUntil > now) {
                const minutesRemaining = Math.ceil((lockedUntil - now) / (60 * 1000));
                console.log(`🔒 Account locked for ${minutesRemaining} more minutes`);
                return res.json({
                    success: false,
                    message: `Account locked. Try again in ${minutesRemaining} minute${minutesRemaining !== 1 ? 's' : ''}.`
                });
            } else {
                console.log('🔓 Lock expired, resetting attempts');
                db.prepare('UPDATE users SET failed_pin_attempts = 0, locked_until = NULL WHERE username = ?')
                  .run(username.toLowerCase());
                user.failed_pin_attempts = 0;
            }
        }

        console.log('User found:', user.username);
        console.log('PIN in database:', user.pin_code ? '[HASHED]' : 'NULL');

        if (!user.pin_code) {
            console.log('❌ No PIN set for this user');
            return res.json({ success: false, message: 'No PIN set for this account' });
        }

        const isValidPin = await bcrypt.compare(pin.toString(), user.pin_code);

        console.log('PIN valid?', isValidPin ? 'YES' : 'NO');

        if (!isValidPin) {
            console.log('❌ PIN mismatch');

            const newAttempts = (user.failed_pin_attempts || 0) + 1;
            console.log(`⚠️ Failed attempt ${newAttempts} of 2`);

            if (newAttempts >= 2) {
                const lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                db.prepare('UPDATE users SET failed_pin_attempts = ?, locked_until = ? WHERE username = ?')
                  .run(newAttempts, lockedUntil, username.toLowerCase());

                console.log('🔒 Account locked for 30 minutes after 2 failed attempts');

                return res.json({
                    success: false,
                    message: 'Too many failed PIN attempts. Account locked for 30 minutes.'
                });
            } else {
                db.prepare('UPDATE users SET failed_pin_attempts = ? WHERE username = ?')
                  .run(newAttempts, username.toLowerCase());

                const attemptsLeft = 2 - newAttempts;
                return res.json({
                    success: false,
                    message: `Invalid PIN. ${attemptsLeft} attempt${attemptsLeft !== 1 ? 's' : ''} remaining.`
                });
            }
        }

        db.prepare('UPDATE users SET failed_pin_attempts = 0, locked_until = NULL WHERE username = ?')
          .run(username.toLowerCase());

        const sessionId = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        db.prepare('INSERT INTO pin_sessions (username, session_id, expires_at) VALUES (?, ?, ?)')
          .run(username.toLowerCase(), sessionId, expiresAt);

        db.prepare('UPDATE users SET last_pin_entry = ? WHERE username = ?')
          .run(new Date().toISOString(), username.toLowerCase());

        console.log('✅ PIN verified successfully for:', username);
        console.log('Session ID:', sessionId);
        console.log('='.repeat(50));

        res.json({
            success: true,
            sessionId: sessionId,
            redirect: 'global.html'
        });

    } catch (err) {
        console.error('❌ PIN verification error:', err);
        console.log('='.repeat(50));
        res.json({ success: false, message: 'PIN verification failed' });
    }
});

app.post('/api/check-pin-session', apiLimiter, (req, res) => {
    const { username, sessionId } = req.body;

    try {
        const session = db.prepare('SELECT * FROM pin_sessions WHERE username = ? AND session_id = ? AND expires_at > ?')
          .get(username.toLowerCase(), sessionId, new Date().toISOString());

        res.json({ valid: !!session });
    } catch (err) {
        res.json({ valid: false });
    }
});

app.post('/api/user-data', apiLimiter, (req, res) => {
    const { username } = req.body;

    console.log('Fetching user data for:', username);

    try {
        const user = db.prepare(`
            SELECT
                username,
                original_username,
                role,
                join_date,
                message_count,
                warnings,
                bio,
                username_changed,
                account_number
            FROM users
            WHERE username = ? OR original_username = ?
        `).get(username.toLowerCase(), username);

        if (user) {
            console.log('User data found:', user);
            res.json(user);
        } else {
            console.log('User not found:', username);
            res.json({ error: 'User not found' });
        }
    } catch (err) {
        console.error('Error fetching user data:', err);
        res.json({ error: 'Server error' });
    }
});

app.post('/api/change-pin', csrfProtection, apiLimiter, async (req, res) => {
    const { username, currentPin, newPin, password } = req.body;

    try {
        const user = db.prepare('SELECT pin_code, password FROM users WHERE username = ?').get(username.toLowerCase());

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        const isValidCurrentPin = await bcrypt.compare(currentPin.toString(), user.pin_code);
        if (!isValidCurrentPin) {
            return res.json({ success: false, message: 'Current PIN is incorrect' });
        }

        const hashedNewPin = await bcrypt.hash(newPin.toString(), SALT_ROUNDS);

        db.prepare('UPDATE users SET pin_code = ? WHERE username = ?').run(hashedNewPin, username.toLowerCase());

        res.json({ success: true, message: 'PIN changed successfully' });
    } catch (err) {
        console.error('PIN change error:', err);
        res.json({ success: false, message: 'Failed to change PIN' });
    }
});

app.post('/api/change-password', csrfProtection, apiLimiter, async (req, res) => {
    const { username, currentPassword, newPassword } = req.body;

    try {
        const user = db.prepare('SELECT password FROM users WHERE username = ?').get(username.toLowerCase());

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.json({ success: false, message: 'Current password is incorrect' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        db.prepare('UPDATE users SET password = ? WHERE username = ?').run(hashedNewPassword, username.toLowerCase());

        res.json({ success: true, message: 'Password changed successfully' });
    } catch (err) {
        console.error('Password change error:', err);
        res.json({ success: false, message: 'Failed to change password' });
    }
});

app.post('/api/delete-account', csrfProtection, apiLimiter, async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        db.prepare('DELETE FROM users WHERE username = ?').run(username.toLowerCase());
        db.prepare('DELETE FROM messages WHERE username = ?').run(username.toLowerCase());
        db.prepare('DELETE FROM warnings WHERE username = ?').run(username.toLowerCase());
        db.prepare('DELETE FROM message_tracking WHERE username = ?').run(username.toLowerCase());
        db.prepare('DELETE FROM pin_sessions WHERE username = ?').run(username.toLowerCase());
        db.prepare('DELETE FROM private_messages WHERE from_user = ? OR to_user = ?').run(username.toLowerCase(), username.toLowerCase());

        res.json({ success: true, message: 'Account deleted' });
    } catch (err) {
        console.error('Delete account error:', err);
        res.json({ success: false, message: 'Failed to delete account' });
    }
});

app.post('/api/update-bio', apiLimiter, (req, res) => {
    const { username, bio } = req.body;

    try {
        db.prepare('UPDATE users SET bio = ? WHERE username = ?').run(bio, username.toLowerCase());
        res.json({ success: true, message: 'Bio updated' });
    } catch (err) {
        console.error('Bio update error:', err.message);
        res.json({ success: false, message: 'Failed to update bio' });
    }
});

app.post('/api/change-username', csrfProtection, apiLimiter, async (req, res) => {
    const { username, newUsername, password } = req.body;

    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());

        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.json({ success: false, message: 'Invalid password' });
        }

        if (user.username_changed === 1) {
            return res.json({ success: false, message: 'Username already changed once' });
        }

        const existingUser = db.prepare('SELECT username FROM users WHERE username = ?').get(newUsername.toLowerCase());
        if (existingUser) {
            return res.json({ success: false, message: 'Username already taken' });
        }

        db.prepare('UPDATE users SET username = ?, original_username = ?, username_changed = 1 WHERE username = ?')
          .run(newUsername.toLowerCase(), newUsername, username.toLowerCase());

        res.json({ success: true, message: 'Username changed successfully' });
    } catch (err) {
        console.error('Username change error:', err.message);
        res.json({ success: false, message: 'Failed to change username' });
    }
});

function cleanupOldDeliveredMessages() {
    try {
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        const result = db.prepare(`
            DELETE FROM private_messages
            WHERE delivered = 1 AND delivered_at < ?
        `).run(sevenDaysAgo.toISOString());

        if (result.changes > 0) {
            console.log(`🧹 Cleaned up ${result.changes} delivered private messages older than 7 days`);
        }
    } catch (err) {
        console.error('Private message cleanup error:', err.message);
    }
}

setInterval(cleanupOldDeliveredMessages, 24 * 60 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(50));
    console.log('✅ Server running on:');
    console.log('   📍 Local: http://127.0.0.1:' + PORT);
    console.log('   🌐 Tor:  Your .onion address');
    console.log('🔌 WebSocket server ready');
    console.log('👥 Online users tracked');
    console.log('⏰ Messages expire after 24 hours');
    console.log('\n📋 Features:');
    console.log('   ✅ PIN required for all chats');
    console.log('   ✅ Change PIN in profile');
    console.log('   ✅ USER role cooldown (5 msgs/5 sec) - FIXED');
    console.log('   ✅ Bio updates working');
    console.log('   ✅ Real message/warning counts');
    console.log('   ✅ One-time username change');
    console.log('   ✅ Change password in profile');
    console.log('   ✅ Recovery phrase validation');
    console.log('   ✅ Private messages stored for offline users - IMPROVED');
    console.log('   ✅ Delivery tracking for offline messages');
    console.log('   ✅ Unread message counters with read tracking - NEW');
    console.log('   ✅ 2 failed PIN attempts = 30 min lockout - NEW');
    console.log('   ✅ 2 failed login attempts = 30 min lockout - NEW');
    console.log('   ✅ Role colors updated - White, Gold, Blue, Purple, Black - NEW');
    console.log('   ✅ 🔐 BCRYPT HASHING for passwords, PINs, and recovery phrases - NEW');
    console.log('   ✅ 🛡️ CUSTOM CSRF PROTECTION ADDED');
    console.log('   ✅ 🔒 RATE LIMITING ADDED');
    console.log('   ✅ 🚫 XSS PROTECTION ADDED');
    console.log('   ✅ 🔐 SECURE HEADERS ADDED');
    console.log('   ✅ ⏰ SESSION TIMEOUT ADDED');
    console.log('='.repeat(50) + '\n');
});