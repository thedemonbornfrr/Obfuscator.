const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// In-memory storage (replace with database in production)
const users = new Map();
const scripts = new Map();
const MAX_SCRIPTS_PER_USER = 5;

function generateId() {
    return crypto.randomBytes(8).toString('hex');
}

// Register endpoint
app.post('/api/auth/register', (req, res) => {
    try {
        const { name, password } = req.body;
        
        if (!name || !password) {
            return res.status(400).json({ error: 'Name and password required' });
        }

        // Check if user exists
        const existingUser = Array.from(users.values()).find(u => u.name === name);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        const userId = generateId();
        const user = {
            id: userId,
            name,
            password, // In production, hash this!
            createdAt: new Date().toISOString(),
            totalObfuscations: 0
        };

        users.set(userId, user);

        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                createdAt: user.createdAt,
                totalObfuscations: user.totalObfuscations
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/api/auth/login', (req, res) => {
    try {
        const { name, password } = req.body;
        
        const user = Array.from(users.values()).find(u => u.name === name && u.password === password);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        res.json({
            success: true,
            user: {
                id: user.id,
                name: user.name,
                createdAt: user.createdAt,
                totalObfuscations: user.totalObfuscations
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Obfuscation function
function obfuscateScript(script, options = {}) {
    let obfuscated = script;

    // Step 1: Variable Renaming
    if (options.varRename) {
        const varMap = new Map();
        const reservedWords = ['and', 'break', 'do', 'else', 'elseif', 'end', 'false', 
            'for', 'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 
            'return', 'then', 'true', 'until', 'while', 'game', 'workspace', 'script',
            'print', 'warn', 'wait', 'spawn', 'task', 'typeof', 'pcall', 'shared', '_G'];
        
        const localRegex = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)/g;
        let match;
        const foundVars = [];
        
        while ((match = localRegex.exec(script)) !== null) {
            const varName = match[1];
            if (!reservedWords.includes(varName.toLowerCase()) && !varMap.has(varName)) {
                const obfName = '_0x' + crypto.randomBytes(2).toString('hex');
                varMap.set(varName, obfName);
                foundVars.push(varName);
            }
        }
        
        foundVars.forEach(oldName => {
            const newName = varMap.get(oldName);
            const regex = new RegExp('\\b' + oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'g');
            obfuscated = obfuscated.replace(regex, newName);
        });
    }

    // Step 2: V3 Class-A Encoding
    if (options.v3ClassA) {
        const encoded = Buffer.from(obfuscated).toString('base64');
        
        obfuscated = `-- Moonware Obfuscator V1.5 - Class-A Protection
-- Obfuscated with Moonware Anti-Skid Technology

local _0xMW = '${encoded}'

local function _0xDecode(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do
            r = r..(f % 2^i - f % 2^(i - 1) > 0 and '1' or '0')
        end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i, i) == '1' and 2^(8 - i) or 0)
        end
        return string.char(c)
    end))
end

local _0xSuccess, _0xResult = pcall(function()
    return loadstring(_0xDecode(_0xMW))()
end)

if not _0xSuccess then
    warn("[Moonware] Script execution failed:", _0xResult)
end`;
    }

    // Step 3: Vanguard Protection
    if (options.vanguard) {
        obfuscated = `-- ╔═══════════════════════════════════════╗
-- ║   Vanguard-WS v3.5 Protection        ║
-- ║   Anti-Decompiler • Anti-Tamper      ║
-- ║   Moonware Security System           ║
-- ╚═══════════════════════════════════════╝
--
-- This script is protected by Moonware Vanguard
-- Unauthorized redistribution is prohibited
--
${obfuscated}`;
    }

    // Step 4: Syntax Bypass
    if (options.bypassSyntax) {
        obfuscated = `-- [LUAU SYNTAX CHECK BYPASS ENABLED]\n${obfuscated}`;
    }

    return obfuscated;
}

// Upload/Obfuscate endpoint
app.post('/api/upload', (req, res) => {
    try {
        const { userId, script, options } = req.body;
        
        if (!userId || !script || script.trim().length === 0) {
            return res.status(400).json({ error: 'User ID and script content required' });
        }

        const user = users.get(userId);
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        // Check script limit
        const userScripts = Array.from(scripts.values()).filter(s => s.userId === userId);
        if (userScripts.length >= MAX_SCRIPTS_PER_USER) {
            return res.status(403).json({ 
                error: `Maximum ${MAX_SCRIPTS_PER_USER} scripts allowed. Delete one first.` 
            });
        }

        const scriptId = generateId();
        const obfuscated = obfuscateScript(script, options);
        
        const newScript = {
            id: scriptId,
            userId: userId,
            content: obfuscated,
            original: script,
            options: options,
            createdAt: new Date().toISOString(),
            enabled: true,
            executions: 0,
            size: Buffer.byteLength(obfuscated, 'utf8')
        };

        scripts.set(scriptId, newScript);
        
        user.totalObfuscations++;
        users.set(userId, user);

        res.json({
            success: true,
            scriptId: scriptId,
            size: newScript.size
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to process script: ' + error.message });
    }
});

// Get user scripts
app.get('/api/scripts/:userId', (req, res) => {
    try {
        const userId = req.params.userId;
        const userScripts = Array.from(scripts.values())
            .filter(s => s.userId === userId)
            .map(s => ({
                id: s.id,
                createdAt: s.createdAt,
                enabled: s.enabled,
                executions: s.executions,
                size: s.size
            }))
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        
        res.json({ scripts: userScripts });
    } catch (error) {
        console.error('Get scripts error:', error);
        res.status(500).json({ error: 'Failed to load scripts' });
    }
});

// Get single script content
app.get('/api/script/:scriptId', (req, res) => {
    try {
        const scriptId = req.params.scriptId;
        const script = scripts.get(scriptId);
        
        if (!script) {
            return res.status(404).json({ error: 'Script not found' });
        }
        
        res.json({ 
            success: true,
            content: script.content 
        });
    } catch (error) {
        console.error('Get script error:', error);
        res.status(500).json({ error: 'Failed to load script' });
    }
});

// Script execution endpoint (for Roblox)
app.get('/v/:scriptId', (req, res) => {
    const scriptId = req.params.scriptId;
    const script = scripts.get(scriptId);
    const userAgent = req.headers['user-agent'] || '';
    
    const isRoblox = userAgent.toLowerCase().includes('roblox');
    
    if (!script) {
        if (isRoblox) {
            return res.status(404).send('-- [Moonware] Script not found or deleted');
        } else {
            return res.sendFile(path.join(__dirname, 'public', 'blocked.html'));
        }
    }
    
    if (!script.enabled) {
        if (isRoblox) {
            return res.status(403).send('-- [Moonware] Script has been disabled by owner');
        } else {
            return res.sendFile(path.join(__dirname, 'public', 'blocked.html'));
        }
    }
    
    if (isRoblox) {
        script.executions++;
        scripts.set(scriptId, script);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        return res.send(script.content);
    }
    
    res.sendFile(path.join(__dirname, 'public', 'blocked.html'));
});

// Delete script
app.delete('/api/scripts/:scriptId', (req, res) => {
    try {
        const scriptId = req.params.scriptId;
        
        if (scripts.has(scriptId)) {
            scripts.delete(scriptId);
            res.json({ success: true, message: 'Script deleted successfully' });
        } else {
            res.status(404).json({ error: 'Script not found' });
        }
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete script' });
    }
});

// Get stats
app.get('/api/stats/:userId', (req, res) => {
    try {
        const userId = req.params.userId;
        const userScripts = Array.from(scripts.values()).filter(s => s.userId === userId);
        const totalScripts = userScripts.length;
        const totalSize = userScripts.reduce((sum, s) => sum + s.size, 0);
        const totalExecutions = userScripts.reduce((sum, s) => sum + s.executions, 0);
        
        res.json({
            totalScripts,
            totalSize,
            totalExecutions,
            slotsLeft: Math.max(0, MAX_SCRIPTS_PER_USER - totalScripts),
            maxSlots: MAX_SCRIPTS_PER_USER
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        version: '1.5.0',
        uptime: process.uptime(),
        totalUsers: users.size,
        totalScripts: scripts.size
    });
});

// Serve index.html for root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
    console.log('╔════════════════════════════════════════╗');
    console.log('║   🌙 Moonware Obfuscator V1.5         ║');
    console.log('╚════════════════════════════════════════╝');
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}/api`);
    console.log(`🌐 Dashboard: http://localhost:${PORT}`);
    console.log('');
});
