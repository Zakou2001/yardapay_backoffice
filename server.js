// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'yardapay-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Database setup
const db = new sqlite3.Database('./yardapay.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);

    // Clients table
    db.run(`CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        numero_telephone TEXT NOT NULL,
        pays_residence TEXT NOT NULL
    )`);

    // Transfers table
    db.run(`CREATE TABLE IF NOT EXISTS transferts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        montant_envoye REAL NOT NULL,
        frais REAL NOT NULL,
        montant_recu REAL NOT NULL,
        date DATETIME DEFAULT CURRENT_TIMESTAMP,
        pays_origine TEXT NOT NULL,
        pays_destination TEXT NOT NULL,
        moyen TEXT NOT NULL,
        FOREIGN KEY (client_id) REFERENCES clients(id)
    )`);

    // Create default admin user
    const defaultPassword = 'momo2023';
    bcrypt.hash(defaultPassword, 10, (err, hash) => {
        if (!err) {
            db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, 
                ['admin', hash]);
        }
    });
});

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Non authentifié' });
    }
    next();
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
        
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!result) return res.status(401).json({ error: 'Identifiants invalides' });
            
            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ success: true, username: user.username });
        });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Get current user
app.get('/api/current-user', requireAuth, (req, res) => {
    res.json({ username: req.session.username });
});

// Dashboard stats
app.get('/api/dashboard', requireAuth, (req, res) => {
    const stats = {};
    
    // Total clients
    db.get('SELECT COUNT(*) as total FROM clients', (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        stats.totalClients = row.total;
        
        // Total transfers
        db.get('SELECT COUNT(*) as total FROM transferts', (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            stats.totalTransferts = row.total;
            
            // Chiffre d'affaires et frais
            db.get('SELECT SUM(montant_envoye) as ca, SUM(frais) as totalFrais FROM transferts', (err, row) => {
                if (err) return res.status(500).json({ error: err.message });
                stats.chiffreAffaires = row.ca || 0;
                stats.fraisCollectes = row.totalFrais || 0;
                
                res.json(stats);
            });
        });
    });
});

// Clients CRUD
app.get('/api/clients', requireAuth, (req, res) => {
    db.all('SELECT * FROM clients ORDER BY id DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/clients', requireAuth, (req, res) => {
    const { nom, numero_telephone, pays_residence } = req.body;
    
    db.run('INSERT INTO clients (nom, numero_telephone, pays_residence) VALUES (?, ?, ?)',
        [nom, numero_telephone, pays_residence],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        }
    );
});

app.put('/api/clients/:id', requireAuth, (req, res) => {
    const { nom, numero_telephone, pays_residence } = req.body;
    
    db.run('UPDATE clients SET nom = ?, numero_telephone = ?, pays_residence = ? WHERE id = ?',
        [nom, numero_telephone, pays_residence, req.params.id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ changes: this.changes });
        }
    );
});

app.delete('/api/clients/:id', requireAuth, (req, res) => {
    db.run('DELETE FROM clients WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ changes: this.changes });
    });
});

// Transfers CRUD
app.get('/api/transferts', requireAuth, (req, res) => {
    const { dateDebut, dateFin, clientId, moyen } = req.query;
    let query = `
        SELECT t.*, c.nom as client_nom 
        FROM transferts t 
        JOIN clients c ON t.client_id = c.id 
        WHERE 1=1
    `;
    const params = [];
    
    if (dateDebut) {
        query += ' AND date >= ?';
        params.push(dateDebut);
    }
    if (dateFin) {
        query += ' AND date <= ?';
        params.push(dateFin + ' 23:59:59');
    }
    if (clientId) {
        query += ' AND client_id = ?';
        params.push(clientId);
    }
    if (moyen) {
        query += ' AND moyen = ?';
        params.push(moyen);
    }
    
    query += ' ORDER BY date DESC';
    
    db.all(query, params, (err, rows) => {
        if (err) {
            console.error('Error fetching transfers:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json(rows || []);
    });
});

app.post('/api/transferts', requireAuth, (req, res) => {
    const { client_id, montant_envoye, frais, montant_recu, pays_origine, pays_destination, moyen } = req.body;
    
    console.log('Creating transfer:', req.body);
    
    db.run(`INSERT INTO transferts (client_id, montant_envoye, frais, montant_recu, pays_origine, pays_destination, moyen) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [client_id, montant_envoye, frais, montant_recu, pays_origine, pays_destination, moyen],
        function(err) {
            if (err) {
                console.error('Error creating transfer:', err);
                return res.status(500).json({ error: err.message });
            }
            console.log('Transfer created with ID:', this.lastID);
            res.json({ id: this.lastID, success: true });
        }
    );
});

app.put('/api/transferts/:id', requireAuth, (req, res) => {
    const { client_id, montant_envoye, frais, montant_recu, pays_origine, pays_destination, moyen } = req.body;
    
    db.run(`UPDATE transferts 
            SET client_id = ?, montant_envoye = ?, frais = ?, montant_recu = ?, 
                pays_origine = ?, pays_destination = ?, moyen = ?
            WHERE id = ?`,
        [client_id, montant_envoye, frais, montant_recu, pays_origine, pays_destination, moyen, req.params.id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ changes: this.changes });
        }
    );
});

app.delete('/api/transferts/:id', requireAuth, (req, res) => {
    db.run('DELETE FROM transferts WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ changes: this.changes });
    });
});

// Analytics
app.get('/api/analytics', requireAuth, (req, res) => {
    const analytics = {};
    
    // Transfert moyen
    db.get('SELECT AVG(montant_envoye) as avg FROM transferts', (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        analytics.transfertMoyen = row.avg || 0;
        
        // Pays principal (origine)
        db.get(`SELECT pays_origine, COUNT(*) as count 
                FROM transferts 
                GROUP BY pays_origine 
                ORDER BY count DESC 
                LIMIT 1`, (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            analytics.paysPrincipal = row ? row.pays_origine : 'N/A';
            
            // Moyen principal
            db.get(`SELECT moyen, COUNT(*) as count 
                    FROM transferts 
                    GROUP BY moyen 
                    ORDER BY count DESC 
                    LIMIT 1`, (err, row) => {
                if (err) return res.status(500).json({ error: err.message });
                analytics.moyenPrincipal = row ? row.moyen : 'N/A';
                
                // Taux de frais moyen
                db.get('SELECT AVG(frais * 100.0 / montant_envoye) as tauxMoyen FROM transferts WHERE montant_envoye > 0', (err, row) => {
                    if (err) return res.status(500).json({ error: err.message });
                    analytics.tauxFraisMoyen = row.tauxMoyen || 0;
                    
                    res.json(analytics);
                });
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Serveur Yardapay démarré sur http://localhost:${PORT}`);
});
