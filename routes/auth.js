const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('../config/db');

router.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'login.html'));
});

router.post('/login', (req, res, next) => {
    const { username, password } = req.body;

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
        return res.status(401).send('Identifiants invalides');
    }

    bcrypt.compare(password, user.password).then((match) => {
        if (!match) {
            return res.status(401).send('Identifiants invalides');
        }

        req.session.regenerate((err) => {
            if (err) return next(err);

            req.session.user = { id: user.id, username: user.username, role: user.role };
            req.session.ip = req.ip;
            req.session.userAgent = req.headers['user-agent'];

            db.prepare(`INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)`)
                .run(user.username, 'LOGIN', req.ip, req.headers['user-agent']);

            req.session.save((err) => {
                if (err) return next(err);
                res.redirect('/bat-computer');
            });
        });
    });
});

router.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'register.html'));
});

router.post('/register', async (req, res) => {
    let { username, password } = req.body;

    username = username.trim();

    if (password.length < 8) {
        return res.status(400).send("Mot de passe trop court");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`).run(username, hashedPassword);
        res.redirect('/auth/login');
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).send("Nom déjà utilisé");
        }
        res.status(500).send("Erreur serveur");
    }
});

router.get('/logout', (req, res) => {
    const username = req.session.user ? req.session.user.username : 'unknown';

    db.prepare(`INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)`)
        .run(username, 'LOGOUT', req.ip, req.headers['user-agent']);

    req.session.destroy((err) => {
        if (err) return res.status(500).send('Erreur lors de la déconnexion');
        res.clearCookie('bat_identity');
        res.redirect('/auth/login');
    });
});

module.exports = router;
