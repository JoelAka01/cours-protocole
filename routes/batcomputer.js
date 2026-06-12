const express = require('express');
const router = express.Router();
const path = require('path');
const db = require('../config/db');
const { isAuthenticated } = require('../middlewares/authCheck');

router.get('/', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'bat-computer.html'));
});

router.get('/api/me', isAuthenticated, (req, res) => {
    res.json({
        id: req.session.user.id,
        username: req.session.user.username
    });
});

router.get('/api/secrets', isAuthenticated, (req, res) => {
    const gadgets = [
        { name: "Batarang", desc: "Arme de jet", icon: "fa-shuriken" },
        { name: "Batmobile", desc: "Véhicule blindé", icon: "fa-car" },
        { name: "Grappin", desc: "Déplacement vertical", icon: "fa-arrow-up" }
    ];
    res.json(gadgets);
});

router.post('/api/reports', isAuthenticated, (req, res) => {
    const { content } = req.body;
    db.prepare(`INSERT INTO reports (content, user_id) VALUES (?, ?)`).run(content, req.session.user.id);
    res.send("Rapport enregistré");
});

router.get('/admin/logs', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'ADMIN') {
        return res.status(403).send('Accès interdit');
    }

    const logs = db.prepare('SELECT * FROM connexions_audit ORDER BY timestamp DESC').all();

    let html = `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Audit Logs</title></head><body>
    <h1>Connexions Audit</h1>
    <table border="1">
        <tr><th>ID</th><th>Username</th><th>Action</th><th>IP</th><th>User-Agent</th><th>Timestamp</th></tr>`;

    logs.forEach(log => {
        html += `<tr><td>${log.id}</td><td>${log.username}</td><td>${log.action}</td><td>${log.ip_address}</td><td>${log.user_agent}</td><td>${log.timestamp}</td></tr>`;
    });

    html += `</table></body></html>`;
    res.send(html);
});

module.exports = router;
