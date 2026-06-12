const db = require('../config/db');

function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    return res.status(401).redirect('/auth/login');
}

function checkFingerprint(req, res, next) {
    if (req.session && req.session.user) {
        if (req.session.ip !== req.ip || req.session.userAgent !== req.headers['user-agent']) {
            db.prepare(`INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)`)
                .run(req.session.user.username, 'FRAUD', req.ip, req.headers['user-agent']);

            req.session.destroy(() => {
                res.clearCookie('bat_identity');
                return res.status(401).send('Session invalidée : empreinte suspecte');
            });
            return;
        }
    }
    next();
}

module.exports = { isAuthenticated, checkFingerprint };
