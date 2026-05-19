const express = require("express");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("database.db");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static("public"));

const PORT = 3000;
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
`).run();

try {
    db.prepare(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'USER'`).run();
} catch (e) {
}

db.prepare(`
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
)
`).run();

const loginAttempts = new Map();

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post("/register", async (req, res) => {

    let { username, password } = req.body;

    username = username.trim();

    if (password.length < 8) {
        return res.status(400).send("Mot de passe trop court");
    }

    try {

        const hashedPassword = await bcrypt.hash(password, 10);

        const stmt = db.prepare(`
            INSERT INTO users (username, password)
            VALUES (?, ?)
        `);

        stmt.run(username, hashedPassword);

        res.send("Utilisateur créé");

    } catch (error) {

        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).send("Nom déjà utilisé");
        }

        res.status(500).send("Erreur serveur");
    }
});
async function authMiddleware(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        res.setHeader("WWW-Authenticate", "Basic");
        return res.status(401).send("Authentification requise");
    }

    const base64 = authHeader.split(" ")[1];

    const decoded = Buffer.from(base64, "base64").toString();

    const [username, ...rest] = decoded.split(":");
    const password = rest.join(":");

    const attempt = loginAttempts.get(username);
    if (attempt && attempt.blockedUntil && Date.now() < attempt.blockedUntil) {
        return res.status(429).send("Trop de tentatives. Réessayez dans 30 secondes.");
    }

    const user = db.prepare(`
        SELECT * FROM users WHERE username = ?
    `).get(username);

    if (!user) {
        recordFailedAttempt(username);
        return res.status(401).send("Utilisateur inconnu");
    }

    const validPassword = await bcrypt.compare(
        password,
        user.password
    );

    if (!validPassword) {
        recordFailedAttempt(username);
        return res.status(401).send("Mot de passe incorrect");
    }

    loginAttempts.delete(username);

    db.prepare(`INSERT INTO logs (username) VALUES (?)`).run(username);

    req.user = user;

    next();
}

function recordFailedAttempt(username) {
    const attempt = loginAttempts.get(username) || { attempts: 0, blockedUntil: null };
    attempt.attempts += 1;
    if (attempt.attempts >= 5) {
        attempt.blockedUntil = Date.now() + 30000;
        attempt.attempts = 0;
    }
    loginAttempts.set(username, attempt);
}
app.get("/api/secrets", authMiddleware, (req, res) => {

    const gadgets = [
        {
            name: "Batarang",
            desc: "Arme de jet",
            icon: "fa-shuriken"
        },
        {
            name: "Batmobile",
            desc: "Véhicule blindé",
            icon: "fa-car"
        }
    ];

    res.json(gadgets);
});

app.get("/api/me", authMiddleware, (req, res) => {

    res.json({
        id: req.user.id,
        username: req.user.username
    });

});
app.post("/api/reports", authMiddleware, (req, res) => {

    const { content } = req.body;

    db.prepare(`
        INSERT INTO reports (content, user_id)
        VALUES (?, ?)
    `).run(content, req.user.id);

    res.send("Rapport enregistré");
});
app.get("/bat-computer", authMiddleware, (req, res) => {

    res.sendFile(
        path.join(__dirname, "private", "bat-computer.html")
    );

});

app.get("/logout", (req, res) => {
    res.setHeader("WWW-Authenticate", "Basic");
    return res.status(401).send("Déconnecté. Fermez cette fenêtre.");
});

app.listen(PORT, () => {
    console.log(`Serveur lancé sur http://localhost:${PORT}`);
});
