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

app.use(express.static(path.join(__dirname, 'public')));


app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post("/register", async (req, res) => {

    let { username, password } = req.body;

    username = username.trim();

    // Vérification mot de passe
    if (password.length < 8) {
        return res.status(400).send("Mot de passe trop court");
    }

    try {

        // Hash du mot de passe
        const hashedPassword = await bcrypt.hash(password, 10);

        const stmt = db.prepare(`
            INSERT INTO users (username, password)
            VALUES (?, ?)
        `);

        stmt.run(username, hashedPassword);

        res.send("Utilisateur créé");

    } catch (error) {

        // Username déjà utilisé
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

    // "Basic xxxxx"
    const base64 = authHeader.split(" ")[1];

    const decoded = Buffer.from(base64, "base64").toString();

    const [username, password] = decoded.split(":");

    const user = db.prepare(`
        SELECT * FROM users WHERE username = ?
    `).get(username);

    if (!user) {
        return res.status(401).send("Utilisateur inconnu");
    }

    const validPassword = await bcrypt.compare(
        password,
        user.password
    );

    if (!validPassword) {
        return res.status(401).send("Mot de passe incorrect");
    }

    req.user = user;

    next();
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

app.listen(PORT, () => {
    console.log(`Serveur lancé sur http://localhost:${PORT}`);
});
