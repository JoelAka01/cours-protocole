require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');

const { checkFingerprint } = require('./middlewares/authCheck');
const authRouter = require('./routes/auth');
const batcomputerRouter = require('./routes/batcomputer');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    name: 'bat_identity',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: './config' }),
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 1800000
    }
}));

app.use(checkFingerprint);

app.use('/auth', authRouter);
app.use('/bat-computer', batcomputerRouter);

app.get('/', (req, res) => {
    res.redirect('/auth/login');
});

app.listen(process.env.PORT, () => {
    console.log(`Serveur lancé sur http://localhost:${process.env.PORT}`);
});

