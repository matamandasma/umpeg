import express, { json, request } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/db.js';

const router = express.Router();

const cookiesOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 30*24*60*60*1000
}

const generateToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: '30d'
    });
}

//Register
router.post('/register', async(req, res) => {
    const {username, email, password} = req.body;

    if (!username || !email || !password){
        return res.status(400).json({ message: 'Please provide all required fields' });
    }

    const userExists = await pool.query( 'SELECT * FROM users WHERE email = $1', [email] );

    if (userExists.rows.length > 0) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await pool.query(
        'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, name, email', [username, email, hashedPassword]
    );

    const token = generateToken(newUser.rows[0].id);

    res.cookie('token', token, cookiesOptions);

    return res.status(201).json({ user: newUser.rows[0] });
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password ) {
        return res.status(400).json({ message: 'Please provide all required fields' });
    }

    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    const userData = user.rows[0];

    const isMatch = await bcrypt.compare(password, userData.password);

    if (!isMatch) {
        return res.status(400),json({ message: 'Invalid credentials' });
    } 

    const token = generateToken(userData.id);

    res.cookie('token', token, cookiesOptions);

    res.json({ 
        user: { 
        id: userData.id, 
        username: userData.username, 
        email: userData.email }
    });

})

router.get('/me', async (req, res) => {
    res.json(req, user)
})

router.post('/logout', (req, res) => {
    res.cookie('token', '', { ...cookiesOptions, maxAge: 1 });
    res.json({ message: 'Logged out successfully' });
})