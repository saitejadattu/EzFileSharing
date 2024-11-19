const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const router = express.Router();

router.post('/signup', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const verificationToken = crypto.randomBytes(20).toString('hex');
        console.log(req.body)
        const newUser = new User({
            email,
            password,
            role,
            verificationToken,
        });
        await newUser.save();
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'bodasaitejacomputer0@gmail.com',
                pass: 'Saiteja0@',
            },
        });
        const verifyUrl = `http://localhost:5000/api/auth/verify-email/${verificationToken}`;
        await transporter.sendMail({
            to: email,
            subject: 'Email Verification',
            text: `Click here to verify your email: ${verifyUrl}`,
        });
        res.status(200).json({ message: 'Signup successful. Please check your email for verification.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});
router.get('/verify-email/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }
        user.isVerified = true;
        user.verificationToken = null;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
});

// login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }

        if (!(await user.matchPassword(password))) {
            return res.status(400).json({ message: 'Invalid password' });
        }

        if (!user.isVerified) {
            return res.status(400).json({ message: 'Please verify your email first' });
        }

        const token = jwt.sign({ userId: user._id, role: user.role }, 'secret', { expiresIn: '1h' });

        res.status(200).json({ token });
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
});

module.exports = router;
