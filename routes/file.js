const express = require('express');
const multer = require('multer');
const path = require('path');
const File = require('../models/File');
const User = require('../models/User');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const router = express.Router();
const upload = multer({
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter(req, file, cb) {
        const allowedTypes = ['application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];

        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only pptx, docx, and xlsx are allowed.'));
        }
    }
});
router.post('/upload', upload.single('file'), async (req, res) => {
    const { authorization } = req.headers;
    if (!authorization) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const token = authorization.split(' ')[1];
    try {
        const decoded = jwt.verify(token, 'secret');
        const user = await User.findById(decoded.userId);

        if (user.role !== 'ops') {
            return res.status(403).json({ message: 'Forbidden. Only Ops users can upload files' });
        }

        const newFile = new File({
            filename: req.file.originalname,
            filepath: req.file.path,
            userId: user._id,
        });

        await newFile.save();
        res.status(200).json({ message: 'File uploaded successfully' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});
router.get('/files', async (req, res) => {
    try {
        const files = await File.find().populate('userId', 'email role');
        res.status(200).json(files);
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/download/:fileId', async (req, res) => {
    const { fileId } = req.params;
    const { authorization } = req.headers;

    if (!authorization) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const token = authorization.split(' ')[1];
    try {
        const decoded = jwt.verify(token, 'secret');
        const user = await User.findById(decoded.userId);

        if (user.role !== 'client') {
            return res.status(403).json({ message: 'Forbidden. Only Client users can download files' });
        }

        const file = await File.findById(fileId);
        if (!file) {
            return res.status(404).json({ message: 'File not found' });
        }

        const downloadLink = crypto.createHash('sha256').update(file._id.toString()).digest('hex');
        res.status(200).json({
            'download-link': `/download-file/${downloadLink}`,
            message: 'success'
        });
    } catch (err) {
        res.status(500).json({ message: 'Server Error' });
    }
});

module.exports = router;
