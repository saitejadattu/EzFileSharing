const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const authRoutes = require('./routes/auth');
const fileRoutes = require('./routes/file');
dotenv.config();
const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

app.use('/api/auth', authRoutes);
app.use('/api/file', fileRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
