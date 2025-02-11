const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');
const ejs = require('ejs');
const multer = require('multer');
const fs = require('fs');
const flash = require('express-flash');

dotenv.config();
const app = express();

// Middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session & Flash Messages
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log('MongoDB Connection Error:', err));


    const UserSchema = new mongoose.Schema({
        username: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        age: { type: Number, default: null },
        gender: { type: String, enum: ['male', 'female', 'other'], default: 'other' },
        failedLoginAttempts: { type: Number, default: 0 },
        isLocked: { type: Boolean, default: false }
    });
    const User = mongoose.model('User', UserSchema);

// Ensure 'uploads' directory exists
const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Image Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

const uploadedPhotos = []; // Store uploaded photo paths

// Routes
app.get('/', (req, res) => {
    ejs.renderFile(__dirname + '/views/index.ejs', {
        user: req.session.user || null, 
        messages: req.flash(),
        photos: uploadedPhotos
    }, (err, str) => {
        res.render('layout', { body: str, user: req.session.user || null, messages: req.flash() });
    });
});

app.get('/login', (req, res) => {
    ejs.renderFile(__dirname + '/views/login.ejs', {
        user: req.session.user || null, 
        messages: req.flash()
    }, (err, str) => {
        res.render('layout', { body: str, user: req.session.user || null, messages: req.flash() });
    });
});

app.get('/register', (req, res) => {
    ejs.renderFile(__dirname + '/views/register.ejs', {
        user: req.session.user || null, 
        messages: req.flash()
    }, (err, str) => {
        res.render('layout', { body: str, user: req.session.user || null, messages: req.flash() });
    });
});

// Registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(password)) {
        req.flash('error', 'Password must be at least 6 characters long, contain at least 1 letter and 1 number.');
        return res.redirect('/register');
    }

    if (!username || !password) {
        req.flash('error', 'All fields are required.');
        return res.redirect('/register');
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
        req.flash('error', 'Username already taken.');
        return res.redirect('/register');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashedPassword });
    req.flash('success', 'Registration successful!');
    res.redirect('/login');
});


// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
        req.flash('error', 'Invalid username or password.');
        return res.redirect('/login');
    }

    if (user.isLocked) {
        req.flash('error', 'Your account is locked due to too many failed login attempts.');
        return res.redirect('/login');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        user.failedLoginAttempts += 1;
        if (user.failedLoginAttempts >= 5) {
            user.isLocked = true;
        }
        await user.save();
        req.flash('error', 'Invalid username or password.');
        return res.redirect('/login');
    }

    user.failedLoginAttempts = 0;
    await user.save();
    req.session.user = user;
    req.flash('success', 'Login successful!');
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    const messages = req.flash('success', 'Logged out successfully.'); 

    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
            return res.redirect('/'); 
        }
        req.session = null;
        req.sessionFlash = messages;
        res.redirect('/login');
    });
});

app.use((req, res, next) => {
    if (req.sessionFlash) {
        req.flash('success', req.sessionFlash);
        delete req.sessionFlash;
    }
    next();
});


// User Management
app.get('/users', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const users = await User.find();
    ejs.renderFile(__dirname + '/views/users.ejs', { users }, (err, str) => {
        res.render('layout', { body: str, user: req.session.user, messages: req.flash() });
    });
});

app.post('/users/delete/:id', async (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    await User.findByIdAndDelete(req.params.id);
    req.flash('success', 'User deleted successfully.');
    res.redirect('/users');
});

// Image Upload Route
app.post('/upload-avatar', upload.single('avatar'), async (req, res) => {
    if (!req.session.user) {
        req.flash('error', 'You need to be logged in to upload an avatar.');
        return res.redirect('/login');
    }
    const user = await User.findById(req.session.user._id);
    if (!user) {
        req.flash('error', 'User not found.');
        return res.redirect('/');
    }
    user.avatar = '/uploads/' + req.file.filename;
    await user.save();
    req.session.user.avatar = user.avatar;
    req.flash('success', 'Avatar updated successfully!');
    res.redirect('/');
});


app.post('/delete-account', async (req, res) => {
    if (!req.session || !req.session.user) {
        return res.redirect('/login');
    }

    try {
        await User.findByIdAndDelete(req.session.user._id);
        
        if (req.session) {
            req.flash('success', 'Your account has been deleted.');
        }

        req.session.destroy(() => {
            res.redirect('/register');
        });
    } catch (error) {
        console.error('Error deleting account:', error);
        
        if (req.session) {
            req.flash('error', 'Failed to delete account.');
        }

        res.redirect('/');
    }
});

app.get('/edit-profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('edit-profile', { user: req.session.user });
});
app.get('/edit-profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    res.render('edit-profile', { user: req.session.user });
});

app.post('/edit-profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const { username, age, gender, password } = req.body;
    const user = await User.findById(req.session.user._id);

    if (!user) {
        return res.redirect('/');
    }

    const parsedAge = parseInt(age, 10);
    if (isNaN(parsedAge) || parsedAge < 1 || parsedAge > 120) {
        req.flash('error', 'Age must be between 1 and 120.');
        return res.redirect('/edit-profile');
    }

    user.username = username || user.username;
    user.age = parsedAge;
    user.gender = gender || user.gender;

    if (password) {
        user.password = await bcrypt.hash(password, 10);
    }

    await user.save();
    req.session.user = user;

    res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));