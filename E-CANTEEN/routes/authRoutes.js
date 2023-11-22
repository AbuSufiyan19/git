const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

router.get('/signup', (req, res) => {
  res.render('signup', { message: req.flash('error') });
});

router.post('/signup', async (req, res) => {
  // Signup logic remains the same
  try {
    const { username, password, email, phonenumber } = req.body;

    // Check if the username already exists
    const existingUser = await User.findOne({  email });

    if (existingUser) {
      req.flash('error', 'Username or email already exists. Please choose a different username or email.');
      return res.redirect('/signup');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({
      username,
      password: hashedPassword,
      email,
      phonenumber,
    });

    // Save the user to the database
    await user.save();

    // Redirect to login after successful signup
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

router.get('/login', (req, res) => {
  res.render('login', { message: req.flash('error') });
});

router.post('/login', async (req, res) => {
  // Login logic remains the same
  try {
    const { email, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ email });

    if (!user) {
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
    }

    // Check the password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id }, 'secret_key', { expiresIn: '1h' });

    // Set the token in the cookie
    res.cookie('token', token);

    // Redirect to the index page after successful login
    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

const authenticateToken = async (req, res, next) => {
  // Authentication middleware logic remains the same
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  jwt.verify(token, 'secret_key', async (err, decoded) => {
    if (err) {
      return res.redirect('/login');
    }

    try {
      const user = await User.findById(decoded.userId);
      if (!user) {
        return res.redirect('/login');
      }

      req.user = { userId: decoded.userId, username: user.username };
      next();
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
  });
};

router.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

router.get('/signup', (req, res) => {
  res.redirect('/signup');
});


router.get('/', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).exec();

    if (!user) {
      return res.redirect('/login');
    }

    // Pass the username to the index page rendering
    res.render('index', { username: user.username });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});
router.get('/adminlogin', function(req, res) {
  res.render('adminlogin'); // Assuming adminlogin.ejs is in your views directory
});

module.exports = router;
