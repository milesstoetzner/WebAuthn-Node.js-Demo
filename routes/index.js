"use strict";

const express = require('express');
const router = express.Router();

const logger = require('../config/logger');
const passport = require('passport');
const User = require('../models/user');

const csrf = require('csurf');
const csrfProtection = csrf();

router.use(csrfProtection);

/**
 * Persistent Authenticated Session
 */

// Logout authenticated user
router.post('/logout', (req, res, next) => {
    req.logout();
    req.flash('success_msg', 'Logged out');
    return res.redirect('/');
});

// Saves the mongo id of an user in the session
passport.serializeUser((user, next) => {
    next(null, user.id);
});

// Attaches information about the user to req.user
passport.deserializeUser((id, next) => {
    User.findById(id, function (err, user) {
        next(err, user);
    });
});

/**
 * Navigation Routes
 */

// Landing page
router.get('/', (req, res, next) => {

    if (req.isAuthenticated()) {
        return res.redirect('/profile');
    }

    return res.render('index', {title: 'Ascensus', csrf: req.csrfToken()});
});

// Help page with information about this project
router.get('/help', (req, res, next) => {
    return res.render('help', {title: 'Help'});
});

// User profile page
router.get('/profile', (req, res, next) => {

    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Not authenticated');
        return res.redirect('/');
    }

    return res.render('profile', {title: req.user.username, user: req.user, csrf: req.csrfToken()});
});

// Returns user's registered information
router.get('/user', (req, res, next) => {

    if (!req.isAuthenticated()) {
        req.flash('error_msg', 'Not authenticated');
        return res.redirect('/');
    }

    // deep copy
    let user = JSON.parse(JSON.stringify(req.user));

    // remove monogdb attributes
    delete user._id;
    delete user.__v;

    return res.json(user);
});

module.exports = router;