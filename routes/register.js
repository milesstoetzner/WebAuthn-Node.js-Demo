/**
 * Registration
 */

"use strict";

const express = require('express');
const router = express.Router();

const utils = require('./utils');
const logger = require('../config/logger');
const User = require('../models/user');
const rp = require('../models/relyingParty');

const csrf = require('csurf');
const csrfProtection = csrf();

router.use(csrfProtection);

/**
 * First part of the registration ceremony of the relying party: Initialisation
 */
router.post('/register', async (req, res, next) => {

    logger.debug('Registration');

    try {

        let name = req.body.name;
        let userHandle = utils.userHandle();
        let excludeCredentials = [];

        // check if user is authenticated
        if (req.isAuthenticated()) {

            // user wants to register additional device
            name = req.user.name;
            userHandle = Buffer.from(req.user.userHandle, 'base64');
            excludeCredentials.push({
                type: 'public-key',
                id: Buffer.from(req.user.credentialId, 'base64'),
                transports: ["usb", "nfc", "ble"]
            });

        } else {

            // new user wants to register
            if (!name) {
                logger.debug('name missing');
                req.flash('error_msg', 'Name missing');
                return res.redirect('/');
            }

            // check if name is already registered
            let user = await User.findOne({name: name}).catch(next);
            if (user && !req.isAuthenticated()) {
                logger.debug('username already registered!');
                req.flash('error_msg', 'Name already registered');
                return res.redirect('/');
            }

        }

        // create and send options
        let PublicKeyCredentialCreationOptions = {
            rp: rp,
            user: {
                id: userHandle,
                name: name,
                displayName: name
            },
            challenge: utils.challenge(),
            pubKeyCredParams: [{
                type: "public-key",
                alg: -7
            }], /* -7 for "ES256" as registered in the IANA COSE Algorithms registry */
            timeout: 60000,
            excludeCredentials: excludeCredentials, /* nothing to exclude */
            authenticatorSelection: {
                authenticatorAttachment: 'cross-platform',
                requireResidentKey: false,
                userVerification: 'preferred'
            },
            attestation: "none",
            extensions: {} /* no extensions */
        };

        logger.debug('PublicKeyCredentialCreationsOptions', JSON.stringify(PublicKeyCredentialCreationOptions));

        req.session.PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions;

        return res.render('register', {
            title: 'Registration',
            PublicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
            csrf: req.csrfToken()
        });

    } catch (e) {
        // registration step failed
        logger.debug(e);
        logger.debug('Registration failed');
        req.flash('error_msg', 'Something went wrong');
        return res.redirect('/');
    }

});

/**
 * Second part of the registration ceremony of the relying party: Verification
 */
router.post('/register/callback', async (req, res, next) => {

    logger.debug('Registration Callback');

    try {

        // decode all necessary data
        let PublicKeyCredentialCreationOptions = req.session.PublicKeyCredentialCreationOptions;
        let PublicKeyCredential = JSON.parse(req.body.PublicKeyCredential);
        let response = PublicKeyCredential.response;
        let clientData = JSON.parse(utils.array2utf8(response.clientDataJSON));
        let hash = utils.hash(Buffer.from(response.clientDataJSON));
        let attestationObject = response.attestationObject;
        let authData = utils.decodeAuthData(attestationObject.authData);
        let fmt = attestationObject.fmt;
        let attStmt = attestationObject.attStmt;

        if (!authData || !fmt || !attStmt) {
            throw 'invalid attestationObject';
        }

        logger.debug('clientData', JSON.stringify(clientData));
        logger.debug('hash', hash);
        logger.debug('authData', JSON.stringify(authData));
        logger.debug('fmt', fmt);
        logger.debug('attStmt', JSON.stringify(attStmt));

        // check expected values: type, challenge, origin and rpIdHash
        utils.equals(clientData.type, 'webauthn.create', 'Type');
        utils.equals(clientData.challenge, utils.array2base64url(PublicKeyCredentialCreationOptions.challenge), 'Challenge');
        utils.equals(clientData.origin, rp.origin, 'Origin');
        /* tokenBinding not supported */
        utils.equals(utils.array2hex(authData.rpIdHash), utils.hash(rp.id), 'RPID');

        // check userVerification respectively userPresence
        if (PublicKeyCredentialCreationOptions.authenticatorSelection.userVerification === 'required') {
            utils.matches(authData.flags, utils.FLAG_UV, 'FLAG_UV');
        } else {
            utils.matches(authData.flags, utils.FLAG_UP, 'FLAG_UP');
        }

        /* no extensions */

        // validate attestationStatement, which is in this implementation always 'none'
        logger.debug('fmt', fmt);
        switch (fmt) {
            case 'none':
                /* nothing to do */
                logger.debug('valid attestation');
                break;
            default:
                throw 'Unsupported Attestation Format';
        }

        // check if credentialId is already registered
        logger.debug('validate credentialId');
        let credentialId = utils.array2base64url(authData.attestedCredentialData.credentialId);
        let user = await User.findOne({credentialId: credentialId}).catch(next);

        if (user) {
            logger.debug('credentialId already used');
            logger.debug('registration failed');
            req.flash('error_msg', 'Credential ID already used');
            return res.redirect('/')
        }

        // check if user is authenticated and therefore wants to register additional device
        if (req.isAuthenticated()) {
            logger.debug('Registration successful');
            req.flash('success_msg', 'Registration successful. Note, that the additional credential is not saved for future authentications!');
            return res.redirect('/profile');
        }

        // create and save new user
        user = PublicKeyCredentialCreationOptions.user;
        let newUser = {
            userHandle: utils.array2base64url(user.id),
            name: user.name,
            displayName: user.displayName,
            credentialId: credentialId,
            credentialPublicKey: authData.attestedCredentialData.credentialPublicKey,
            signCount: utils.array2hex(authData.signCount)
        };

        await User(newUser).save().catch(next);

        logger.debug('user', JSON.stringify(newUser));

        // regenerate session
        req.session.regenerate((err) => {

            logger.debug('Registration successful');
            req.flash('success_msg', 'Registration successful');
            return res.redirect('/');
        });

    } catch (e) {
        // validation step failed
        logger.debug(e);
        logger.debug('Registration failed');
        req.flash('error_msg', e);
        return res.redirect('/');
    }

});

module.exports = router;