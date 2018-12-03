/**
 * Authentication
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
 * First part of the authentication ceremony of the relying party: Initialisation
 */
router.post('/authenticate', async (req, res, next) => {

    logger.debug('Authentication');

    let name = req.body.name;
    if (!name) {
        logger.debug('name missing');
        req.flash('error_msg', 'Name missing');
        return res.redirect('/');
    }

    logger.debug('name', name);

    // find user by using the provided displayName
    let user = await User.findOne({name: name}).catch(next);

    if (!user) {
        logger.debug('user not found');
        req.flash('error_msg', 'User not found');
        return res.redirect('/');
    }

    // create and send options
    let PublicKeyCredentialRequestOptions = {
        challenge: utils.challenge(),
        timeout: 60000,
        rpId: rp.id,
        allowCredentials: [{type: "public-key", id: Buffer.from(user.credentialId, 'base64'), transports: ["usb", "nfc", "ble"]}],
        userVerification: "preferred",
        extensions: {}
    };

    logger.debug('PublicKeyCredentialRequestOptions', JSON.stringify(PublicKeyCredentialRequestOptions));

    req.session.PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions;

    return res.render('authenticate', {
        title: 'Login',
        PublicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
        csrf: req.csrfToken()
    });
});

/**
 * Second part of the authentication ceremony of the relying party: Verification
 */
router.post('/authenticate/callback', async (req, res, next) => {

    logger.debug('Authentication Callback');

    try {

        // decode all necessary data
        let PublicKeyCredentialRequestOptions = req.session.PublicKeyCredentialRequestOptions;
        let PublicKeyCredential = JSON.parse(req.body.PublicKeyCredential);
        let response = PublicKeyCredential.response;
        let authenticatorData = utils.decodeAuthData(response.authenticatorData);
        let clientData = JSON.parse(utils.array2utf8(response.clientDataJSON));
        let hash = [... Buffer.from(utils.hash(Buffer.from(response.clientDataJSON)), 'hex')];
        let userHandle = utils.array2base64url(response.userHandle);

        logger.debug('authenticatorData', JSON.stringify(authenticatorData));
        logger.debug('authenticatorDataRaw', JSON.stringify(response.authenticatorData));
        logger.debug('clientData', JSON.stringify(clientData));
        logger.debug('hash', JSON.stringify(hash));
        logger.debug('signature', JSON.stringify(response.signature));
        logger.debug('userHandle', userHandle);

        // check if received credential is allowed
        if (PublicKeyCredentialRequestOptions.allowCredentials) {
            utils.allowed(PublicKeyCredential.id, PublicKeyCredentialRequestOptions.allowCredentials);
        } else {
            logger.debug('no PublicKeyCredentialRequestOptions.allowCredentials');
        }

        // find user by using credentialId
        logger.debug('find user by credentialId');
        let user = await User.findOne({credentialId: PublicKeyCredential.id}).catch(next);

        if (user) {
            // userHandle is always null when using FIDO U2F security token
            if (userHandle) {
                utils.equals(user.userHandle, userHandle, 'User Handle');
            } else {
                logger.debug('no response.userHandle');
            }

        } else {
            logger.debug('no user found');
            throw 'no user found by credentialId';
        }

        // check expected values: type, challenge, origin and rpIdHash
        utils.equals(clientData.type, 'webauthn.get', 'Type');
        utils.equals(clientData.challenge, utils.array2base64url(PublicKeyCredentialRequestOptions.challenge), 'Challenge');
        utils.equals(clientData.origin, rp.origin, 'Origin');
        /* tokenBinding not supported */
        utils.equals(utils.array2hex(authenticatorData.rpIdHash), utils.hash(rp.id), 'RPID');

        // check userVerification respectively userPresence
        if (PublicKeyCredentialRequestOptions.userVerification === 'required') {
            utils.matches(authenticatorData.flags, utils.FLAG_UV, 'FLAG_UV');
        } else {
            utils.matches(authenticatorData.flags, utils.FLAG_UP, 'FLAG_UP');
        }

        /* no extensions */

        // verify assertionSignature
        utils.verify(user.credentialPublicKey, response.authenticatorData.concat(hash), response.signature);

        // check and update signCount
        logger.debug('validate Signature Counter');
        let signCount = utils.array2hex(authenticatorData.signCount);
        if (signCount !== 0 || user.signCount !== 0) {
            if (signCount <= user.signCount) {
                throw 'Invalid Signature Counter';
            } else {
                logger.debug('valid Signature Counter');
            }

        }

        user.signCount = signCount;
        user = await user.save().catch(next);

        logger.debug('user', JSON.stringify(user));

        // regenerate session
        req.session.regenerate((err) => {

            // login user persistent
            req.login(user, (err) => {
                if (err) {
                    logger.error(err);
                    return next(err);
                }

                logger.debug('Authentication successful');
                req.flash('success_msg', 'Authentication successful');
                return res.redirect('/profile');
            });
        });

    } catch (e) {
        // validation step failed
        logger.debug(e);
        logger.debug('Authentication failed');
        req.flash('error_msg', e);
        return res.redirect('/');
    }

});

module.exports = router;