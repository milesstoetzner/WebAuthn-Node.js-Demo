/**
 * This file provides auxiliary functions used during registration and authentication.
 */

"use strict";

const crypto = require('crypto');
const logger = require('../config/logger');
const cbor = require('../public/javascripts/cbor');
const EC = require('elliptic').ec;
const ec = new EC('p256');

module.exports = {

    FLAG_UP: 0x01, // Flag for userPresence
    FLAG_UV: 0x04, // Flag for userVerification
    FLAG_AT: 0x40, // Flag for attestedCredentialData
    FLAG_ED: 0x80, // Flag for extensions

    /**
     * Decodes authData to a JSON Object.
     * Reference: https://webauthn.bin.coffee/driver.js
     * @param authData
     * @returns {{rpIdHash: *, flags: *, signCount: *, attestedCredentialData: {aaugid: *, credentialId: *, credentialPublicKey: *}}}
     */
    decodeAuthData: function (authData) {
        let rpIdHash = authData.slice(0, 32);
        let flags = authData.slice(32, 33)[0];
        let signCount = authData.slice(33, 37);

        if ((flags & this.FLAG_AT) === 0x00) {
            // no attestedCredentialData
            return {
                rpIdHash: rpIdHash,
                flags: flags,
                signCount: signCount
            }
        }

        if (authData.length < 38) {
            // attestedCredentialData missing
            throw 'invalid authData.length';
        }

        let aaguid = authData.slice(37, 53);
        let credentialIdLength = (authData[53] << 8) + authData[54]; //16-bit unsigned big-endian integer
        let credenitalId = authData.slice(55, 55 + credentialIdLength);
        let credentialPublicKey = this.decodeCredentialPublicKey(authData.slice(55 + credentialIdLength));

        /* decoding extensions - not implemented */

        return {
            rpIdHash: rpIdHash,
            flags: flags,
            signCount: signCount,
            attestedCredentialData: {
                aaguid: aaguid,
                credentialId: credenitalId,
                credentialPublicKey: credentialPublicKey
            }
        }
    },

    /**
     * Decodes a COSE_Key-encoded credentialPublicKey.
     * Reference: https://webauthn.bin.coffee/driver.js
     * @param array
     * @returns {{kty: string, alg: string, crv: string, X: *, Y: *, use: string, key_ops: string}}
     */
    decodeCredentialPublicKey: function (array) {
        let credentialPublicKey = cbor.decode(new Uint8Array(array).buffer);

        const cose_kty = 1;
        const cose_kty_ec2 = 2;
        const cose_alg = 3;
        const cose_alg_ECDSA_w_SHA256 = -7;
        const cose_crv = -1;
        const cose_crv_P256 = 1;
        const cose_crv_x = -2;
        const cose_crv_y = -3;

        if (!(cose_kty in credentialPublicKey && cose_alg in credentialPublicKey && cose_crv in credentialPublicKey
            && cose_crv_x in credentialPublicKey && cose_crv_y in credentialPublicKey)) {
            throw "invalid CBOR Public Key Object";
        }
        if (credentialPublicKey[cose_kty] !== cose_kty_ec2) {
            throw "unexpected key type";
        }
        if (credentialPublicKey[cose_alg] !== cose_alg_ECDSA_w_SHA256) {
            throw "unexpected public key algorithm";
        }
        if (credentialPublicKey[cose_crv] !== cose_crv_P256) {
            throw "unexpected curve";
        }

        if (credentialPublicKey[cose_crv_x].length !== 32 || credentialPublicKey[cose_crv_y].length !== 32) {
            throw "coordinates must be 32 bytes long";
        }

        logger.debug('X', this.array2hex(credentialPublicKey[cose_crv_x]));
        logger.debug('Y', this.array2hex(credentialPublicKey[cose_crv_y]));

        return {
            kty: "EC",
            alg: "ES256",
            crv: "P256",
            x: this.array2hex(credentialPublicKey[cose_crv_x]),
            y: this.array2hex(credentialPublicKey[cose_crv_y]),
            use: "sig",
            key_ops: "verify"
        };
    },

    /**
     * Returns the hex value of an array of bytes/ buffer
     * @param array
     * @returns {string}
     */
    array2hex: (array) => {
        return Buffer.from(array).toString('hex');
    },

    /**
     * Returns the utf8 value of an array of bytes/ buffer
     * @param array
     * @returns {string}
     */
    array2utf8: (array) => {
        return Buffer.from(array).toString('utf8');
    },

    /**
     * Returns the base64 value of an array of bytes/ buffer
     * @param array
     * @returns {string}
     */
    array2base64: (array) => {
        return Buffer.from(array).toString('base64');
    },

    /**
     * Returns the base64url value of an array of bytes/ buffer
     * @param array
     * @returns {string}
     */
    array2base64url: (array) => {
        return Buffer.from(array).toString('base64').replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    },

    /**
     * Checks if value1 and value2 are equal. If not throw msg.
     * @param value1
     * @param value2
     * @param msg
     */
    equals: (value1, value2, msg) => {
        logger.debug('validate', msg);
        logger.debug('value1', value1);
        logger.debug('value2', value2);
        if (value1 !== value2) {
            throw 'Invalid ' + msg;
        }
        logger.debug('valid', msg);
    },

    /**
     * Performs bitwise logical AND between value1 and value 2 and checks if the result is null. If not throw msg.
     * This operation is used to check if specific flags of an attestationObject are set.
     * @param value1
     * @param value2
     * @param msg
     */
    matches: (value1, value2, msg) => {
        logger.debug('validate', msg);
        logger.debug('value1', value1);
        logger.debug('value2', value2);
        if ((value1 & value2) === 0x00) {
            throw 'Invalid ' + msg;
        }
        logger.debug('valid', msg);
    },

    /**
     * Checks if received credential id is listed in allowCredentials
     * @param id
     * @param allowCredentials
     */

    allowed: (id, allowCredentials) => {
        logger.debug('validate Credential ID');

        let allowed = false;

        for (let cred of allowCredentials) {
            let credId = Buffer.from(cred.id).toString('base64').replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
            logger.debug('value1', credId);
            logger.debug('value2', id);
            if (credId === id) {
                allowed = true;
                break;
            }

        }

        if (!allowed) {
            throw 'Invalid Credential ID'
        }

        logger.debug('valid Credential ID');
    },

    /**
     * Returns a new random generated userHandle as Buffer.
     * @returns {*}
     */
    userHandle: () => {
        return crypto.randomBytes(32);
    },

    /**
     * Returns a new random challenge as Buffer.
     * @returns {*}
     */
    challenge: () => {
        return crypto.randomBytes(32);
    },

    /**
     * Checks if a signature could be verified by using a publicKey, data and a given signature.
     * This operation is used to verify an assertionSignature.
     * @param publicKey
     * @param data
     * @param derSig
     */
    verify: function (publicKey, data, derSig) {
        logger.debug('validate signature');

        // import key
        let key = ec.keyFromPublic(publicKey, 'hex');

        // sha256 hash of data to verify
        let msgHash = this.hash(new Buffer(data));

        // verify signature
        let valid = key.verify(msgHash, derSig);

        if (valid) {
            logger.debug('valid signature');
        } else {
            throw 'invalid signature';
        }
    },

    /**
     * Returns the sha-256 value of an given input as hex value.
     * @param data
     * @returns {string|PromiseLike<ArrayBuffer>}
     */
    hash: function (data) {
        let hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest('hex');
    }
};