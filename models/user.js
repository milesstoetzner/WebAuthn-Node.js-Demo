/**
 * User Schema
 * @type {mongoose.Schema}
 */

let mongoose = require('mongoose');
let Schema = mongoose.Schema;

let userSchema = new Schema ({
    userHandle: String,
    name: String,
    displayName: String,
    credentialId: String,
    credentialPublicKey: Object,
    signCount: String
    //icon: String
});

let User = mongoose.model('user', userSchema);

module.exports = User;