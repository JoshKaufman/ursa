// Copyright 2012 The Obvious Corporation.

/*
 * "rsab": RSA crypto, with an emphasis on Buffer objects
 */

/*
 * Modules used
 */

var rsabNative = require("../bin/rsabNative");

/*
 * Exported bindings
 */

/*
 * Initialization
 */

// This forces OpenSSL to be initialized.
require("crypto");

module.exports = {
    hello: rsabNative.hello
};
