2018-09-15, Version 0.10.1
==========================

 * folk ursa (Raymond Feng)

 * test(ci): add node versions 8, 9 and 10 to build pipeline (Jan Kuri)

 * update(): update to NodeJS 10 or OpenSSL 1.1.0 (closes #167) (Jan Kuri)

 * add utf16le unicode (chenhao)

 * fix build badge (Josh Kaufman)

 * fix build url (Josh Kaufman)

 * update readme for ownership transfter (Josh Kaufman)

 * adding node 7 to travis (Chris Manson)

 * converting over to use mocha for the test harness (Chris Manson)

 * maintainer needed (Jeremie Miller)

 * Test against node v5 and v6 (Michael Wain)

 * Updating method binding to use SetPrototypeMethod (Michael Wain)

 * Issue #128 Changed minimum node engine to >= 0.10. Fixed typo (CT Arrington)

 * Issue #128 Changed minimum node engine to >= 0.10 (CT Arrington)

 * update binding.gyp (Vladimir Bulyga)

 * update install instructions for windows (Denise Draper)

 * Add table of contents, re-order build sections (Denise Draper)

 * Remove asprintf. It's not used any more. (David Halls)

 * Fix build on Node 0.12 (David Halls)

 * test 0.12 too (Adriano Raiano)

 * new rev for node v4+, fixes #102 (Jeremie Miller)

 * Safer with statement group (David Halls)

 * Tidy up semicolons (David Halls)

 * Fix failing tests. Need to return from function when do NaNReturn. (David Halls)

 * use always newest node v4.x version (Adriano Raiano)

 * 0 (Chris Manson)

 * adding gcc-4.8 to the travis install (Chris Manson)

 * adding env for Travis build (Chris Manson)

 * update travis.yml to node 4.0 (bellbind)

 * quick hack for switching to nan-2.0.9 for node-4.0 (module worked but npm test not worked) (bellbind)

 * usage fixup (yelo)

 * Update license attribute (Peter deHaan)

 * Have the `update(...)` method of Signer and Verifier to return `this`. (Pier Fumagalli)

 * bump nan@1.7.0, fixes #82, h/t @mattcollier (Jeremie Miller)

 * Fix README for use_pss_padding argument (David Halls)

 * Tidy up and fix PSS. Add tests. (David Halls)

 * Allow Debug builds (Bryan English)

 * Update README.md (AJ ONeal)

 * More NAN fixes. (mbullington)

 * Fix to work with NAN. (mbullington)

 * add travis build status (Jeremie Miller)

 * update all the links for the maintainer change, bump ver (Jeremie Miller)

 * 0.11 --> 0.12 (C J Silverio)

 * Testing on node 0.10 caught a bug! (C J Silverio)

 * Let's test across various nodes with Travis. (C J Silverio)

 * Bumped nan to 1.6.2. Completed the port, mostly by restoring all the defensive programming & missing argument checks. (C J Silverio)

 * Jshint noticed some minor problems here. (C J Silverio)

 * Migrated ursa to use NAN macros to hide away V8 api changes. (C J Silverio)

 * Beat to quarters and clear for action. (C J Silverio)

 * Fix tests. (Michael Bullington)

 * Added PrivateKey.getPrivateExponent(). (Michael Bullington)

 * fix the conflict and merge in the openssh contrib from @13W (Jeremie Miller)

 * Add other repos of interest (AJ ONeal)

 * Added simple encrypt / decrypt example (AJ ONeal)

 * bump ver to 0.8.1 with the clean build and new readme (Jeremie Miller)

 * also check asprintf response and clear up that warning (Jeremie Miller)

 * don't re-define so we don't trigger a build warning (Jeremie Miller)

 * minimal travis-ci test (Jeremie Miller)

 * update the description and author/links/notes with nodeprime maintenance ongoing (Jeremie Miller)

 * Use `process.config` to determine build type (Maciej Małecki)

 * Transfer notice (Anton Kovalyov)

 * Add notice about maintenance (or lack thereof) (Dan Pupius)

 * added small mention of the new method in the README (matt.todd)

 * added test around the new method (matt.todd)

 * added error checking (matt.todd)

 * created api to enable the creation of a private key given the individual componenets of a private key (matt.todd)

 * Add link to latest Visual Studio (jimmydorry)

 * Include string.h. fix Medium/ursa#49 (leeyeh)

 * Ensure password and cipher args get freed. (Matt MacAulay)

 * Added support for saving encrypted private keys (Matt MacAulay)

 * openSshPublicKey hangs in a loop (Vladimir Bulyga)

 * Add support for PEM with passphrase detection (Alexander Rysenko)

 * update readme (Vladimir Bulyga)

 * implemented reading from openssh public key (Vladimir Bulyga)

 * Revert "Make OAEP default for publicDecrypt and privateEncrypt" No OAEP for publicDecrypt and privateEncrypt because they're meant for signing (David Halls)

 * Make OAEP default for publicDecrypt and privateEncrypt (David Halls)

 * Expose PSS padding add and verify functions (David Halls)

 * Don't try to interpret RSA errors - always throw exception. Since public decrypt throws exceptions anyway, now verify is consistent - changes the API - verify functions never return false, they always throw an exception on fail (David Halls)

 * Test for more error codes which can result from bad sig (as opposed to lib failure or malloc error) (David Halls)

 * Catch more PKCS1 errors (David Halls)

 * Tidy up. Always close. Catch more PSS verify statuses. (David Halls)

 * Change default PSS padding to hash length to match JOSE default (see http://www.ietf.org/mail-archive/web/jose/current/msg02905.html) (David Halls)

 * Allow PSS to be specified with padding=true (David Halls)

 * Close scope when raising exception (David Halls)

 * Update package.json (CoryGH)

 * Add PSS padding for signatures (David Halls)

 * added test cases (Kris Brown)

 * updated documentation to cover support for defaulting padding modes in javascript layer (Kris Brown)

 * fixed export of RSA_NO_PADDING (Kris Brown)

 * add support to supply padding type to private encrypt and public decrypt (Kris Brown)

 * Bump version to be ready for republishing. (Dan Bornstein)

 * Add missing `return`. (Dan Bornstein)

 * Restore final newlines (Schabse Laks)

 * Fix install script for Node 0.6 (Schabse Laks)

 * Separate asprintf.h (Schabse Laks)

 * Use inline links (Schabse Laks)

 * Document Windows support (Schabse Laks)

 * Cross-platform installer (Schabse Laks)

 * Fix non-Windows support (Schabse Laks)

 * Ignore newline differences (Schabse Laks)

 * Fix OpenSSL initialization (Schabse Laks)

 * Fix Visual C++ compilation errors (Schabse Laks)

 * Link to OpenSSL on Windows (Schabse Laks)

 * Add compatibility note. (Dan Bornstein)

 * Handle both variants of key generation. (Dan Bornstein)

 * Add default for `node_shared_openssl`. (Dan Bornstein)

 * Again. (Dan Bornstein)

 * Pointless tweak. (Dan Bornstein)

 * Credits. (Dan Bornstein)

 * I actually think this should still work for Node 0.6.*. (Dan Bornstein)

 * Improved error checking. (Dan Bornstein)

 * Undo `--verbose`. (Dan Bornstein)

 * Move the `conditions` section. (Dan Bornstein)

 * Attempt to conditionally change `include_dirs`. (Dan Bornstein)

 * `node-gyp --verbose` (Dan Bornstein)

 * Tweaks. (Dan Bornstein)

 * First attempt to make `node-gyp` work. (Dan Bornstein)

 * Update contributors. (Dan Bornstein)

 * Set padding default in js, not C++; pub-en/pri-de (Tyler Neylon)

 * Support old-style padding for public-en/priv.-de. (Tyler Neylon)

 * Expand slightly. (Dan Bornstein)


2012-04-04, Version 0.6.8
=========================

 * Fix typo. (Dan Bornstein)


2012-03-29, Version 0.6.7
=========================

 * New coercers. (Dan Bornstein)

 * This comment was basically a TODO. Make it more sensible. (Dan Bornstein)


2012-03-09, Version 0.6.6
=========================

 * Work around "npm publish" bug. (Dan Bornstein)


2012-03-06, Version 0.6.5
=========================

 * Add type-general key reader function, createKey(). (Dan Bornstein)

 * Document. (Dan Bornstein)


2012-03-01, Version 0.6.4
=========================

 * Add sameness / equality checks. (Dan Bornstein)


2012-02-29, Version 0.6.3
=========================

 * Bump version. (Dan Bornstein)

 * Added type assertion functions. (Dan Bornstein)

 * Bind the test script. (Dan Bornstein)


2012-02-27, Version 0.6.2
=========================

 * Add "use strict". (Dan Bornstein)


2012-02-24, Version 0.6.1
=========================

 * Bump version. (Dan Bornstein)

 * Add convenient hashAndSign() and hashAndVerify(). (Dan Bornstein)


2012-02-24, Version 0.6.0
=========================

 * Bump version and add some keywords. (Dan Bornstein)

 * I got my separator wrong. (Dan Bornstein)

 * Add the remaining tests. (Dan Bornstein)

 * Add the easy tests. (Dan Bornstein)

 * Expose signing and verification. (Dan Bornstein)

 * Make verify() return a boolean. (Dan Bornstein)

 * It all seems to be working. (Dan Bornstein)

 * Add some tests. (Dan Bornstein)

 * Convert debug message to sanity check. (Dan Bornstein)

 * Fix problems. (Dan Bornstein)

 * Add wrappers for RSA_sign(), RSA_verify(), and OBJ_txt2nid(). (Dan Bornstein)


2012-02-17, Version 0.4.13
==========================

 * Sort. (Dan Bornstein)

 * Add type testers. (Dan Bornstein)

 * Looks like NPM uses this. (Dan Bornstein)


2012-02-10, Version 0.4.12
==========================

 * Righto. (Dan Bornstein)

 * Helps to notice newlines. (Dan Bornstein)


2012-02-10, Version 0.4.11
==========================

 * Bump version. (Dan Bornstein)

 * Better exception messages when constructing keys. (Dan Bornstein)

 * Fix file name, and clarify a little. (Dan Bornstein)

 * I feel capital. (Dan Bornstein)

 * Add a couple TODOs. (Dan Bornstein)

 * Clean up #includes. (Dan Bornstein)


2012-02-10, Version 0.4.10
==========================

 * And one more. (Dan Bornstein)

 * Fix syntax error. (Dan Bornstein)


2012-02-10, Version 0.4.9
=========================

 * First release!
