// Copyright 2012 The Obvious Corporation.

#include "ursaNative.h"
#include <node_buffer.h>
#include <stdio.h>
#include <stdlib.h>

// FIXME: Do we need all of these?
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

using namespace v8;


/*
 * Initialization and binding
 */

/**
 * Top-level initialization function.
 */
void init(Handle<Object> target) {
    RsaWrap::InitClass(target);
}

NODE_MODULE(ursaNative, init)

/**
 * Helper for prototype binding.
 */
#define BIND(proto, highName, lowName) \
    (proto)->Set(String::NewSymbol(#highName), \
        FunctionTemplate::New(lowName)->GetFunction())

/**
 * Initialize the bindings for this class.
 */
void RsaWrap::InitClass(Handle<Object> target) {
    Local<String> className = String::NewSymbol("RsaWrap");

    // Basic instance setup
    Local<FunctionTemplate> tpl = FunctionTemplate::New(New);

    tpl->SetClassName(className);
    tpl->InstanceTemplate()->SetInternalFieldCount(1); // required by ObjectWrap

    // Prototype method bindings
    Local<ObjectTemplate> proto = tpl->PrototypeTemplate();

    BIND(proto, generatePrivateKey, GeneratePrivateKey);
    BIND(proto, getExponent,        GetExponent);
    BIND(proto, getModulus,         GetModulus);
    BIND(proto, getPrivateKeyPem,   GetPrivateKeyPem);
    BIND(proto, getPublicKeyPem,    GetPublicKeyPem);
    BIND(proto, privateDecrypt,     PrivateDecrypt);
    BIND(proto, privateEncrypt,     PrivateEncrypt);
    BIND(proto, publicDecrypt,      PublicDecrypt);
    BIND(proto, publicEncrypt,      PublicEncrypt);
    BIND(proto, setPrivateKeyPem,   SetPrivateKeyPem);
    BIND(proto, setPublicKeyPem,    SetPublicKeyPem);

    // Store the constructor in the target bindings.
    target->Set(className, Persistent<Function>::New(tpl->GetFunction()));
}


/*
 * Helper functions
 */

/**
 * Schedule the current SSL error as a higher-level exception.
 */
static void scheduleSslException() {
    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<Value> exception = Exception::Error(String::New(err));

    ERR_clear_error();
    ThrowException(exception);
}

/**
 * Schedule an "allocation failed" exception. This (tries) to allocate
 * as well, which very well could (probably will) fail too, but it's the
 * best we can do in a bad situation.
 */
static void scheduleAllocException() {
    ThrowException(Exception::Error(String::New("Allocation failed.")));
}

/**
 * Check that the given argument index exists and is a Buffer. Returns
 * true if so. Schedules an exception and returns false if not.
 */
static bool isBuffer(const Arguments& args, int index) {
    if (args.Length() <= index) {
        char *message = NULL;
        asprintf(&message, "Missing args[%d].", index);
        ThrowException(Exception::TypeError(String::New(message)));
        free(message);
        return false;
    }

    if (!node::Buffer::HasInstance(args[index])) {
        char *message = NULL;
        asprintf(&message, "Expected a Buffer in args[%d].", index);
        ThrowException(Exception::TypeError(String::New(message)));
        free(message);
        return false;
    }

    return true;
}

/**
 * Get a Buffer out of the args[0], converted to a freshly-allocated
 * memory BIO. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns NULL.
 */
static BIO *getArg0Buffer(const Arguments& args) {
    if (!isBuffer(args, 0)) { return NULL; }

    Local<Object> buf = args[0]->ToObject();
    char *data = node::Buffer::Data(buf);
    ssize_t length = node::Buffer::Length(buf);
    BIO *bp = BIO_new_mem_buf(data, length);

    if (bp == NULL) { scheduleSslException(); }

    return bp;
}

/**
 * Get a Buffer out of args[1], converted to a freshly-allocated (char
 * *). Returns a non-null pointer on success. On failure, schedules an
 * exception and returns NULL.
 */
static char *getArg1String(const Arguments& args) {
    if (!isBuffer(args, 1)) { return NULL; }

    Local<Object> buf = args[1]->ToObject();
    char *data = node::Buffer::Data(buf);
    ssize_t length = node::Buffer::Length(buf);
    char *result = (char *) malloc(length + 1);

    if (result == NULL) {
        scheduleAllocException();
        return NULL;
    }

    memcpy(result, data, length);
    result[length] = '\0';
    return result;
}

/*
 * RsaWrap implementation
 */

/**
 * Straightforward constructor. Nothing much to initialize, other than
 * to ensure that our one instance variable is sanely NULLed.
 */
RsaWrap::RsaWrap() {
    rsa = NULL;
}

/**
 * Destructor, which is called automatically via the ObjectWrap mechanism
 * when the corresponding high-level object gets gc'ed.
 */
RsaWrap::~RsaWrap() {
    if (rsa != NULL) {
        RSA_free(rsa);
    }
}

/**
 * Get an (RsaWrap *) out of the given arguments, expecting the
 * underlying (RSA *) to be non-null and more specifically a private
 * key. Returns a non-null pointer on success. On failure, schedules
 * an exception and returns null.
 */
RsaWrap *RsaWrap::unwrapExpectPrivateKey(const Arguments& args) {
    RsaWrap *obj = unwrapExpectSet(args);

    if ((obj != NULL) && (obj->rsa->d != NULL)) {
        return obj;
    }

    Local<Value> exception =
        Exception::Error(String::New("Expected a private key."));
    ThrowException(exception);
    return NULL;
}

/**
 * Get an (RsaWrap *) out of the given arguments, expecting the underlying
 * (RSA *) to be non-null. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns null.
 */
RsaWrap *RsaWrap::unwrapExpectSet(const Arguments& args) {
    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());

    if (obj->rsa != NULL) {
        return obj;
    }

    Local<Value> exception = Exception::Error(String::New("Key not yet set."));
    ThrowException(exception);
    return NULL;
}

/**
 * Get an (RsaWrap *) out of the given arguments, expecting the underlying
 * (RSA *) to be null. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns null.
 */
RsaWrap *RsaWrap::unwrapExpectUnset(const Arguments& args) {
    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());

    if (obj->rsa == NULL) {
        return obj;
    }

    Local<Value> exception = Exception::Error(String::New("Key already set."));
    ThrowException(exception);
    return NULL;
}

/**
 * Construct an empty instance.
 */
Handle<Value> RsaWrap::New(const Arguments& args) {
    RsaWrap *obj = new RsaWrap();
    obj->Wrap(args.This());

    return args.This();
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::GeneratePrivateKey(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectUnset(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

/**
 * Get the public exponent of the underlying RSA object. The return
 * value is a Buffer containing the unsigned number in big-endian
 * order.
 */
Handle<Value> RsaWrap::GetExponent(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    BIGNUM *number = obj->rsa->e; // Note: Modulus is target->n.
    int length = BN_num_bytes(number);
    node::Buffer *result = node::Buffer::New(length);

    if (result == NULL) {
        scheduleAllocException();
        return Undefined();
    }

    if (BN_bn2bin(number, (unsigned char *) node::Buffer::Data(result)) < 0) {
        scheduleSslException();
        delete result;
        return Undefined();
    }

    return result->handle_;
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::GetModulus(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::GetPrivateKeyPem(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectPrivateKey(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::GetPublicKeyPem(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::PrivateDecrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectPrivateKey(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::PrivateEncrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectPrivateKey(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::PublicDecrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::PublicEncrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::SetPrivateKeyPem(const Arguments& args) {
    HandleScope scope;
    bool ok = true;

    RsaWrap *obj = unwrapExpectUnset(args);
    ok &= (obj != NULL);

    BIO *bp = NULL;
    if (ok) {
        bp = getArg0Buffer(args);
        ok &= (bp != NULL);
    }

    char *password = NULL;
    if (ok && (args.Length() >= 2)) {
        password = getArg1String(args);
        ok &= (password != NULL);
    }

    if (ok) {
        obj->rsa = PEM_read_bio_RSAPrivateKey(bp, NULL, 0, password);
        if (obj->rsa == NULL) { scheduleSslException(); }
    }

    if (bp != NULL) { BIO_free(bp); }
    free(password);
    return Undefined();
}

/**
 * Sets the underlying RSA object to correspond to the given
 * public key (a Buffer of PEM format data). This throws an
 * exception if the underlying RSA had previously been set.
 */
Handle<Value> RsaWrap::SetPublicKeyPem(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectUnset(args);
    if (obj == NULL) { return Undefined(); }

    BIO *bp = getArg0Buffer(args);
    if (bp == NULL) { return Undefined(); }

    obj->rsa = PEM_read_bio_RSA_PUBKEY(bp, NULL, NULL, NULL);

    if (obj->rsa == NULL) { scheduleSslException(); }

    BIO_free(bp);
    return Undefined();
}
