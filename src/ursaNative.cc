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
 * Convert the given (BIGNUM *) to a Buffer of unsigned big-endian
 * contents. Returns a Buffer-containing handle on success. Schedules an
 * exception and returns Undefined() on failure.
 */
static Handle<Value> bignumToBuffer(BIGNUM *number) {
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

    // TODO: Is there a more idiomatic way of getting a handle from
    // a Buffer?
    return result->handle_;
}

/**
 * Convert the given memory-based (BIO *) to a Buffer of its contents.
 * Returns a Buffer-containing handle on success. Schedules an
 * exception and returns Undefined() on failure. In either case, the
 * BIO is freed by the time this function returns.
 *
 * As a special case to help with error handling, if given a NULL
 * argument, this simply returns Undefined().
 */
static Handle<Value> bioToBuffer(BIO *bio) {
    if (bio == NULL) {
        return Undefined();
    }

    char *data;
    long length = BIO_get_mem_data(bio, &data);
    node::Buffer *result = node::Buffer::New(length);

    if (result == NULL) {
        scheduleAllocException();
        BIO_vfree(bio);
        return Undefined();
    }

    memcpy(node::Buffer::Data(result), data, length);
    BIO_vfree(bio);

    // TODO: Is there a more idiomatic way of getting a handle from
    // a Buffer?
    return result->handle_;
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
 * Get a Buffer out of args[0], converted to a freshly-allocated
 * memory BIO. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns NULL.
 */
static BIO *getArg0Bio(const Arguments& args) {
    if (!isBuffer(args, 0)) { return NULL; }

    Local<Object> buf = args[0]->ToObject();
    char *data = node::Buffer::Data(buf);
    ssize_t length = node::Buffer::Length(buf);
    BIO *bio = BIO_new_mem_buf(data, length);

    if (bio == NULL) { scheduleSslException(); }

    return bio;
}

/**
 * Get a Buffer out of args[0], yielding a data pointer and length.
 * Returns a non-null pointer on success and sets the given length
 * pointer. On failure, schedules an exception and returns NULL.
 */
static void *getArg0DataAndLength(const Arguments& args, int *lengthPtr) {
    if (!isBuffer(args, 0)) { return NULL; }

    Local<Object> buf = args[0]->ToObject();

    *lengthPtr = node::Buffer::Length(buf);
    return node::Buffer::Data(buf);
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

    // The "d" field should always be set on a private key and never
    // set on a public key.
    if ((obj == NULL) || (obj->rsa->d != NULL)) {
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

    return bignumToBuffer(obj->rsa->e);
}

/**
 * Get the public modulus of the underlying RSA object. The return
 * value is a Buffer containing the unsigned number in big-endian
 * order.
 */
Handle<Value> RsaWrap::GetModulus(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    return bignumToBuffer(obj->rsa->n);
}

/**
 * Get the private key of the underlying RSA object as a file
 * in PEM format. The return value is a Buffer containing the
 * file contents (in ASCII / UTF8). Note: This does not do any
 * encryption of the results.
 */
Handle<Value> RsaWrap::GetPrivateKeyPem(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectPrivateKey(args);
    if (obj == NULL) { return Undefined(); }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        scheduleSslException();
        return Undefined();
    }

    if (!PEM_write_bio_RSAPrivateKey(bio, obj->rsa,
                                     NULL, NULL, 0, NULL, NULL)) {
        scheduleSslException();
        BIO_vfree(bio);
        return Undefined();
    }

    return bioToBuffer(bio);
}

/**
 * Get the public key of the underlying RSA object as a file
 * in PEM format. The return value is a Buffer containing the
 * file contents (in ASCII / UTF8).
 */
Handle<Value> RsaWrap::GetPublicKeyPem(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        scheduleSslException();
        return Undefined();
    }

    if (!PEM_write_bio_RSA_PUBKEY(bio, obj->rsa)) {
        scheduleSslException();
        BIO_vfree(bio);
        return Undefined();
    }

    return bioToBuffer(bio);
}

/**
 * Perform decryption on the given buffer using the RSA key, which
 * must be a private key. This always uses the padding mode
 * RSA_PKCS1_OAEP_PADDING.
 */
Handle<Value> RsaWrap::PrivateDecrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectPrivateKey(args);
    if (obj == NULL) { return Undefined(); }

    int length;
    void *data = getArg0DataAndLength(args, &length);
    if (data == NULL) { return Undefined(); }

    int rsaLength = RSA_size(obj->rsa);
    unsigned char buf[rsaLength];

    int bufLength = RSA_private_decrypt(length, (unsigned char *) data,
                                        buf, obj->rsa, RSA_PKCS1_OAEP_PADDING);

    if (bufLength < 0) {
        scheduleSslException();
        return Undefined();
    }

    node::Buffer *result = node::Buffer::New(bufLength);

    if (result == NULL) {
        scheduleAllocException();
        return Undefined();
    }

    memcpy(node::Buffer::Data(result), buf, bufLength);
    return result->handle_;
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::PrivateEncrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectPrivateKey(args);
    if (obj == NULL) { return Undefined(); }

    int length;
    void *data = getArg0DataAndLength(args, &length);
    if (data == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

// FIXME: Need documentation.
Handle<Value> RsaWrap::PublicDecrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    int length;
    void *data = getArg0DataAndLength(args, &length);
    if (data == NULL) { return Undefined(); }

    // FIXME: Need real implementation.
    return scope.Close(String::New("world"));
}

/**
 * Perform encryption on the given buffer using the public (aspect of the)
 * RSA key. This always uses the padding mode RSA_PKCS1_OAEP_PADDING.
 */
Handle<Value> RsaWrap::PublicEncrypt(const Arguments& args) {
    HandleScope scope;

    RsaWrap *obj = unwrapExpectSet(args);
    if (obj == NULL) { return Undefined(); }

    int length;
    void *data = getArg0DataAndLength(args, &length);
    if (data == NULL) { return Undefined(); }

    int rsaLength = RSA_size(obj->rsa);
    node::Buffer *result = node::Buffer::New(rsaLength);

    if (result == NULL) {
        scheduleAllocException();
        return Undefined();
    }

    int ret = RSA_public_encrypt(length, (unsigned char *) data, 
                                 (unsigned char *) node::Buffer::Data(result),
                                 obj->rsa, RSA_PKCS1_OAEP_PADDING);

    if (ret < 0) {
        scheduleSslException();
        return Undefined();
    }

    return result->handle_;
}

/**
 * Sets the underlying RSA object to correspond to the given
 * private key (a Buffer of PEM format data). This throws an
 * exception if the underlying RSA had previously been set.
 */
Handle<Value> RsaWrap::SetPrivateKeyPem(const Arguments& args) {
    HandleScope scope;
    bool ok = true;

    RsaWrap *obj = unwrapExpectUnset(args);
    ok &= (obj != NULL);

    BIO *bio = NULL;
    if (ok) {
        bio = getArg0Bio(args);
        ok &= (bio != NULL);
    }

    char *password = NULL;
    if (ok && (args.Length() >= 2)) {
        password = getArg1String(args);
        ok &= (password != NULL);
    }

    if (ok) {
        obj->rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, 0, password);
        if (obj->rsa == NULL) { scheduleSslException(); }
    }

    if (bio != NULL) { BIO_vfree(bio); }
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

    BIO *bio = getArg0Bio(args);
    if (bio == NULL) { return Undefined(); }

    obj->rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if (obj->rsa == NULL) { scheduleSslException(); }

    BIO_vfree(bio);
    return Undefined();
}
