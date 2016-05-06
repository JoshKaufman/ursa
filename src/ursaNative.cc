// Copyright 2012 The Obvious Corporation.

#include "ursaNative.h"
#include <node_buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

using namespace v8;

#ifdef _WIN32
#  include <malloc.h>
#  define VAR_ARRAY(type, name, size)  type* name = (type*)_alloca(size)
#else
#  define VAR_ARRAY(type, name, size)  type name[size]
#endif

Nan::Persistent<Function> constructor;



/*
 * Initialization and binding
 */
#define NanThrowError(err) Nan::ThrowError(err);
#define NanNewBufferHandle(length) Nan::NewBuffer(length).ToLocalChecked()
#define args info
#define NanScope() Nan::HandleScope scope
#define NanReturnUndefined() { info.GetReturnValue().Set(Nan::Undefined()); return; }
#define NanNew Nan::New
#define NanReturnValue(value) { info.GetReturnValue().Set(value); return; }
#define NanFalse() Nan::False()
#define NanTrue() Nan::True()

#define RSA_PKCS1_SALT_LEN_HLEN    -1
#define RSA_PKCS1_SALT_LEN_MAX     -2
#define RSA_PKCS1_SALT_LEN_RECOVER -2

/**
 * Top-level initialization function.
 */
void init(Local<Object> target) {
    NODE_DEFINE_CONSTANT(target, RSA_NO_PADDING);
    NODE_DEFINE_CONSTANT(target, RSA_PKCS1_PADDING);
    NODE_DEFINE_CONSTANT(target, RSA_PKCS1_OAEP_PADDING);
    NODE_DEFINE_CONSTANT(target, RSA_PKCS1_SALT_LEN_HLEN);
    NODE_DEFINE_CONSTANT(target, RSA_PKCS1_SALT_LEN_MAX);
    NODE_DEFINE_CONSTANT(target, RSA_PKCS1_SALT_LEN_RECOVER);

    RsaWrap::InitClass(target);

#ifdef _WIN32
    // On Windows, we can't use Node's OpenSSL, so we link
    // to a standalone OpenSSL library. Therefore, we need
    // to initialize OpenSSL separately.

    //TODO: Do I need to free these?
    //I'm not sure where to call ERR_free_strings() and EVP_cleanup()
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();
#endif
}

NODE_MODULE(ursaNative, init)


/*
 * Helper functions
 */

/**
 * Schedule the current SSL error as a higher-level exception.
 */
static void scheduleSslException() {
    char *err = ERR_error_string(ERR_get_error(), NULL);
    ERR_clear_error();
    NanThrowError(err);
}

/**
 * Schedule an "allocation failed" exception. This (tries) to allocate
 * as well, which very well could (probably will) fail too, but it's the
 * best we can do in a bad situation.
 */
static void scheduleAllocException() {
    NanThrowError("Allocation failed.");
}

/**
 * Convert the given (BIGNUM *) to a Buffer of unsigned big-endian
 * contents. Returns a Buffer-containing handle on success. Schedules an
 * exception and returns Undefined() on failure.
 */
static Nan::NAN_METHOD_RETURN_TYPE bignumToBuffer(Nan::NAN_METHOD_ARGS_TYPE args,
                                                  BIGNUM *number) {
    int length = BN_num_bytes(number);
    Local<Object> result = NanNewBufferHandle(length);

    if (BN_bn2bin(number, (unsigned char *) node::Buffer::Data(result)) < 0) {
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(result);
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
static Nan::NAN_METHOD_RETURN_TYPE bioToBuffer(Nan::NAN_METHOD_ARGS_TYPE args,
                                               BIO *bio) {
    if (bio == NULL) {
        NanReturnUndefined();
    }

    char *data;
    long length = BIO_get_mem_data(bio, &data);
    Local<Object> result = NanNewBufferHandle(length);

    if (result.IsEmpty()) {
        scheduleAllocException();
        BIO_vfree(bio);
        NanReturnUndefined();
    }

    memcpy(node::Buffer::Data(result), data, length);
    BIO_vfree(bio);

    NanReturnValue(result);
}

/**
 * Get a Buffer out of args[0], converted to a freshly-allocated
 * memory BIO. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns NULL.
 */
static BIO *getArg0Bio(const Local<Object> buf) {
    if (!node::Buffer::HasInstance(buf)) {
        NanThrowError("Expected a Buffer in args[0].");
        return NULL;
    }

    char *data = node::Buffer::Data(buf);
    ssize_t length = node::Buffer::Length(buf);
    BIO *bio = BIO_new_mem_buf(data, length);

    if (bio == NULL) { scheduleSslException(); }

    return bio;
}

static BIGNUM *getArgXBigNum(const Local<Object> buf) {
    if (!node::Buffer::HasInstance(buf)) {
        NanThrowError("Expected a Buffer.");
        return NULL;
    }
    char *data = node::Buffer::Data(buf);
    ssize_t length = node::Buffer::Length(buf);

    return BN_bin2bn(reinterpret_cast<unsigned char*>(data),length,NULL);
}


/**
 * Get a Buffer out of args[1], converted to a freshly-allocated (char
 * *). Returns a non-null pointer on success. On failure, schedules an
 * exception and returns NULL.
 */
static char *copyBufferToCharStar(const Local<Object> buf) {

    if (!node::Buffer::HasInstance(buf)) {
        return NULL;
    }

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

/**
 * Get a string out of args[] at the given index, converted to a
 * freshly-allocated (char *). Returns a non-null pointer on
 * success. On failure, schedules an exception and returns NULL.
 */
static char *copyBufferToUtf8String(const Local<String> str) {
// static char *getArgString(const Arguments& args, int index) {
    int length = str->Utf8Length();
    char *result = (char *) malloc(length + 1);

    if (result == NULL) {
        scheduleAllocException();
        return NULL;
    }

    result[length] = 'x'; // Set up a small sanity check (see below).
    str->WriteUtf8(result, length + 1);

    if (result[length] != '\0') {
        const char *message = "String conversion failed.";
        NanThrowError(message);
        free(result);
        return NULL;
    }

    return result;
}

/**
 * Generate a key, using one of the two possibly-available functions.
 * This prefers the newer function, if available.
 */
static RSA *generateKey(int num, unsigned long e) {
#if OPENSSL_VERSION_NUMBER < 0x009080001
    return RSA_generate_key(num, e, NULL, NULL);
#else
    BIGNUM *eBig = BN_new();

    if (eBig == NULL) {
        return NULL;
    }

    if (!BN_set_word(eBig, e)) {
        BN_free(eBig);
        return NULL;
    }

    RSA *result = RSA_new();

    if (result == NULL) {
        BN_free(eBig);
        return NULL;
    }

    if (RSA_generate_key_ex(result, num, eBig, NULL) < 0) {
        RSA_free(result);
        result = NULL;
    }

    BN_free(eBig);
    return result;
#endif
}


/*
 * Utility function implementation
 */

/**
 * Call the OpenSSL function OBJ_txt2nid() on the given string.
 * This returns a number representing the text that, as far as I
 * (danfuzz) know, is not necessarily stable across versions of
 * OpenSSL, so it's only safe to use transiently.
 */
NAN_METHOD(TextToNid) {
    NanScope();

    if (args.Length() < 1) {
        NanThrowError("Missing args[0].");
        NanReturnUndefined();
    }

    if (!args[0]->IsString()) {
        NanThrowError("Expected a string in args[0].");
        NanReturnUndefined();
    }

    Local<String> str = args[0].As<String>();
    char *name = copyBufferToUtf8String(str);
    if (name == NULL) { NanReturnUndefined(); }

    int nid = OBJ_txt2nid(name);
    free(name);

    if (nid == NID_undef) {
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(NanNew<Number>(nid));
}


/*
 * RsaWrap implementation
 */

/**
 * Initialize the bindings for this class.
 */
void RsaWrap::InitClass(Local<Object> target) {
    Local<String> className = NanNew("RsaWrap").ToLocalChecked();

    // Basic instance setup
    Local<FunctionTemplate> tpl = NanNew<FunctionTemplate>(New);

    tpl->SetClassName(className);
    tpl->InstanceTemplate()->SetInternalFieldCount(1); // req'd by ObjectWrap

    Nan::SetPrototypeMethod(tpl, "generatePrivateKey", GeneratePrivateKey);
    Nan::SetPrototypeMethod(tpl, "getExponent",        GetExponent);
    Nan::SetPrototypeMethod(tpl, "getPrivateExponent", GetPrivateExponent);
    Nan::SetPrototypeMethod(tpl, "getModulus",         GetModulus);
    Nan::SetPrototypeMethod(tpl, "getPrivateKeyPem",   GetPrivateKeyPem);
    Nan::SetPrototypeMethod(tpl, "getPublicKeyPem",    GetPublicKeyPem);
    Nan::SetPrototypeMethod(tpl, "privateDecrypt",     PrivateDecrypt);
    Nan::SetPrototypeMethod(tpl, "privateEncrypt",     PrivateEncrypt);
    Nan::SetPrototypeMethod(tpl, "publicDecrypt",      PublicDecrypt);
    Nan::SetPrototypeMethod(tpl, "publicEncrypt",      PublicEncrypt);
    Nan::SetPrototypeMethod(tpl, "setPrivateKeyPem",   SetPrivateKeyPem);
    Nan::SetPrototypeMethod(tpl, "setPublicKeyPem",    SetPublicKeyPem);
    Nan::SetPrototypeMethod(tpl, "sign",               Sign);
    Nan::SetPrototypeMethod(tpl, "verify",             Verify);
    Nan::SetPrototypeMethod(tpl, "createPrivateKeyFromComponents", CreatePrivateKeyFromComponents);
    Nan::SetPrototypeMethod(tpl, "createPublicKeyFromComponents",  CreatePublicKeyFromComponents);
    Nan::SetPrototypeMethod(tpl, "openPublicSshKey",   OpenPublicSshKey);
    Nan::SetPrototypeMethod(tpl, "addPSSPadding",      AddPSSPadding);
    Nan::SetPrototypeMethod(tpl, "verifyPSSPadding",   VerifyPSSPadding);

    // Store the constructor in the target bindings.
    target->Set(NanNew("RsaWrap").ToLocalChecked(), tpl->GetFunction());
    constructor.Reset(tpl->GetFunction());

    target->Set(NanNew("textToNid").ToLocalChecked(), Nan::New<FunctionTemplate>(TextToNid)->GetFunction());
}

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

NAN_METHOD(RsaWrap::OpenPublicSshKey) {
    NanScope();
    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectUnset(obj);

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    Local<Object> obj_n = args[0].As<Object>();
    Local<Object> obj_e = args[1].As<Object>();
    int n_length = node::Buffer::Length(obj_n);
    int e_length = node::Buffer::Length(obj_e);
    unsigned char *data_n = (unsigned char *)malloc(n_length);
    unsigned char *data_e = (unsigned char *)malloc(e_length);
    memcpy(data_n, node::Buffer::Data(obj_n), n_length);
    memcpy(data_e, node::Buffer::Data(obj_e), e_length);

    if (obj->rsa == NULL) {
        obj->rsa = RSA_new();
    }

    obj->rsa->n = BN_bin2bn(data_n, n_length, NULL);
    obj->rsa->e = BN_bin2bn(data_e, e_length, NULL);
    free(data_n);
    free(data_e);
    NanReturnUndefined();
}

/**
 * Get an (RsaWrap *) out of the given arguments, expecting the
 * underlying (RSA *) to be non-null and more specifically a private
 * key. Returns a non-null pointer on success. On failure, schedules
 * an exception and returns null.
 */
RsaWrap* RsaWrap::expectPrivateKey(RsaWrap* obj) {
    obj = expectSet(obj);

    // The "d" field should always be set on a private key and never
    // set on a public key.
    if ((obj == NULL) || (obj->rsa->d != NULL)) {
        return obj;
    }

    NanThrowError("Expected a private key.");
    return NULL;
}

/**
 * Get an (RsaWrap *) out of the given arguments, expecting the underlying
 * (RSA *) to be non-null. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns null.
 */
RsaWrap *RsaWrap::expectSet(RsaWrap* obj) {

    if (obj->rsa != NULL) {
        return obj;
    }

    NanThrowError("Key not yet set.");
    return NULL;
}

/**
 * Get an (RsaWrap *) out of the given arguments, expecting the underlying
 * (RSA *) to be null. Returns a non-null pointer on success. On failure,
 * schedules an exception and returns null.
 */
RsaWrap *RsaWrap::expectUnset(RsaWrap* obj) {

    if (obj->rsa == NULL) {
        return obj;
    }

    NanThrowError("Key already set.");
    return NULL;
}

/**
 * Construct an empty instance.
 */
NAN_METHOD(RsaWrap::New) {
    NanScope();

    RsaWrap *obj = new RsaWrap();
    obj->Wrap(args.This());

    NanReturnValue(args.This());
}

/**
 * Set the underlying RSA struct to a newly-generated key pair.
 */
NAN_METHOD(RsaWrap::GeneratePrivateKey) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectUnset(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    // Sadly the change in V8 args type signature makes this messier now.
    if (args.Length() < 1) {
        NanThrowError("Missing args[0].");
        NanReturnUndefined();
    }

    if (!args[0]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[0].");
        NanReturnUndefined();
    }

    if (args.Length() < 2) {
        NanThrowError("Missing args[1].");
        NanReturnUndefined();
    }

    if (!args[1]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[1].");
        NanReturnUndefined();
    }

    int modulusBits = args[0]->Uint32Value();
    int exponent = args[1]->Uint32Value();

    // Sanity-check the arguments, since (as of this writing) OpenSSL
    // either doesn't check, or at least doesn't consistently check:
    //
    // * The modulus bit count must be >= 512. Really, it just has to
    //   be a positive integer, but anything less than 512 is a
    //   horrendously bad idea.
    //
    // * The exponend must be positive and odd.

    if (modulusBits < 512) {
        NanThrowError("Expected modulus bit count >= 512.");
        NanReturnUndefined();
    }

    if (exponent <= 0) {
        NanThrowError("Expected positive exponent.");
        NanReturnUndefined();
    }

    if ((exponent & 1) == 0) {
        NanThrowError("Expected odd exponent.");
        NanReturnUndefined();
    }

    obj->rsa = generateKey(modulusBits, (unsigned long) exponent);

    if (obj->rsa == NULL) {
        scheduleSslException();
    }

    NanReturnUndefined();
}

/**
 * Get the public exponent of the underlying RSA object. The return
 * value is a Buffer containing the unsigned number in big-endian
 * order.
 */
NAN_METHOD(RsaWrap::GetExponent) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    bignumToBuffer(args, obj->rsa->e);
}

/**
 * Get the private exponent of the underlying RSA object. The return
 * value is a Buffer containing the unsigned number in big-endian
 * order. The returned exponent is not encrypted in any way,
 * so this should be used with caution.
 */
NAN_METHOD(RsaWrap::GetPrivateExponent) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectPrivateKey(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    bignumToBuffer(args, obj->rsa->d);
}

/**
 * Get the public modulus of the underlying RSA object. The return
 * value is a Buffer containing the unsigned number in big-endian
 * order.
 */
NAN_METHOD(RsaWrap::GetModulus) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    bignumToBuffer(args, obj->rsa->n);
}

/**
 * Get the private key of the underlying RSA object as a file
 * in PEM format. The return value is a Buffer containing the
 * file contents (in ASCII / UTF8). Note: This does not do any
 * encryption of the results.
 */
NAN_METHOD(RsaWrap::GetPrivateKeyPem) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectPrivateKey(obj);

    if (obj == NULL) { NanReturnUndefined(); }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        scheduleSslException();
        NanReturnUndefined();
    }

    char *password = NULL;
    int passwordLen = 0;
    const EVP_CIPHER *cipher = NULL;

    if (args.Length() > 0) {
      Local<String> pstr = args[0].As<String>();
      password = copyBufferToUtf8String(pstr);

      Local<String> cstr = args[1].As<String>();
      char *cipherName = copyBufferToUtf8String(cstr);
      cipher = EVP_get_cipherbyname(cipherName);
      free(cipherName);
    }

    if (password != NULL) {
      passwordLen = (int)strlen(password);
    }


    if (!PEM_write_bio_RSAPrivateKey(bio, obj->rsa,
                                     cipher, (unsigned char *)password,
                                     passwordLen, NULL, NULL)) {
        scheduleSslException();
        BIO_vfree(bio);
        free(password);
        NanReturnUndefined();
    }

    free(password);
    bioToBuffer(args, bio);
}

/**
 * Get the public key of the underlying RSA object as a file
 * in PEM format. The return value is a Buffer containing the
 * file contents (in ASCII / UTF8).
 */
NAN_METHOD(RsaWrap::GetPublicKeyPem) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        scheduleSslException();
        NanReturnUndefined();
    }

    if (!PEM_write_bio_RSA_PUBKEY(bio, obj->rsa)) {
        scheduleSslException();
        BIO_vfree(bio);
        NanReturnUndefined();
    }

    bioToBuffer(args, bio);
}

/**
 * Perform decryption on the given buffer using the RSA key, which
 * must be a private key, and padding mode.
 */
NAN_METHOD(RsaWrap::PrivateDecrypt) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectPrivateKey(obj);

    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    Local<Object> buffer = args[0].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[0].");
        NanReturnUndefined();
    }

    size_t length = node::Buffer::Length(buffer);
    char* data = node::Buffer::Data(buffer);
    if (data == NULL) { NanReturnUndefined(); }

    int rsaLength = RSA_size(obj->rsa);
    VAR_ARRAY(unsigned char, buf, rsaLength);

    if (!args[1]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[1].");
        NanReturnUndefined();
    }
    int padding = args[1]->Uint32Value();

    int bufLength = RSA_private_decrypt(length, (unsigned char *) data,
                                        buf, obj->rsa, padding);

    if (bufLength < 0) {
        scheduleSslException();
        NanReturnUndefined();
    }

    Local<Object> result = NanNewBufferHandle(bufLength);
    memcpy(node::Buffer::Data(result), buf, bufLength);
    NanReturnValue(result);
}

/**
 * Perform encryption on the given buffer using the RSA key, which
 * must be private, and padding mode.
 */
NAN_METHOD(RsaWrap::PrivateEncrypt) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectPrivateKey(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    Local<Object> buffer = args[0].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[0].");
        NanReturnUndefined();
    }
    size_t length = node::Buffer::Length(buffer);
    char* data = node::Buffer::Data(buffer);
    if (data == NULL) { NanReturnUndefined(); }

    int rsaLength = RSA_size(obj->rsa);
    Local<Object> result = NanNewBufferHandle(rsaLength);

    if (!args[1]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[1].");
        NanReturnUndefined();
    }
    int padding = args[1]->Uint32Value();

    int ret = RSA_private_encrypt(length, (unsigned char *) data,
                                  (unsigned char *) node::Buffer::Data(result),
                                  obj->rsa, padding);

    if (ret < 0) {
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(result);
}

/**
 * Perform decryption on the given buffer using the (public aspect of
 * the) RSA key, and padding mode.
 */
NAN_METHOD(RsaWrap::PublicDecrypt) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    Local<Object> buffer = args[0].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[0].");
        NanReturnUndefined();
    }
    size_t length = node::Buffer::Length(buffer);
    char* data = node::Buffer::Data(buffer);
    if (data == NULL) { NanReturnUndefined(); }

    int rsaLength = RSA_size(obj->rsa);
    VAR_ARRAY(unsigned char, buf, rsaLength);

    if (!args[1]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[1].");
        NanReturnUndefined();
    }
    int padding = args[1]->Uint32Value();

    int bufLength = RSA_public_decrypt(length, (unsigned char *) data,
                                       buf, obj->rsa, padding);

    if (bufLength < 0) {
        scheduleSslException();
        NanReturnUndefined();
    }

    Local<Object> result = NanNewBufferHandle(bufLength);
    memcpy(node::Buffer::Data(result), buf, bufLength);
    NanReturnValue(result);
}

/**
 * Perform encryption on the given buffer using the public (aspect of the)
 * RSA key, and padding mode.
 */
NAN_METHOD(RsaWrap::PublicEncrypt) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    Local<Object> buffer = args[0].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[0].");
        NanReturnUndefined();
    }
    size_t length = node::Buffer::Length(buffer);
    char* data = node::Buffer::Data(buffer);

    int rsaLength = RSA_size(obj->rsa);
    Local<Object> result = NanNewBufferHandle(rsaLength);

    if (!args[1]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[1].");
        NanReturnUndefined();
    }
    int padding = args[1]->Uint32Value();

    int ret = RSA_public_encrypt(length, (unsigned char *) data,
                                 (unsigned char *) node::Buffer::Data(result),
                                 obj->rsa, padding);

    if (ret < 0) {
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(result);
}

/**
 * Sets the underlying RSA object to correspond to the given
 * private key (a Buffer of PEM format data). This throws an
 * exception if the underlying RSA had previously been set.
 */
NAN_METHOD(RsaWrap::SetPrivateKeyPem) {
    NanScope();
    bool ok = true;

    if (args.Length() < 1) {
        NanThrowError("Missing args[0].");
        NanReturnUndefined();
    }

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectUnset(obj);
    ok &= (obj != NULL);

    BIO *bio = NULL;
    if (ok) {
        bio = getArg0Bio(args[0].As<Object>());
        ok &= (bio != NULL);
    }

    Local<Object> buf = args[1].As<Object>();
    char *password = NULL;
    if (ok && (args.Length() >= 2)) {
        password = copyBufferToCharStar(buf);
        if (password == NULL) {
            NanThrowError("Expected a Buffer in args[1].");
        }
        ok &= (password != NULL);
    }

    if (ok) {
        obj->rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, 0, password);
        if (obj->rsa == NULL) { scheduleSslException(); }
    }

    if (bio != NULL) { BIO_vfree(bio); }
    if (password != NULL) { free(password); };
    NanReturnUndefined();
}

/**
 * Sets the underlying RSA object to correspond to the given
 * public key (a Buffer of PEM format data). This throws an
 * exception if the underlying RSA had previously been set.
 */
NAN_METHOD(RsaWrap::SetPublicKeyPem) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectUnset(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 1) {
        NanThrowError("Missing args[0].");
        NanReturnUndefined();
    }

    BIO *bio = getArg0Bio(args[0].As<Object>());
    if (bio == NULL) { NanReturnUndefined(); }

    obj->rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if (obj->rsa == NULL) { scheduleSslException(); }

    BIO_vfree(bio);
    NanReturnUndefined();
}

/**
 * Sign the given hash data. First argument indicates what kind of hash
 * was performed. Returns a Buffer object.
 */
NAN_METHOD(RsaWrap::Sign) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectPrivateKey(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    if (!args[0]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[0].");
        NanReturnUndefined();
    }
    int nid = args[0]->Uint32Value();

    Local<Object> buffer = args[1].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[1].");
        NanReturnUndefined();
    }
    size_t dataLength = node::Buffer::Length(buffer);
    char* data = node::Buffer::Data(buffer);
    if (data == NULL) { NanReturnUndefined(); }

    unsigned int rsaSize = (unsigned int) RSA_size(obj->rsa);
    unsigned int sigLength = rsaSize;
    Local<Object> result = NanNewBufferHandle(sigLength);

    int ret = RSA_sign(nid, (unsigned char*) data, dataLength,
                       (unsigned char *) node::Buffer::Data(result),
                       &sigLength, obj->rsa);

    if (ret == 0) {
        // TODO: Will this leak the result buffer? Is it going to be gc'ed?
        scheduleSslException();
        NanReturnUndefined();
    }

    if (rsaSize != sigLength) {
        // Sanity check. Shouldn't ever happen in practice.
        NanThrowError("Shouldn't happen.");
    }

    NanReturnValue(result);
}

/**
 * Verify the signature on the given hash data. First argument indicates
 * what kind of hash was performed. Throws an exception if the signature
 * did not verify.
 */
NAN_METHOD(RsaWrap::Verify) {
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 3) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    if (!args[0]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[0].");
        NanReturnUndefined();
    }
    int nid = args[0]->Uint32Value();

    Local<Object> buffer = args[1].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[1].");
        NanReturnUndefined();
    }
    size_t dataLength = node::Buffer::Length(buffer);
    char* data = node::Buffer::Data(buffer);
    if (data == NULL) { NanReturnUndefined(); }

    Local<Object> sigBuffer = args[2].As<Object>();
    if (!node::Buffer::HasInstance(sigBuffer)) {
        NanThrowError("Expected a Buffer in args[2].");
        NanReturnUndefined();
    }
    size_t sigLength = node::Buffer::Length(sigBuffer);
    char* sig = node::Buffer::Data(sigBuffer);
    if (sig == NULL) { NanReturnUndefined(); }

    int ret = RSA_verify(nid, (unsigned char *) data, dataLength,
                         (unsigned char *) sig, sigLength, obj->rsa);
    if (ret == 0) {
        // Something went wrong; investigate!
        unsigned long err = ERR_peek_error();
        int lib = ERR_GET_LIB(err);
        int reason = ERR_GET_REASON(err);
        if ((lib == ERR_LIB_RSA) && (reason == RSA_R_BAD_SIGNATURE)) {
            // This just means that the signature didn't match
            // (as opposed to, say, a more dire failure in the library
            // warranting an exception throw).
            ERR_get_error(); // Consume the error (get it off the err stack).
            NanReturnValue(NanFalse());
        }
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(NanTrue());
}

/**
  * Add PSS padding to a digest. First argument is digest algorithm ID,
  * second is the digest, third is the salt length.
  */
NAN_METHOD(RsaWrap::AddPSSPadding)
{
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 3) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    if (!args[0]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[0].");
        NanReturnUndefined();
    }
    int nid = args[0]->Uint32Value();
    const EVP_MD *Hash = EVP_get_digestbynid(nid);
    if (Hash == NULL) { NanReturnUndefined(); }

    Local<Object> buffer = args[1].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[1].");
        NanReturnUndefined();
    }
    size_t mHashLength = node::Buffer::Length(buffer);
    char *mHash = node::Buffer::Data(buffer);
    if (mHash == NULL) { NanReturnUndefined(); }
    if (mHashLength != (size_t) EVP_MD_size(Hash)) {
        NanThrowError("Incorrect hash size.");
        NanReturnUndefined();
    }

    if (!args[2]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[2].");
        NanReturnUndefined();
    }
    int sLen = args[2]->Uint32Value();

    unsigned int emLength = (unsigned int) RSA_size(obj->rsa);
    Local<Object> EM = NanNewBufferHandle(emLength);

    int ret = RSA_padding_add_PKCS1_PSS(obj->rsa,
                    (unsigned char*) node::Buffer::Data(EM),
                    (unsigned char*) mHash, Hash, sLen);
    if (ret == 0) { 
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(EM);
}

/**
  * Verify a signature with PSS padding. First argument is digest algorithm ID,
  * second is the digest, third is the padded digest, fourth is the salt length.
  */
NAN_METHOD(RsaWrap::VerifyPSSPadding)
{
    NanScope();

    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectSet(obj);
    if (obj == NULL) { NanReturnUndefined(); }

    if (args.Length() < 4) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    if (!args[0]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[0].");
        NanReturnUndefined();
    }
    int nid = args[0]->Uint32Value();
    const EVP_MD *Hash = EVP_get_digestbynid(nid);
    if (Hash == NULL) { NanReturnUndefined(); }

    Local<Object> buffer = args[1].As<Object>();
    if (!node::Buffer::HasInstance(buffer)) {
        NanThrowError("Expected a Buffer in args[1].");
        NanReturnUndefined();
    }
    size_t mHashLength = node::Buffer::Length(buffer);
    char *mHash = node::Buffer::Data(buffer);
    if (mHash == NULL) { NanReturnUndefined(); }
    if (mHashLength != (size_t) EVP_MD_size(Hash)) {
        NanThrowError("Incorrect hash size.");
        NanReturnUndefined();
    }

    Local<Object> emBuffer = args[2].As<Object>();
    if (!node::Buffer::HasInstance(emBuffer)) {
        NanThrowError("Expected a Buffer in args[2].");
        NanReturnUndefined();
    }
    if (node::Buffer::Length(emBuffer) != (size_t) RSA_size(obj->rsa)) {
        NanThrowError("Incorrect encoded message size.");
        NanReturnUndefined();
    }
    char *EM = node::Buffer::Data(emBuffer);
    if (EM == NULL) { NanReturnUndefined(); }

    if (!args[3]->IsInt32()) {
        NanThrowError("Expected a 32-bit integer in args[3].");
        NanReturnUndefined();
    }
    int sLen = args[3]->Uint32Value();

    int ret = RSA_verify_PKCS1_PSS(obj->rsa, 
                    (unsigned char*) mHash, Hash, (unsigned char*) EM, sLen);
    if (ret == 0) {
        // Something went wrong; investigate!
        unsigned long err = ERR_peek_error();
        int lib = ERR_GET_LIB(err);
        int reason = ERR_GET_REASON(err);
        if ((lib == ERR_LIB_RSA) && (reason == RSA_R_BAD_SIGNATURE)) {
            // This just means that the signature didn't match
            // (as opposed to, say, a more dire failure in the library
            // warranting an exception throw).
            ERR_get_error(); // Consume the error (get it off the err stack).
            NanReturnValue(NanFalse());
        }
        scheduleSslException();
        NanReturnUndefined();
    }

    NanReturnValue(NanTrue());
}

NAN_METHOD(RsaWrap::CreatePrivateKeyFromComponents) {
    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectUnset(obj);
    if (obj == NULL) {
        NanReturnUndefined();
    }

    if (args.Length() < 8) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    obj->rsa = RSA_new();
    if (obj->rsa == NULL) {
        NanReturnUndefined();
    }

    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    BIGNUM *dp = NULL;
    BIGNUM *dq = NULL;
    BIGNUM *inverseQ = NULL;
    BIGNUM *d = NULL;

    bool ok = true;

    modulus = getArgXBigNum(args[0].As<Object>());
    ok &= (modulus != NULL);
    if (ok) {
        exponent = getArgXBigNum(args[1].As<Object>());
        ok &= (exponent != NULL);
    }
    if (ok) {
        p = getArgXBigNum(args[2].As<Object>());
        ok &= (p != NULL);
    }
    if (ok) {
        q = getArgXBigNum(args[3].As<Object>());
        ok &= (q != NULL);
    }
    if (ok) {
        dp = getArgXBigNum(args[4].As<Object>());
        ok &= (dp != NULL);
    }
    if (ok) {
        dq = getArgXBigNum(args[5].As<Object>());
        ok &= (dq != NULL);
    }
    if (ok) {
        inverseQ = getArgXBigNum(args[6].As<Object>());
        ok &= (inverseQ != NULL);
    }
    if (ok) {
        d = getArgXBigNum(args[7].As<Object>());
        ok &= (d != NULL);
    }

    if (ok) {
        obj->rsa->n = modulus;
        obj->rsa->e = exponent;
        obj->rsa->p = p;
        obj->rsa->q = q;
        obj->rsa->dmp1 = dp;
        obj->rsa->dmq1 = dq;
        obj->rsa->iqmp = inverseQ;
        obj->rsa->d = d;
    } else {
        if (modulus) { BN_free(modulus); }
        if (exponent) { BN_free(exponent); }
        if (p) { BN_free(p); }
        if (q) { BN_free(q); }
        if (dp) { BN_free(dp); }
        if (dq) { BN_free(dq); }
        if (inverseQ) { BN_free(inverseQ); }
        if (d) { BN_free(d); }
    }

    NanReturnUndefined();
}

NAN_METHOD(RsaWrap::CreatePublicKeyFromComponents) {
    RsaWrap *obj = ObjectWrap::Unwrap<RsaWrap>(args.Holder());
    obj = expectUnset(obj);
    if (obj == NULL) {
        NanReturnUndefined();
    }

    if (args.Length() < 2) {
        NanThrowError("Not enough args.");
        NanReturnUndefined();
    }

    obj->rsa = RSA_new();
    if (obj->rsa == NULL) {
        NanReturnUndefined();
    }

    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;

    bool ok = true;

    modulus = getArgXBigNum(args[0].As<Object>());
    ok &= (modulus != NULL);
    if (ok) {
        exponent = getArgXBigNum(args[1].As<Object>());
        ok &= (exponent != NULL);
    }

    if (ok) {
        obj->rsa->n = modulus;
        obj->rsa->e = exponent;
    } else {
        if (modulus) { BN_free(modulus); }
        if (exponent) { BN_free(exponent); }
    }

    NanReturnUndefined();
}

