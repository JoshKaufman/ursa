// Copyright 2012 The Obvious Corporation.

#include "rsabNative.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

using namespace v8;


/**
 * Top-level initialization function.
 */
void init(Handle<Object> target) {
    RsaWrap::InitClass(target);
}

NODE_MODULE(rsabNative, init)

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
    proto->Set(String::NewSymbol("hello"),
	       FunctionTemplate::New(Hello)->GetFunction());

    // Store the constructor in the target bindings.
    target->Set(className, Persistent<Function>::New(tpl->GetFunction()));
}

RsaWrap::RsaWrap() {
    rsa = NULL;
}

RsaWrap::~RsaWrap() {
    if (rsa != NULL) {
	RSA_free(rsa);
    }
    printf("~~~ DESTRUCTOR CALLED\n");
}

Handle<Value> RsaWrap::New(const Arguments& args) {
    HandleScope scope;

    printf("~~~ ALLOC\n");

    RsaWrap *obj = new RsaWrap();
    obj->Wrap(args.This());

    return args.This();
}

// FIXME: Temporary!
Handle<Value> RsaWrap::Hello(const Arguments& args) {
    HandleScope scope;
    return scope.Close(String::New("world"));
}
