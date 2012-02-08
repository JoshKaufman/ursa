// Copyright 2012 The Obvious Corporation.

#ifndef RSAB_NATIVE_H
#define RSAB_NATIVE_H

#define BUILDING_NODE_EXTENSION
#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>

#include <openssl/rsa.h>

class RsaWrap : node::ObjectWrap {
  public:
    static void InitClass(v8::Handle<v8::Object> target);

  protected:
    RsaWrap();
    ~RsaWrap();

    static v8::Handle<v8::Value> New(const v8::Arguments& args);
    static v8::Handle<v8::Value> Hello(const v8::Arguments& args);

  private:
    RSA *rsa;
};

#endif // def RSAB_NATIV_H
