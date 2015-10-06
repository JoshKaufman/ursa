// Copyright 2012 The Obvious Corporation.

#ifndef URSA_NATIVE_H
#define URSA_NATIVE_H

#ifndef BUILDING_NODE_EXTENSION
#define BUILDING_NODE_EXTENSION
#endif
#include <node.h>
#include <nan.h>
#include <v8.h>

#include <openssl/rsa.h>

class RsaWrap : public node::ObjectWrap {
  public:
    static void InitClass(v8::Local<v8::Object> target);

  protected:
    RsaWrap();
    ~RsaWrap();

    static NAN_METHOD(New);
    static NAN_METHOD(GeneratePrivateKey);
    static NAN_METHOD(GetExponent);
    static NAN_METHOD(GetPrivateExponent);
    static NAN_METHOD(GetModulus);
    static NAN_METHOD(GetPrivateKeyPem);
    static NAN_METHOD(GetPublicKeyPem);
    static NAN_METHOD(PrivateDecrypt);
    static NAN_METHOD(PrivateEncrypt);
    static NAN_METHOD(PublicDecrypt);
    static NAN_METHOD(PublicEncrypt);
    static NAN_METHOD(SetPrivateKeyPem);
    static NAN_METHOD(SetPublicKeyPem);
    static NAN_METHOD(Sign);
    static NAN_METHOD(Verify);
    static NAN_METHOD(CreatePrivateKeyFromComponents);
    static NAN_METHOD(CreatePublicKeyFromComponents);
    static NAN_METHOD(OpenPublicSshKey);
    static NAN_METHOD(AddPSSPadding);
    static NAN_METHOD(VerifyPSSPadding);

  private:
    static RsaWrap *expectPrivateKey(RsaWrap* obj);
    static RsaWrap *expectSet(RsaWrap* obj);
    static RsaWrap *expectUnset(RsaWrap* obj);

    RSA *rsa;
};

NAN_METHOD(TextToNid);

#endif // def URSA_NATIVE_H
