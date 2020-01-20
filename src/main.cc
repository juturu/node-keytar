#include "nan.h"
#include "async.h"

namespace {

NAN_METHOD(SetPassword) {
  SetPasswordWorker* worker = new SetPasswordWorker(
    *v8::String::Utf8Value(info[0]),
    *v8::String::Utf8Value(info[1]),
    *v8::String::Utf8Value(info[2]),
    *v8::String::Utf8Value(info[3]),
    info[4]->Int32Value(),
    info[5]->Int32Value(),
    new Nan::Callback(info[6].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(GetPassword) {
  GetPasswordWorker* worker = new GetPasswordWorker(
    *v8::String::Utf8Value(info[0]),
    *v8::String::Utf8Value(info[1]),
    new Nan::Callback(info[2].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(DeletePassword) {
  DeletePasswordWorker* worker = new DeletePasswordWorker(
    *v8::String::Utf8Value(info[0]),
    *v8::String::Utf8Value(info[1]),
    new Nan::Callback(info[2].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(FindPassword) {
  FindPasswordWorker* worker = new FindPasswordWorker(
    *v8::String::Utf8Value(info[0]),
    new Nan::Callback(info[1].As<v8::Function>()));
  Nan::AsyncQueueWorker(worker);
}

NAN_MODULE_INIT(Init) {
  Nan::SetMethod(target, "getPassword", GetPassword);
  Nan::SetMethod(target, "setPassword", SetPassword);
  Nan::SetMethod(target, "deletePassword", DeletePassword);
  Nan::SetMethod(target, "findPassword", FindPassword);
}

}  // namespace

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(keytar, Init)
#else
NODE_MODULE(keytar, Init)
#endif
