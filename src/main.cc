#include "nan.h"
#include "async.h"

namespace {

NAN_METHOD(SetPassword) {
  auto service = std::string(*v8::String::Utf8Value(info[0]));
  auto account = std::string(*v8::String::Utf8Value(info[1]));
  auto passwd = std::string(*v8::String::Utf8Value(info[2]));
  SetPasswordWorker* worker = new SetPasswordWorker(
    service,
    account,
    passwd,
    new Nan::Callback(info[3].As<v8::Function>()));
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

void Init(v8::Handle<v8::Object> exports) {
  Nan::SetMethod(exports, "getPassword", GetPassword);
  Nan::SetMethod(exports, "setPassword", SetPassword);
  Nan::SetMethod(exports, "deletePassword", DeletePassword);
  Nan::SetMethod(exports, "findPassword", FindPassword);
}

}  // namespace

NODE_MODULE(keytar, Init)
