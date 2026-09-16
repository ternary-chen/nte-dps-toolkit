// 链接实际 app/main.cpp；意外进入监控入口时使定向测试失败。
#include "nte/loader/App/LoaderApp.h"
namespace nte::loader {
int LoaderApp::Run(const LoaderConfig&) { return 99; }
}
