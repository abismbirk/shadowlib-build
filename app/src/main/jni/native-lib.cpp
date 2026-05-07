#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <cstring>
#include <android/log.h>

#define TAG "ShadowInterceptor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int sockfd = -1;
static std::mutex mtx;

void connectToServer() {
    while (true) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) { sleep(1); continue; }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(50051);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == 0) break;
        close(sockfd); sockfd = -1; sleep(1);
    }
    LOGI("Connected to Shadow App");
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    new std::thread(connectToServer);
    return JNI_VERSION_1_6;
}
