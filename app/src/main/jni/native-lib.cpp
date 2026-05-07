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
#include <vector>

#define TAG "PhantomHarvester"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int sockfd = -1;
static std::mutex mtx;

// دالة إرسال البيانات
void sendData(const std::string& msg) {
    if (sockfd >= 0) {
        std::lock_guard<std::mutex> lock(mtx);
        send(sockfd, msg.c_str(), msg.size(), 0);
    }
}

// الاتصال بالخادم
void connectToServer() {
    while (true) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) { sleep(1); continue; }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(50051);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == 0) {
            LOGI("Connected to Shadow App");
            break;
        }
        close(sockfd); sockfd = -1; sleep(1);
    }
}

// ماسح الأنماط في الذاكرة
void* findPattern(void* start, size_t size, const char* pattern, size_t len) {
    for (size_t i = 0; i <= size - len; i++) {
        bool found = true;
        for (size_t j = 0; j < len; j++) {
            if (pattern[j] != '\xFF' && ((char*)start)[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return (char*)start + i;
    }
    return nullptr;
}

// حصاد الأوفستات
void harvestOffsets() {
    void* anogs = dlopen("libanogs.so", RTLD_NOLOAD);
    if (!anogs) {
        sendData("ERROR: libanogs.so not found\n");
        return;
    }
    
    // الحصول على قاعدة المكتبة
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    char line[512];
    uintptr_t base = 0, end = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libanogs.so") && strstr(line, "r-xp")) {
            sscanf(line, "%lx-%lx", &base, &end);
            break;
        }
    }
    fclose(fp);
    if (!base) {
        sendData("ERROR: base not found\n");
        return;
    }
    size_t size = end - base;
    void* mem = (void*)base; // قراءة مباشرة من الذاكرة

    // أنماط البحث لدوال الحماية (أمثلة - يجب استبدالها بالأنماط الحقيقية)
    struct { const char* name; const char* pattern; size_t len; } targets[] = {
        {"AnoSDKInit", "\x00\x00\x00\x00", 4}, // وضع نمط حقيقي هنا
        {"AnoSDKGetReportData", "\x00\x00\x00\x00", 4},
        {"AnoSDKIoctl", "\x00\x00\x00\x00", 4}
    };

    for (auto& target : targets) {
        void* addr = findPattern(mem, size, target.pattern, target.len);
        if (addr) {
            uintptr_t offset = (uintptr_t)addr - base;
            std::string msg = target.name + std::string(": 0x") + std::to_string(offset) + "\n";
            sendData(msg);
        } else {
            sendData(target.name + std::string(": NOT FOUND\n"));
        }
    }
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    new std::thread(connectToServer);
    sleep(2); // انتظار الاتصال
    harvestOffsets();
    return JNI_VERSION_1_6;
}
