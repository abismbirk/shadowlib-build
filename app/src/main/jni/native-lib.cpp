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
#include <fstream>
#include <sstream>
#include <fcntl.h>

#define TAG "ShadowAgent"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static int sockfd = -1;
static std::mutex mtx;

void sendData(const std::string& msg) {
    if (sockfd >= 0) {
        std::lock_guard<std::mutex> lock(mtx);
        send(sockfd, msg.c_str(), msg.size(), 0);
    }
}

void connectToServer() {
    while (true) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) { sleep(1); continue; }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(50051);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == 0) {
            LOGI("Connected to Legion OS");
            sendData("AGENT_ONLINE\n");
            return;
        }
        close(sockfd); sockfd = -1; sleep(1);
    }
}

// استخراج عنوان قاعدة libanogs.so من /proc/self/maps
uintptr_t getAnogsBase() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("libanogs.so") != std::string::npos && line.find("r-xp") != std::string::npos) {
            uintptr_t base = std::stoull(line.substr(0, line.find('-')), nullptr, 16);
            maps.close();
            return base;
        }
    }
    maps.close();
    return 0;
}

// استخراج الأوفستات باستخدام dlsym
void harvestOffsets() {
    void* anogs = dlopen("libanogs.so", RTLD_NOLOAD);
    if (!anogs) {
        sendData("ERROR: libanogs.so not loaded\n");
        return;
    }

    uintptr_t base = getAnogsBase();
    if (!base) {
        sendData("ERROR: base not found\n");
        return;
    }

    // قائمة دوال الحماية المستهدفة
    std::vector<std::string> targets = {
        "AnoSDKInit", "AnoSDKGetReportData", "AnoSDKGetReportData2",
        "AnoSDKGetReportData3", "AnoSDKGetReportData4", "AnoSDKIoctl",
        "AnoSDKIoctlOld", "AnoSDKOnRecvData", "AnoSDKOnRecvSignature",
        "AnoSDKRegistInfoListener", "AnoSDKSetUserInfo",
        "AnoSDKSetUserInfoWithLicense", "AnoSDKDelReportData",
        "AnoSDKDelReportData3", "AnoSDKDelReportData4"
    };

    std::ostringstream msg;
    msg << "OFFSETS_START\n";
    for (const auto& sym : targets) {
        void* addr = dlsym(RTLD_DEFAULT, sym.c_str());
        if (addr) {
            uintptr_t offset = (uintptr_t)addr - base;
            msg << sym << ": 0x" << std::hex << offset << "\n";
        }
    }
    msg << "OFFSETS_END\n";
    sendData(msg.str());
    LOGI("Offsets harvested and sent");
}

// البحث عن عناوين IP:Port محتملة في مقاطع بيانات libanogs.so
void scanForServers() {
    uintptr_t base = getAnogsBase();
    if (!base) return;

    std::ifstream maps("/proc/self/maps");
    std::string line;
    uintptr_t start = 0, end = 0;
    while (std::getline(maps, line)) {
        if (line.find("libanogs.so") != std::string::npos && line.find("rw-p") != std::string::npos) {
            start = std::stoull(line.substr(0, line.find('-')), nullptr, 16);
            end = std::stoull(line.substr(line.find('-') + 1, line.find(' ') - line.find('-') - 1), nullptr, 16);
            break;
        }
    }
    maps.close();

    if (!start || !end) return;

    size_t size = end - start;
    void* mem = (void*)start;

    std::ostringstream msg;
    msg << "SERVERS_START\n";
    // فحص بسيط للعثور على أنماط IP رقمية
    for (size_t i = 0; i <= size - 4; i += 4) {
        unsigned char* p = (unsigned char*)mem + i;
        if (p[0] >= 1 && p[0] <= 223 && p[1] < 256 && p[2] < 256 && p[3] < 256) {
            // تحقق إضافي من البورت
            if (i + 6 < size) {
                unsigned short port = *(unsigned short*)(p + 4);
                if (port > 0 && port < 65535) {
                    msg << (int)p[0] << "." << (int)p[1] << "." << (int)p[2] << "." << (int)p[3] << ":" << port << "\n";
                }
            }
        }
    }
    msg << "SERVERS_END\n";
    sendData(msg.str());
    LOGI("Server scan completed");
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    new std::thread([]() {
        connectToServer();
        sleep(3); // انتظار تحميل المكتبات
        harvestOffsets();
        scanForServers();
    });
    return JNI_VERSION_1_6;
}
