#include <cstring>
void copy(char* dst, const char* src) {
    char buf[32];
    memcpy(buf, src, sizeof(buf));
    std::memcpy(dst, src, sizeof buf);
}
