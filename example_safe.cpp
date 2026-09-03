// Safe-code corpus (C++).
// Every block is the safe counterpart of a pattern the analyzer detects.
// The analyzer must report ZERO findings in this file.

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <random>
#include <string>

void read_name_safely() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);      // bounded, unlike gets()
}

void copy_name_safely(const char* src) {
    char dest[32];
    strncpy(dest, src, sizeof(dest) - 1);  // bounded copy
    dest[sizeof(dest) - 1] = '\0';
}

void read_input_safely() {
    char name[16];
    scanf("%15s", name);                 // explicit field width
}

unsigned int strong_token() {
    std::random_device rd;               // not rand()
    return rd();
}

void log_message_safely(const char* userMessage) {
    printf("%s", userMessage);           // literal format string
}

void copy_block_safely(char* dst, char* src) {
    memcpy(dst, src, 16);                // constant length
}

void manage_memory() {
    int* values = new int[100];
    values[0] = 1;
    delete[] values;                     // matching delete
}

const char* config_path = "/etc/app/config.yaml";   // not a credential
