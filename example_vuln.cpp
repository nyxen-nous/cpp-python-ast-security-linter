// Vulnerable-code corpus (C++).
// Each block contains one deliberate weakness. The EXPECT comment names the
// rule that must fire.
//
// The comment below is a decoy: it mentions gets( and strcpy( and system(
// which a regex-based scanner would flag. A tokenizer never sees them as code.

#include <cstdio>
#include <cstring>
#include <cstdlib>

// EXPECT CPP.SEC.009
const char* db_password = "hunter2-production-db";

void read_name() {
    char buf[64];
    // EXPECT CPP.SEC.001
    gets(buf);
}

void copy_name(const char* src) {
    char dest[32];
    // EXPECT CPP.SEC.002
    strcpy(dest, src);
}

void run_shell(const char* userInput) {
    // EXPECT CPP.SEC.003
    system(userInput);
}

void read_input() {
    char name[16];
    // EXPECT CPP.SEC.004
    scanf("%s", name);
}

int weak_token() {
    // EXPECT CPP.SEC.005
    return rand();
}

void log_message(char* userMessage) {
    // EXPECT CPP.SEC.006
    printf(userMessage);
}

void copy_block(char* dst, char* src, int len) {
    // EXPECT CPP.SEC.007
    memcpy(dst, src, len);
}

void leak_memory() {
    // EXPECT CPP.SEC.008
    int* values = new int[100];
    values[0] = 1;
}

// This string literal must NOT match: "call gets(buf) and strcpy(a,b) now"
const char* doc = "call gets(buf) and strcpy(a,b) now";
