// Coverage for CPP.SEC.009 after the secret-name refinement.
//
// The qualifier suppression mirrors the Python side, and `pw` is now a
// recognised abbreviation. Exactly two findings are expected: pw and password.
//
// EXPECT CPP.SEC.009

#include <cstring>

void qualifiers_are_not_secrets() {
    const char* token_type = "encoded-word";
    const char* auth_scheme = "bearer-authentication";
    const char* password_field = "user_password_entry";
    const char* secret_name = "primary-database";
}

void real_credentials() {
    char pw[] = "hunter2secret";
    const char* password = "admin-p4ssw0rd";
}
