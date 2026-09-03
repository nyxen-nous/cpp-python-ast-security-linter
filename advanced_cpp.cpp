// Additional C++ security/regression corpus.
#include <cstddef>
#include <cstdlib>

void use_after_free() {
    int* p = new int(42);
    delete p;
    // EXPECT CPP.SEC.010
    return *p;
}

void double_free(int* p) {
    // EXPECT CPP.SEC.011
    delete p;
    delete p;
}

int uninitialized_local() {
    int value;
    // EXPECT CPP.SEC.012
    return value;
}

char* uncontrolled_alloc(int n) {
    // EXPECT CPP.SEC.013
    return new char[n];
}

int null_deref() {
    int* p = nullptr;
    // EXPECT CPP.SEC.014
    return *p;
}
