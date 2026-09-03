// Safe counterparts for the additional C++ rules.
#include <memory>
#include <random>

int initialized_local() {
    int value = 42;
    return value;
}

std::unique_ptr<int> managed_value() {
    return std::make_unique<int>(42);
}

void freed_once(int* p) {
    delete p;
    p = nullptr;
}

int fixed_value() {
    int value = 64;
    return value;
}

int checked_deref(int* p) {
    if (p == nullptr) return 0;
    return *p;
}
