#include <memory>

void safe() {
    std::unique_ptr<int> p(new int(2));
    std::shared_ptr<int> q(new int(3));
}
