// test_logappend.cpp
#include <cassert>
#include "logappend.cpp"  // Include your header or implementation files

void testIsValidName() {
    assert(isValidName("JohnDoe") == true);
    assert(isValidName("") == false);
    assert(isValidName("John123") == false);
}

void testIsValidRoomId() {
    assert(isValidRoomId("101") == true);
    assert(isValidRoomId("-1") == false);
    assert(isValidRoomId("Room1") == false);
}

int main() {
    testIsValidName();
    testIsValidRoomId();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}