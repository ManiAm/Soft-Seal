#include <cstdio>
#include "obfusheader.h"  // adjust path if needed

// Simple function we will call via CALL()
void secret_function(const char* msg)
{
    std::printf("[secret_function] %s\n", msg);
}

int main()
{
    // 1) Direct use of OBF for string and integers
    std::printf(
        "char*: %s\n"
        "int (dec): %d\n"
        "boolean: %d\n",
        OBF("this is a secret literal"),
        OBF(123),
        OBF(true)
    );

    std::printf("\n");

    // 2) Safe usage via MAKEOBF (as shown in README)
    auto obf = MAKEOBF("another secret");
    std::printf("MAKEOBF decrypted: %s\n", (char*)obf);

    std::printf("\n");

    // 3) Call hiding. Note the & on the function
    CALL(&secret_function, OBF("calling hidden function"));

    std::printf("\n");

    // 4) Hiding a printf call
    CALL(&std::printf, OBF("Very secure call from printf\n"));

    return 0;
}
