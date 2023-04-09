#include <string>
#include "c3_model.h"

using namespace std;

int main(void) {
    c3_model model;
    uint64_t s = 12888;
    uint64_t ptr = model.malloc_c3(s);

    if (ptr == MEM_SIZE) {
        cout << "Error when allocating size " << s << endl;
        return 0;
    }

    cout << "Encrypted Address: " << hex << ptr << endl;

    string dat = "AAAAAAAAAAAAAAAAAAAAAAAAAAA";

    model.store_c3(ptr, dat, 12);

    return 0;
}
