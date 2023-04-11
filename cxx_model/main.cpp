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

    string dat = "Hello World";

    model.store_c3(ptr, dat, 11);
    string *lol = model.read_c3(ptr, 11);

    cout << "Decrypted: " << *lol << endl;

    delete lol;

    return 0;
}
