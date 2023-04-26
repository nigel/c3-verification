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
    cout << "WRITING WITHIN BOUNDS" << endl;
    model.store_c3(ptr + 5, 11);
    cout << "READING OOB" << endl;
    bool res = model.read_c3(ptr + 9, 11); // read +4 bytes OOB
    cout << endl;

    // assertion fails
    assert (res);

    return 0;
}
