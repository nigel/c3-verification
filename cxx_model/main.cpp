#include "c3_model.h"

using namespace std;

int main(int argc, char *argv[]) {
    c3_model model;
    uint64_t s = 12888;
    uint64_t ptr = model.malloc_c3(s, 0x87122312acd3ffa);

    if (ptr == MEM_SIZE) {
        cout << "Error when allocating size " << s << endl;
        return 0;
    }

    cout << hex << ptr << endl;
    return 0;
}
