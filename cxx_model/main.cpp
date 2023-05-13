#include <string>
#include "c3_model.h"

using namespace std;

int main(void) {
    c3_model model;
    uint64_t ptr = model.malloc_c3(20);

    // write within bounds
    model.store_c3(ptr + 5, 11);

    // read +4 bytes OOB
    bool res = model.read_c3(ptr + 9, 11); 
    assert (res);

    return 0;
}
