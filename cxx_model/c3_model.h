

#include <assert.h>
#include <iostream>
#include <vector>

using namespace std;

#ifndef CXX_MODEL_C3_MODEL_H_

#define MEM_SIZE 1 << 64
#define S_IDX 63
#define S_PRIME_IDX 47
#define POWER_LIMIT 34

// Macro: bv[start:end]
#define __BVSLICE__(x, start, end) ((x >> end) & ((1 << (start + 1 - end)) - 1))

// Crypto primitives
// tweak (arg : bv38) : bv24 = arg[23 : 0] ^ (0bv10 ++ arg[37 : 24]);
#define __TWEAK__(x) ((x & 0xFFFFFF) ^ (x >> 24))
// k_cipher(plaintext : bv24, key : bv24, tweak : bv24) : bv24 = plaintext ^ key ^ tweak;
#define __K_CIPHER__(pt, key, tweak) (pt ^ key ^ tweak)

typedef uint word_t;
typedef uint key_t;


class lazy_mem {

    struct alloc_t {
        uint base;
        uint size;
    };

public:
    vector<alloc_t> mem;
    uint mem_size;

    bool is_alloc (uint addr) {
        for (int i = 0; i < mem.size(); i++) {
            if (addr >= mem[i].base && addr < mem[i].base + mem[i].size) {
                return true;
            }
        }
        return false;
    }

    uint make_alloc (uint size, uint start = 0) {
        uint base = start;
        vector<alloc_t>::iterator it_ins = mem.begin();
        for (vector<alloc_t>::iterator it = mem.begin(); it != mem.end(); it++) {
            if (it->base - base >= size) {
                it_ins = it;
                break;
            }
            base = it->base + it->size;
        }
        if (mem_size - base < size) {
            return -1;
        }
        alloc_t a;
        a.base = base;
        a.size = size;
        mem.insert(it_ins++, a);
        return base;
    }

    void print_mem () {
        cout << "Memory: " << endl;
        for (vector<alloc_t>::iterator it = mem.begin(); it != mem.end(); it++) {
            cout << "[" << it->base << ", " << it->size + it->base << "] ";
        }
        cout << endl;
    }

    lazy_mem (uint size) : mem_size(size) { }

};

typedef struct {
    uint power;
    
} ca_t;


class c3_model {

public:

    lazy_mem mem = lazy_mem(MEM_SIZE);
    key_t pointer_key;
    key_t data_key;


    uint get_power (uint base, uint size) {
        assert(base + size <= MEM_SIZE);
        uint power = (64 - __builtin_clz((base ^ (base + size)) & ((1 << MAX_POWER) - 1)));
        assert(power <= MAX_POWER);
        return power;
    }

    uint malloc_c3 (uint size, uint start) {
        uint base = mem.make_alloc(size, start);
        if (base == -1) {
            return -1;
        }
        
        uint power = get_power(base, size);
        
        uint sign = __BVSLICE__(base, S_IDX, S_IDX);
        uint upper_addr = __BVSLICE__(base, 46, MAX_POWER+1);
        uint s_prime = __BVSLICE__(base, S_PRIME_IDX, S_PRIME_IDX);
        uint fixed_addr = __BVSLICE__(base, MAX_POWER, power);
        uint offset = __BVSLICE__(base, power-1, 0);
        
        uint tweak = __TWEAK__((power << (MAX_POWER-power+1)) | fixed_addr);
        
        uint encrypted_slice = __K_CIPHER__(upper_addr, pointer_key, tweak);
    }

};



#endif // CXX_MODEL_C3_MODEL_H_