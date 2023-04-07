#include <assert.h>
#include <iostream>
#include <vector>
#include <climits>
#include <cstdlib>

using namespace std;

#ifndef CXX_MODEL_C3_MODEL_H_

// On 64 bit system, MEM_SIZE is (2^64) - 1
#define MEM_SIZE ULLONG_MAX
#define S_IDX 63
#define S_PRIME_IDX 47
#define MAX_POWER 34

// Macro: bv[start:end]
#define __BVSLICE__(x, start, end) ((x >> end) & ((1ULL << (start + 1ULL - end)) - 1ULL))

// Crypto primitives
// tweak (arg : bv38) : bv24 = arg[23 : 0] ^ (0bv10 ++ arg[37 : 24]);
#define __TWEAK__(x) (((x) & 0xFFFFFF) ^ (x >> 24))
// k_cipher(plaintext : bv24, key : bv24, tweak : bv24) : bv24 = plaintext ^ key ^ tweak;
#define __K_CIPHER__(pt, key, tweak) (pt ^ key ^ tweak)

typedef uint64_t word_t;
typedef uint64_t data_key_t;

/* Memory interface */
class lazy_mem {

    struct alloc_t {
        uint64_t base;
        uint64_t size;
    };

public:
    vector<alloc_t> mem;
    uint64_t mem_size;

    bool is_alloc (uint64_t addr) {
        for (size_t i = 0; i < mem.size(); i++) {
            if (addr >= mem[i].base && addr < mem[i].base + mem[i].size) {
                return true;
            }
        }
        return false;
    }

    uint64_t make_alloc (uint64_t size, uint64_t start = 0) {
        uint64_t base = start;
        vector<alloc_t>::iterator it_ins = mem.begin();
        for (vector<alloc_t>::iterator it = mem.begin(); it != mem.end(); it++) {
            if (it->base - base >= size) {
                it_ins = it;
                break;
            }
            base = it->base + it->size;
        }
        if (mem_size - base < size) {
            return MEM_SIZE;
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

    lazy_mem (uint64_t size) : mem_size(size) { }

};

typedef struct {
    uint64_t power;
    
} ca_t;


/* C3 Wrapped API of memory */
class c3_model {

public:

    lazy_mem mem = lazy_mem(MEM_SIZE);
    data_key_t pointer_key;
    data_key_t data_key;

    c3_model() {
        pointer_key = __BVSLICE__(pointer_key, 24, 0);
        data_key = __BVSLICE__(data_key, 24, 0);
    }

    uint64_t get_power (uint64_t base, uint64_t size) {
        assert(base + size <= MEM_SIZE);
        uint64_t power = (64ULL - __builtin_clzll((base ^ (base + size)) & ((1ULL << MAX_POWER) - 1ULL)));
        assert(power <= MAX_POWER);
        return power;
    }

    uint64_t data_keystream_module (ca_t ca) {
        return (pow(ca, 2) ^ data_key + 1) % (1 << 63);
    }

    uint64_t store_byte_c3 (ca_t ca, char byte) {
        uint64_t power = __BVSLICE__(ca, 62, 57);
        uint64_t offset = __BVSLICE__(ca, (power - 1), 0);

        uint64_t keystream = data_keystream_module(ca);

        char mask = __BVSLICE__(keystream, offset, offset);

        char enc = byte ^ mask;
        char dec = enc ^ mask;
        return 0;
    }

    uint64_t malloc_c3 (uint64_t size, uint64_t start = 0) {
        uint64_t base = mem.make_alloc(size, start);
        if (base == MEM_SIZE) {
            return MEM_SIZE;
        }
        
        uint64_t power = get_power(base, size);
        
        uint64_t sign = __BVSLICE__(base, S_IDX, S_IDX);
        uint64_t upper_addr = __BVSLICE__(base, 46, (MAX_POWER + 1));
        uint64_t s_prime = __BVSLICE__(base, S_PRIME_IDX, S_PRIME_IDX);

        uint64_t fixed_addr = __BVSLICE__(base, MAX_POWER, power);

        uint64_t offset = __BVSLICE__(base, (power - 1), 0);
        
        uint64_t tweak = __TWEAK__((power << (MAX_POWER-power+1)) | fixed_addr);
        
        uint64_t encrypted_slice = __K_CIPHER__(upper_addr, pointer_key, tweak);
        uint64_t upper_encrypted = __BVSLICE__(encrypted_slice, 24, 16);
        uint64_t lower_encrypted = __BVSLICE__(encrypted_slice, 15, 0);
        std::cout << hex << encrypted_slice << endl;
        std::cout << hex << power << endl;

        return (sign << 63) | (power << 57) | (upper_encrypted << 48)
            | (s_prime << 47) | (lower_encrypted << 32)
            | (__BVSLICE__(base, 31, 0));
    }

};

#endif // CXX_MODEL_C3_MODEL_H_
