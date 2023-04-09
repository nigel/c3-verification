#include <assert.h>
#include <iostream>
#include <vector>
#include <climits>
#include <cstdlib>
#include <cmath>

using namespace std;

#ifndef CXX_MODEL_C3_MODEL_H_

// On 64 bit system, MEM_SIZE is (2^64) - 1
#define MEM_SIZE ULLONG_MAX
#define S_IDX 63
#define S_PRIME_IDX 47
#define MAX_POWER 34
#define TEMP_KEY 13371337

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
    vector<alloc_t *> mem;

    uint64_t mem_size;

    bool is_alloc (uint64_t addr) {
        for (size_t i = 0; i < mem.size(); i++) {
            if (addr >= mem[i]->base && addr < mem[i]->base + mem[i]->size) {
                return true;
            }
        }
        return false;
    }

    uint64_t make_alloc (uint64_t size) {
        void *base = malloc(size);
        assert (base != NULL);
        return (uint64_t) base;
        /*
        uint64_t base = start;
        vector<alloc_t *>::iterator it_ins = mem.begin();
        for (vector<alloc_t *>::iterator it = mem.begin(); it != mem.end(); it++) {
            alloc_t *_alloc = *it;

            if (_alloc->base - base >= size) {
                it_ins = it;
                break;
            }
            base = _alloc->base + _alloc->size;
        }
        if (mem_size - base < size) {
            return MEM_SIZE;
        }
        alloc_t *a = (alloc_t *) calloc(sizeof(alloc_t) + size, 1);
        a->base = base;
        a->size = size;
        mem.insert(it_ins++, a);
        return base;
        */
    }

    void print_mem () {
        cout << "Memory: " << endl;
        for (vector<alloc_t *>::iterator it = mem.begin(); it != mem.end(); it++) {
            alloc_t *_alloc = *it;
            cout << "[" << _alloc->base << ", " << _alloc->size + _alloc->base << "] ";
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

private:
    data_key_t pointer_key;
    data_key_t data_key;

    uint64_t get_fixed_addr(uint64_t ca, uint64_t power) {
        return __BVSLICE__(ca, 31, power);
    }

    uint64_t decode_addr_c3 (uint64_t ca) {
        uint64_t power = __BVSLICE__(ca, 62, 57);
        uint64_t ciphertext = 
            ( __BVSLICE__(ca, 56, 48) << 16) | (__BVSLICE__(ca, 46, 32));
        uint64_t fixed_addr = get_fixed_addr(ca, power);
        uint64_t tweak = __TWEAK__((power << (31-power+1)) | fixed_addr);

        uint64_t sign = __BVSLICE__(ca, S_IDX, S_IDX);
        uint64_t s_prime = __BVSLICE__(ca, S_PRIME_IDX, S_PRIME_IDX);

        uint64_t plain_addr = __K_CIPHER__(ciphertext, pointer_key, tweak);
        plain_addr = __BVSLICE__(plain_addr, 14, 0);

        return (sign << 63ULL) | ((65535ULL & s_prime) << 47) | (plain_addr << 32) | (__BVSLICE__(ca, 31, 0));
    }

public:

    lazy_mem mem = lazy_mem(MEM_SIZE);

    c3_model() {
        srand (time(NULL));
        pointer_key = __BVSLICE__(TEMP_KEY, 24, 0);
        data_key = __BVSLICE__(TEMP_KEY, 24, 0);
    }

    uint64_t get_power (uint64_t base, uint64_t size) {
        assert(base + size <= MEM_SIZE);
        uint64_t power = (64ULL - __builtin_clzll((base ^ (base + size)) & ((1ULL << MAX_POWER) - 1ULL)));
        assert(power <= MAX_POWER);
        return power;
    }

    uint64_t data_keystream_module (uint64_t ca) {
        // (x^2) ^ data_key  + 1
        return (((ca * ca) ^ data_key) + 1) % (1ULL << 63);
    }

    void store_byte_c3 (uint64_t ca, char byte) {
        uint64_t power = __BVSLICE__(ca, 62, 57);
        uint64_t offset = __BVSLICE__(ca, (power - 1), 0) % 8;

        /* Encrypting data */
        uint64_t keystream = data_keystream_module(ca & (~15ULL));
        char mask = __BVSLICE__(keystream, offset, offset);
        char enc = byte ^ mask;

        /* Decrypting CA */
        char *addr = (char *) decode_addr_c3(ca);

        *addr = enc;
    }

    void store_c3 (uint64_t ca, string data, uint64_t size) {
        uint64_t i;
        uint64_t power = __BVSLICE__(ca, 62, 57);

        if (size >= (1ULL << power)) {
            return;
        }
        for (i = 0; i < size; i += 1) {
            store_byte_c3(ca + i, data[i]);
        }
    }

    uint64_t malloc_c3 (uint64_t size) {
        uint64_t base = mem.make_alloc(size);
        if (base == MEM_SIZE) {
            return MEM_SIZE;
        }
        std::cout << "Raw addr : " << hex << base << std::endl;
        
        uint64_t power = get_power(base, size);
        
        uint64_t sign = __BVSLICE__(base, S_IDX, S_IDX);
        uint64_t upper_addr = __BVSLICE__(base, 46, 32);
        uint64_t s_prime = __BVSLICE__(base, S_PRIME_IDX, S_PRIME_IDX);

        uint64_t fixed_addr = get_fixed_addr(base, power);
        uint64_t tweak = __TWEAK__((power << (31-power+1)) | fixed_addr);
        
        uint64_t encrypted_slice = __K_CIPHER__(upper_addr, pointer_key, tweak);
        uint64_t upper_encrypted = __BVSLICE__(encrypted_slice, 23, 15);
        uint64_t lower_encrypted = __BVSLICE__(encrypted_slice, 14, 0);

        return (sign << 63) | (power << 57) | (upper_encrypted << 48)
            | (s_prime << 47) | (lower_encrypted << 32)
            | (__BVSLICE__(base, 31, 0));
    }

};

#endif // CXX_MODEL_C3_MODEL_H_
