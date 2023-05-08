#include <assert.h>
#include <algorithm>
#include <iostream>
#include <climits>
#include <cstdlib>
#include <vector>
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

/* C3 Wrapped API of memory */
class c3_model {

private:

    /* start of memory safety monitor */
    typedef enum {
        ENCRYPTED,
        UNINITIALIZED,
        GARBLED
    } alloc_state_t;

    struct alloc_t {
        uint64_t ca;
        data_key_t data_key;
        data_key_t pointer_key;
        alloc_state_t state;
        bool allocated; // Is this allocation active? (not freed/unitialized)
    };


    // used to generate the encrypted slice in a safe manner
    std::vector<uint64_t> encrypted_slices;
    std::vector<alloc_t *> mem_arr;

    /* Returns all the alloc_t's associated w/ "ca" using the "p_key". Stores them into "vec" */
    void find_allocs_from_ca (uint64_t ca, vector<alloc_t *> *vec, data_key_t p_key) {
        for (alloc_t *i : mem_arr) {
            if ((i->ca == ca) && (i->pointer_key == p_key)) {
                vec->push_back(i);
            }
        }
    }

    /* Generates a unique encrypted slice */
    // TODO shoudl take into account the PID
    uint64_t get_encrypted_slice() {
        uint64_t retval = rand() % (1 << 24);
        while (std::count(encrypted_slices.begin(), encrypted_slices.end(), retval))
            retval = rand() % (1 << 24);
        return retval;
    }

    /* Adds entry to the mem_arr */
    void add_to_mem_arr(uint64_t ca, data_key_t pointer_key,
            alloc_state_t state = UNINITIALIZED, data_key_t d_key = 0, bool allocated = true) {
        // TODO find existing allocs

        std::vector<alloc_t *> allocs;
        find_allocs_from_ca (ca, &allocs, pointer_key);

        assert((allocs.size() == 1) || (allocs.size() == 0));

        if ((allocs.size() != 0) && (!allocs[0]->allocated)) {
            allocs[0]->allocated = true;
            return;
        }

        alloc_t *_alloc = (alloc_t *) calloc(sizeof(alloc_t), 1);
        assert (_alloc != 0);

        _alloc->state = state;
        _alloc->ca = ca;
        _alloc->pointer_key = pointer_key;
        _alloc->data_key = d_key;
        _alloc->allocated = allocated;
        mem_arr.push_back(_alloc);
    }


    /* end of memory safety monitor */

    data_key_t pointer_key;
    data_key_t data_key;

    // From malloc/try_box
    // https://github.com/IntelLabs/c3-simulator/blob/b01f1ea97979327be420ed0eb8f7cb8a8e759e04/malloc/try_box.h
    uint64_t get_power (uint64_t base, uint64_t size) {
        assert (base + size <= MEM_SIZE);
        /*
        uint64_t power = (64ULL - __builtin_clzll((base ^ (base + size)) & ((1ULL << MAX_POWER) - 1ULL)));
        */
		size = (size < (1UL << 0) ? (1UL << 0) : size);
		size_t max_off = size - 1;
		uint64_t ptr_end = base + max_off;
		uint64_t diff = base ^ ptr_end;
		uint64_t leading_zeros_in_diff = (diff == 0 ? 64 : __builtin_clzl(diff));

		if (leading_zeros_in_diff < 32) {
            assert (false);
			return 0;
		}
		uint8_t enc_size = (uint8_t)(64 - leading_zeros_in_diff);

        printf("Enc_size: %u\n", enc_size);

        assert (enc_size < 34);
        assert (enc_size >= 1);

		return enc_size;
    }

    uint64_t data_keystream_module (uint64_t ca) {
        // (x^2) ^ data_key  + 1
        return (((ca * ca) ^ data_key) + 1) % (1ULL << 63);
    }

    char read_byte_c3(uint64_t ca, data_key_t data_key, data_key_t pointer_key) {

        std::vector<alloc_t *> allocs;
        find_allocs_from_ca(ca, &allocs, pointer_key);

        // sanity check
        assert(allocs.size() == 1);

        alloc_t *a = allocs[0];

        return a->data_key == data_key;
    }

    uint64_t get_fixed_addr(uint64_t ca, uint64_t power) {
        return __BVSLICE__(ca, 31, power);
    }

    void store_byte_c3 (uint64_t ca) {
        std::vector<alloc_t *> allocs;
        find_allocs_from_ca(ca, &allocs, pointer_key);

        // Empty result vector, must be an OOB or UAF
        if (allocs.empty()) {
            add_to_mem_arr(ca,
                    pointer_key,
                    ENCRYPTED,
                    data_key,
                    false);
            return;
        }

        assert(allocs.size() == 1);

        // Overwrite the previous, shit's now encrypted with new data
        for (alloc_t *i : allocs) {
            // assuming that CAs dont map to same LAs
            i->state = ENCRYPTED;
            i->data_key = data_key;
        }

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

    c3_model() {
        srand (time(NULL));
        pointer_key = __BVSLICE__(TEMP_KEY, 24, 0);
        data_key = __BVSLICE__(TEMP_KEY, 24, 0);
    }

    void store_c3 (uint64_t ca, uint64_t size) {
        for (uint64_t i = 0; i < size; i += 1) {
            store_byte_c3(ca + i);
        }
    }

    /* Returns true if the READ did not violate confidentiality properties */
    bool read_c3 (uint64_t ca, uint64_t size) {
        uint64_t i;
        for (i = 0; i < size; i += 1) {
            printf("checking byte %lu\n", i);
            if (!read_byte_c3(ca + i, data_key, pointer_key)) {
                printf("CONFIDENTIALITY VIOLATION ON BYTE %lu\n", i);
                return false;
            }
        }

        return true;
    }

    uint64_t malloc_c3 (uint64_t size) {
        
        uint64_t base = (uint64_t) malloc(size);
        std::cout << "Raw addr : " << hex << base << std::endl;

        // Create CA
        uint64_t power = get_power(base, size);
        
        uint64_t sign = __BVSLICE__(base, S_IDX, S_IDX);
        //uint64_t upper_addr = __BVSLICE__(base, 46, 32);
        uint64_t s_prime = __BVSLICE__(base, S_PRIME_IDX, S_PRIME_IDX);

        //uint64_t fixed_addr = get_fixed_addr(base, power);

        /*
        uint64_t tweak = __TWEAK__((power << (31-power+1)) | fixed_addr);
        uint64_t encrypted_slice = __K_CIPHER__(upper_addr, pointer_key, tweak);
        */
        uint64_t encrypted_slice = get_encrypted_slice();

        uint64_t upper_encrypted = __BVSLICE__(encrypted_slice, 23, 15);
        uint64_t lower_encrypted = __BVSLICE__(encrypted_slice, 14, 0);

        uint64_t ca = (sign << 63) | (power << 57) | (upper_encrypted << 48)
            | (s_prime << 47) | (lower_encrypted << 32)
            | (__BVSLICE__(base, 31, 0));

        printf("Power: %ld\n", power);

        // Initialize the mem safety monitor entry
        for (uint64_t i = 0; i < size; i += 1)
            add_to_mem_arr(ca + i, pointer_key);

        return ca;
    }

};

#endif // CXX_MODEL_C3_MODEL_H_
