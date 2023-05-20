# c3-verification
A foundational model to verify the confidentiality guarantees of C3

## Model Description
We provide a standard memory management API to the adversary in a four process (PIDs) system:

- `malloc (size : bv64, pointer_key : bv24)`
- `read_byte (ca : ca_t, data_key : bv24, pointer_key : bv24)`
- `write_byte (ca : ca_t, data_key : bv24, pointer_key : bv24)`
- `free (ca : ca_t, pointer_key : bv24)`

Any process in the system has access to the API and is assumed to be an adversary with the goal of gaining information not intended for the given PID. The adversary(ies) can execute a string of n function calls as described in the control block `f = bmc(n)`. 

Concreate or symbolic values stored by `write_byte` is not actually stored and recovered. `write_byte` with data key `d` and pointer key `p`  populates a bookkeeping datastructure to a byte allocation so that when we call `read_byte` with data key `d` and pointer key `p`, we "gain information". Using an incorrect data/pointer key pair will result in no information gain.

This scheme allows us to abstract out the cryptographic units to model a "perfect encryption".

### Important Disclaimers
- This model abstracts out the microarchitectural details of a general CPU. We therefore don't provide any safety evaluations of speculative execution. Extraneous processes, users, kernel details, etc. are also left out of the model's safety evaluation.

- Pointers (addresses) in this model does not go over `0xFFFF800000000000`. This constraint is applied on `line 90` to prevent the CA from overflowing as this model fails in that case.
