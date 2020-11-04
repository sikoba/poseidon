# Poseidon hash

Poseidon is a zero-knowledge friendly hash, defined in the following [research paper](https://eprint.iacr.org/2019/458.pdf).

We propose here a [crystal](https://crystal-lang.org/) implementation based on the [reference implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/poseidonperm_x5_254_5.sage). We also includes the sponge construction so that arbitrary input length hash can be computed.

## Usage
Instantiate the class *Poseidon* with a prime number and the number of desired bits of security. Optionally one can specify the sponge *capacity* and the *width* of the permutation (in number of field elements).
The hashing function requires a *PoseidonParameters* object, which can be retrieved by calling the *auto_parameters* function.
Parameters can be fully customized by initialising a *PoseidonParams* object and calling the *set_params* function. In that case, one must also set the round constants that can either be provided with the *set_round_constants* function or auto-generated. If the round constants are generated, you must call *init_generator()* before computing the hash.

Please note that the mds matrix is **not** generated, it is hardcoded for only a few values of field size and permutation width. In case of, one can set it with the *set_mds_matrix* function.

You can also refer to the examples in spec.

