module argon2;

/**
 * Ported from Argon2 reference implementation, copyright below:
 *
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

extern (C):

enum : uint
{
	/// Minimum number of lanes (degree of parallelism)
	ARGON2_MIN_LANES = 1,
	/// Maximum number of lanes (degree of parallelism)
	ARGON2_MAX_LANES = 0xFFFFFF
}

enum : uint
{
	/// Minimum number of threads
	ARGON2_MIN_THREADS = 1,
	/// Maximum number of threads
	ARGON2_MAX_THREADS = 0xFFFFFF
}

/// Number of synchronization points between lanes per pass
enum uint ARGON2_SYNC_POINTS = 4;

enum : uint
{
	/// Minimum digest size in bytes
	ARGON2_MIN_OUTLEN = 4,
	/// Maximum digest size in bytes
	ARGON2_MAX_OUTLEN = 0xFFFFFFFF
}

// dfmt off
import core.stdc.limits : CHAR_BIT;
private T ARGON2_MIN(T)(T a, T b) { return a < b ? a : b; }
enum : uint
{
	/// Minimum number of memory blocks (each of BLOCK_SIZE bytes)
	ARGON2_MIN_MEMORY = 2 * ARGON2_SYNC_POINTS, /* 2 blocks per slice */

	/// Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB)
	ARGON2_MAX_MEMORY_BITS = ARGON2_MIN(32u, (void*).sizeof * CHAR_BIT - 10 - 1),
	/// Maximum number of memory blocks (each of BLOCK_SIZE bytes)
	ARGON2_MAX_MEMORY = ARGON2_MIN(0xFFFFFFFFu, 1uL << ARGON2_MAX_MEMORY_BITS),
}
// dfmt on

enum : uint
{
	/// Minimum number of passes
	ARGON2_MIN_TIME = 1,
	/// Maximum number of passes
	ARGON2_MAX_TIME = 0xFFFFFFFF
}

enum : uint
{
	/// Minimum password length in bytes
	ARGON2_MIN_PWD_LENGTH = 0,
	/// Maximum password length in bytes
	ARGON2_MAX_PWD_LENGTH = 0xFFFFFFFF
}

enum : uint
{
	/// Minimum associated data length in bytes
	ARGON2_MIN_AD_LENGTH = 0,
	/// Maximum associated data length in bytes
	ARGON2_MAX_AD_LENGTH = 0xFFFFFFFF
}

enum : uint
{
	/// Minimum salt length in bytes
	ARGON2_MIN_SALT_LENGTH = 8,
	/// Maximum salt length in bytes
	ARGON2_MAX_SALT_LENGTH = 0xFFFFFFFF
}

enum : uint
{
	/// Minimum key length in bytes
	ARGON2_MIN_SECRET = 0,
	/// Maximum key length in bytes
	ARGON2_MAX_SECRET = 0xFFFFFFFF
}

enum : uint
{
	/// Flags to determine which fields are securely wiped (default = no wipe).
	ARGON2_DEFAULT_FLAGS = 0,
	/// Securely wipe password
	ARGON2_FLAG_CLEAR_PASSWORD = 1 << 0,
	/// Securely wipe secret
	ARGON2_FLAG_CLEAR_SECRET = 1 << 1
}

/**
* Global flag to determine if we are wiping internal memory buffers.
* This flag is defined in core.c and defaults to 1 (wipe internal memory).
*/
extern int FLAG_clear_internal_memory; // @suppress(dscanner.style.phobos_naming_convention)

/** Error codes */
enum Argon2_ErrorCodes
{
	ARGON2_OK = 0,

	ARGON2_OUTPUT_PTR_NULL = -1,

	ARGON2_OUTPUT_TOO_SHORT = -2,
	ARGON2_OUTPUT_TOO_LONG = -3,

	ARGON2_PWD_TOO_SHORT = -4,
	ARGON2_PWD_TOO_LONG = -5,

	ARGON2_SALT_TOO_SHORT = -6,
	ARGON2_SALT_TOO_LONG = -7,

	ARGON2_AD_TOO_SHORT = -8,
	ARGON2_AD_TOO_LONG = -9,

	ARGON2_SECRET_TOO_SHORT = -10,
	ARGON2_SECRET_TOO_LONG = -11,

	ARGON2_TIME_TOO_SMALL = -12,
	ARGON2_TIME_TOO_LARGE = -13,

	ARGON2_MEMORY_TOO_LITTLE = -14,
	ARGON2_MEMORY_TOO_MUCH = -15,

	ARGON2_LANES_TOO_FEW = -16,
	ARGON2_LANES_TOO_MANY = -17,

	ARGON2_PWD_PTR_MISMATCH = -18, /* NULL ptr with non-zero length */
	ARGON2_SALT_PTR_MISMATCH = -19, /* NULL ptr with non-zero length */
	ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
	ARGON2_AD_PTR_MISMATCH = -21, /* NULL ptr with non-zero length */

	ARGON2_MEMORY_ALLOCATION_ERROR = -22,

	ARGON2_FREE_MEMORY_CBK_NULL = -23,
	ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

	ARGON2_INCORRECT_PARAMETER = -25,
	ARGON2_INCORRECT_TYPE = -26,

	ARGON2_OUT_PTR_MISMATCH = -27,

	ARGON2_THREADS_TOO_FEW = -28,
	ARGON2_THREADS_TOO_MANY = -29,

	ARGON2_MISSING_ARGS = -30,

	ARGON2_ENCODING_FAIL = -31,

	ARGON2_DECODING_FAIL = -32,

	ARGON2_THREAD_FAIL = -33,

	ARGON2_DECODING_LENGTH_FAIL = -34,

	ARGON2_VERIFY_MISMATCH = -35
}

alias argon2_error_codes = Argon2_ErrorCodes;

// dfmt off
/** Memory allocator types --- for external allocation */
alias allocate_fptr = int(ubyte** memory, size_t bytes_to_allocate);
/** Memory allocator types --- for external deallocation */
alias deallocate_fptr = void(ubyte* memory, size_t bytes_to_allocate);
// dfmt on

/* Argon2 external data structures */

/++
#### Context:

structure to hold Argon2 inputs

- output array and its length,
- password and its length,
- salt and its length,
- secret and its length,
- associated data and its length,
- number of passes, amount of used memory (in KBytes, can be rounded up a bit)
- number of parallel threads that will be run

All the parameters above affect the output hash value.
Additionally, two function pointers can be provided to allocate and
deallocate the memory (if NULL, memory will be allocated internally).
Also, three flags indicate whether to erase password, secret as soon as they
are pre-hashed (and thus not needed anymore), and the entire memory

#### Default values

Optional settings are set to `null` / `0`, default version is latest, default
flags are selected.

#### Simplest situation:

you have output array out[8], password is stored in
pwd[32], salt is stored in salt[16], you do not have keys nor associated
data. You need to spend 1 GB of RAM and you run 5 passes of Argon2d with
4 parallel lanes. \
You want to use the default memory allocator. \
You want to erase the password an the internal memory. \
Then you initialize:
---
Argon2_Context(outArr, 8, // outArr, outlen
	pwd, 32,  // pwd, pwdlen
	salt, 16, // salt, saltlen
	NULL, 0,  // optional secret, secretlen
	NULL, 0,  // optional associated data, ad len
	5, 1<<20, 4, 4,    // t_cost, m_cost, lanes, threads
	ARGON2_VERSION_13, // version_
	NULL, NULL, // memory (de)allocation functions
	ARGON2_DEFAULT_FLAGS | ARGON2_FLAG_CLEAR_PASSWORD
); 
---
+/
struct Argon2_Context
{
	/// output array
	ubyte* outArr;
	/// digest length
	uint outlen;

	/// password array
	ubyte* pwd;
	/// password length
	uint pwdlen;

	/// salt array
	ubyte* salt;
	/// salt length
	uint saltlen;

	/// (optional) key array
	ubyte* secret = null;
	/// key length
	uint secretlen = 0;

	/// (optional) associated data array
	ubyte* ad = null;
	/// associated data length
	uint adlen = 0;

	/// number of passes
	uint t_cost;
	/// amount of memory requested (in KB, gets rounded up to KiB)
	uint m_cost;
	/++ Number of lanes, sometimes referred to as p (degree of parallelism).
	
	In functions with fewer params p may influence the number of threads too
	(better performance, thread count doesn't influence output).
	+/
	uint lanes;
	/// Maximum number of threads used, does not influence the output, only
	/// performance.
	uint threads = ARGON2_MIN_THREADS;

	/// version number (argon2_version)
	uint version_ = Argon2_version.ARGON2_VERSION_NUMBER;

	/// (optional) pointer to memory allocator
	allocate_fptr* allocate_cbk = null;
	/// (optional) pointer to memory deallocator
	deallocate_fptr* free_cbk = null;

	/// array of bool options
	uint flags = ARGON2_DEFAULT_FLAGS;
}
/// ditto
alias argon2_context = Argon2_Context;

/// Argon2 primitive type
enum Argon2_type
{
	Argon2_d = 0,
	Argon2_i = 1,
	Argon2_id = 2
}
/// ditto
alias argon2_type = Argon2_type;

/// Version of the algorithm
enum Argon2_version
{
	ARGON2_VERSION_10 = 0x10,
	ARGON2_VERSION_13 = 0x13,
	ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
}
/// ditto
alias argon2_version = Argon2_version;

/**
 * Function that gives the string representation of an `Argon2_type`.
 * Params:
 * type = The `Argon2_type` that we want the string for
 * uppercase = Whether the string should have the first letter uppercase
 * Returns:
 * `NULL` if invalid type, otherwise the string representation.
 */
const(char)* argon2_type2string(Argon2_type type, int uppercase);

/**
 * Function that performs memory-hard hashing with certain degree of parallelism
 * Params:
 * context = Pointer to the Argon2 internal structure
 * type = The `Argon2_type` that is used for hashing
 * Returns:
 * Error code if smth is wrong, `ARGON2_OK` otherwise
 */
int argon2_ctx(argon2_context* context, Argon2_type type);

/**
 * Hashes a password with Argon2i, producing an encoded hash at `encoded`
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different `parallelism`
 * 		levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hashlen = Desired length of the hash in bytes
 * encoded = Buffer where to write the encoded hash
 * encodedlen = Size of the buffer (thus max size of the encoded hash)
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2i_hash_encoded(const uint t_cost,
	const uint m_cost,
	const uint parallelism,
	const(ubyte)* pwd, const size_t pwdlen,
	const(ubyte)* salt, const size_t saltlen,
	const size_t hashlen, char* encoded,
	const size_t encodedlen);

/**
 * Hashes a password with Argon2i, producing a raw hash at `hash`
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different `parallelism`
 *       levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hash = Buffer where to write the raw hash - updated by the function
 * hashlen = Desired length of the hash in bytes
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2i_hash_raw(const uint t_cost, const uint m_cost,
	const uint parallelism, const(ubyte)* pwd,
	const size_t pwdlen, const(ubyte)* salt,
	const size_t saltlen, ubyte* hash,
	const size_t hashlen);

/**
 * Hashes a password with Argon2d, producing an encoded hash at `encoded`
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different parallelism
 *      levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hashlen = Desired length of the hash in bytes
 * encoded = Buffer where to write the encoded hash
 * encodedlen = Size of the buffer (thus max size of the encoded hash)
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2d_hash_encoded(const uint t_cost,
	const uint m_cost,
	const uint parallelism,
	const(ubyte)* pwd, const size_t pwdlen,
	const(ubyte)* salt, const size_t saltlen,
	const size_t hashlen, char* encoded,
	const size_t encodedlen);

/**
 * Hashes a password with Argon2d, producing a raw hash at `hash`
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different parallelism
 *       levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hash = Buffer where to write the raw hash - updated by the function
 * hashlen = Desired length of the hash in bytes
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2d_hash_raw(const uint t_cost, const uint m_cost,
	const uint parallelism, const(ubyte)* pwd,
	const size_t pwdlen, const(ubyte)* salt,
	const size_t saltlen, ubyte* hash,
	const size_t hashlen);

/**
 * Hashes a password with Argon2id, producing an encoded hash at `encoded`
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different parallelism
 *      levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hashlen = Desired length of the hash in bytes
 * encoded = Buffer where to write the encoded hash
 * encodedlen = Size of the buffer (thus max size of the encoded hash)
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2id_hash_encoded(const uint t_cost,
	const uint m_cost,
	const uint parallelism,
	const(ubyte)* pwd, const size_t pwdlen,
	const(ubyte)* salt, const size_t saltlen,
	const size_t hashlen, char* encoded,
	const size_t encodedlen);

/**
 * Hashes a password with Argon2id, producing a raw hash at `hash`
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different parallelism
 *       levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hash = Buffer where to write the raw hash - updated by the function
 * hashlen = Desired length of the hash in bytes
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2id_hash_raw(const uint t_cost,
	const uint m_cost,
	const uint parallelism, const(ubyte)* pwd,
	const size_t pwdlen, const(ubyte)* salt,
	const size_t saltlen, ubyte* hash,
	const size_t hashlen);

/**
 * Generic hash function that returns the raw hash at `hash` and the encoded
 * hash at `encoded`. The argon2{i,d,id} type is selected with `type`.
 * Params:
 * t_cost = Number of iterations
 * m_cost = Sets memory usage to `m_cost` kibibytes
 * parallelism = Number of threads and compute lanes, different parallelism
 *      levels will give different results
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * salt = Pointer to salt
 * saltlen = Salt size in bytes
 * hash = Buffer where to write the raw hash - updated by the function
 * hashlen = Desired length of the hash in bytes
 * encoded = Buffer where to write the encoded hash
 * encodedlen = Size of the buffer (thus max size of the encoded hash)
 * type = What argon2 type to hash with
 * version_ = What `argon2_version` to use
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2_hash(const uint t_cost, const uint m_cost,
	const uint parallelism, const(ubyte)* pwd,
	const size_t pwdlen, const(ubyte)* salt,
	const size_t saltlen, ubyte* hash,
	const size_t hashlen, char* encoded,
	const size_t encodedlen, Argon2_type type,
	const uint version_);

/**
 * Verifies a password against an encoded string
 * Encoded string is restricted as in `validate_inputs()`
 * Params:
 * encoded = String encoding parameters, salt, hash
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2i_verify(const(char)* encoded, const(ubyte)* pwd,
	const size_t pwdlen);

/**
 * Verifies a password against an encoded string
 * Encoded string is restricted as in `validate_inputs()`
 * Params:
 * encoded = String encoding parameters, salt, hash
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2d_verify(const char* encoded, const void* pwd,
	const size_t pwdlen);

/**
 * Verifies a password against an encoded string
 * Encoded string is restricted as in `validate_inputs()`
 * Params:
 * encoded = String encoding parameters, salt, hash
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2id_verify(const char* encoded, const void* pwd,
	const size_t pwdlen);

/**
 * Generic verify function to verify a password against an encoded string.
 * Type of argon2{i,d,id} is selected with `type`.
 * Encoded string is restricted as in `validate_inputs()`
 * Params:
 * encoded = String encoding parameters, salt, hash
 * pwd = Pointer to password
 * pwdlen = Password size in bytes
 * type = What argon2 type to hash with
 * Returns:
 * `ARGON2_OK` if successful
 */
int argon2_verify(const char* encoded, const void* pwd,
	const size_t pwdlen, Argon2_type type);

/**
 * Argon2d: Version of Argon2 that picks memory blocks depending
 * on the password and salt. $(B Only for side-channel-free environment!)
 * Params:
 * context = Pointer to current Argon2 context
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2d_ctx(argon2_context* context);

/**
 * Argon2i: Version of Argon2 that picks memory blocks
 * independent on the password and salt. Good for side-channels,
 * but worse w.r.t. tradeoff attacks if only one pass is used.
 * Params:
 * context = Pointer to current Argon2 context
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2i_ctx(argon2_context* context);

/**
 * Argon2id: Version of Argon2 where the first half-pass over memory is
 * password-independent, the rest are password-dependent (on the password and
 * salt). OK against side channels (they reduce to 1/2-pass Argon2i), and
 * better with w.r.t. tradeoff attacks (similar to Argon2d).
 * Params:
 * context = Pointer to current Argon2 context
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2id_ctx(argon2_context* context);

/**
 * Verify if a given password is correct for Argon2d hashing
 * Params:
 * context = Pointer to current Argon2 context
 * hash = The password hash to verify. The length of the hash is
 *        specified by the context outlen member
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2d_verify_ctx(argon2_context* context, const char* hash);

/**
 * Verify if a given password is correct for Argon2i hashing
 * Params:
 * context = Pointer to current Argon2 context
 * hash = The password hash to verify. The length of the hash is
 *        specified by the context outlen member
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2i_verify_ctx(argon2_context* context, const char* hash);

/**
 * Verify if a given password is correct for Argon2id hashing
 * Params:
 * context = Pointer to current Argon2 context
 * hash = The password hash to verify. The length of the hash is
 *        specified by the context outlen member
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2id_verify_ctx(argon2_context* context, const char* hash);

/**
 * Generic verify function to verify if a given password is correct.
 * Type of argon2{i,d,id} is selected with `type`.
 * Params:
 * context = Pointer to current Argon2 context
 * hash = The password hash to verify. The length of the hash is
 *        specified by the context outlen member
 * type = What argon2 type to hash with
 * specified by the context outlen member
 * Returns:
 * Zero if successful, a non zero error code otherwise
 */
int argon2_verify_ctx(argon2_context* context, const char* hash,
	Argon2_type type);

/**
 * Get the associated error message for given error code
 * Params:
 * error_code = The argon2_error_codes value
 * Returns:
 * The error message associated with the given error code
 */
const(char)* argon2_error_message(int error_code);

/**
 * Returns the encoded hash length for the given input parameters
 * Params:
 * t_cost =  Number of iterations
 * m_cost =  Memory usage in kibibytes
 * parallelism =  Number of threads; used to compute lanes
 * saltlen =  Salt size in bytes
 * hashlen =  Hash size in bytes
 * type = The Argon2_type that we want the encoded length for
 * Returns:
 * The encoded hash length in bytes
 */
size_t argon2_encodedlen(uint t_cost, uint m_cost,
	uint parallelism, uint saltlen,
	uint hashlen, Argon2_type type);
