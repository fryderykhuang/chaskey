#include <stdlib.h>
// TODO
typedef unsigned char uint8_t;
typedef unsigned char uint_fast8_t;
typedef int int32_t;
typedef unsigned int uint32_t;
// typedef unsigned long long size_t;
#ifndef __cplusplus
#define nullptr 0
typedef int bool;
#define true 1
#define false 0
#endif

#ifdef __BYTE_ORDER__
#ifdef __ORDER_BIG_ENDIAN__
#define arch_traits_big_endian (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#endif
#endif
#ifndef arch_traits_big_endian
#define arch_traits_big_endian 0
#endif

#ifdef __xtensa__
	/* unaligned access to uint32_t causes system fault on esp8266			 */
#define	arch_traits_direct_safe 0;
#else
#define arch_traits_direct_safe !arch_traits_big_endian;
#endif

#if arch_traits_big_endian
uint32_t endian_byteswap(uint32_t val) { return bswap_32(val); }
#else
#define endian_index(N, val) (val)
uint32_t endian_byteswap(uint32_t val) { return val; }
#endif


#define MAKE_ROR_ROL(T) \
T ror(T val, uint_fast8_t N) { return (val << (sizeof(T)*8 - N)) | ((val) >> (N)); }; \
T rol(T x, uint_fast8_t N) { return (x >> (sizeof(T)*8 - N)) | ((x) << (N)); }



/**
 * Block of bits stored as of N elements of type T
 */
#define MAKE_BLOCK(T,N) \
typedef T block_t[N]; \
typedef T item_t; \
/*typedef uint8_t raw_t[sizeof(block_t)];*/ \
bool block_eq(block_t self, block_t val) { \
	int res = 1; \
	for (int i = N; i--; ) res &= self[i] == val[i]; \
	return res; \
} \
bool block_neq(block_t self, block_t val) { \
	int res = 0; \
	for (int i = N; i--; ) res |= self[i] != val[i]; \
	return res; \
} \
void block_xor_assign(block_t self, block_t val) { \
	for(int i = N; i--; ) self[i] ^= val[i]; \
} \
uint_fast8_t block_size(block_t self, block_t val) { \
	return sizeof(self); \
} \
void block_assign(block_t self, block_t val) { \
	for(int i = N; i--; ) self[i] = val[i]; \
}; \
uint8_t* block_raw(block_t self) { return (uint8_t*) self; } \
\
/* block_formatter */ \
typedef struct block_formatter { \
	union { \
		block_t w; \
		uint8_t b[sizeof(block_t)]; \
	} data; \
	uint_fast8_t pos; \
	block_t* raw; \
	uint_fast8_t size; \
} block_formatter_t; \
\
\
void block_formatter_base_append_msg(block_formatter_t* self, const uint8_t** msg, size_t* len) {\
	while (self->pos < sizeof(self->data.b) && *len) { \
		self->data.b[endian_index(sizeof(T), self->pos++)] = *(*msg)++; \
		--(*len); \
	} \
} \
size_t block_formatter_base_append_block(block_formatter_t* self, const block_t block) { \
	uint8_t* msg = (uint8_t*)block; \
	size_t len = sizeof(block_t); \
	block_formatter_base_append_msg(self, &msg, &len); \
	return sizeof(block_t) - len; \
} \
bool block_formatter_pad(block_formatter_t* self, uint8_t chr) { \
	bool padded = false; \
	while (self->pos < sizeof (self->data.b)) { \
		self->data.b[endian_index(sizeof(T), self->pos++)] = chr; \
		chr = 0; \
		padded = true; \
	} \
	return padded; \
} \
uint_fast8_t block_formatter_base_available(block_formatter_t* self) { \
 	return self->pos; \
} \
bool block_formatter_base_full(block_formatter_t* self) { \
 	return block_formatter_base_available(self) == sizeof(self->data.b); \
} \
void block_formatter_base_reset(block_formatter_t* self) { self->pos = 0; } \
T* block_formatter_base_block(block_formatter_t* self) { return self->data.w; } \
void block_formatter_final(block_t block) { \
	if (arch_traits_big_endian) { \
	/* // TODO
	for(int i T& p : block) p = endian<>::byteswap<T>(p); } */ \
	} \
} \
T* block_formatter_result(block_formatter_t* self, block_t block) { \
	if (arch_traits_big_endian) { \
		for (uint_fast8_t i = 0; i < N; ++i) \
			self->data.w[i] = endian_byteswap(block[i]); \
		return self->data.w; \
	} \
	return block; \
} \
void block_formatter_base_xor_bytes(uint8_t* state, const void* ptr, uint_fast8_t len) { \
	uint8_t* bytes = (uint8_t*) ptr; \
	uint_fast8_t i = 0; \
	while (len--) { \
		state[endian_index(4, i)] ^= bytes[endian_index(4, i)]; \
		++i; \
	} \
} \
void block_formatter_append(block_formatter_t* self, const uint8_t** msg, size_t* len) { \
	if (*len < sizeof(block_t) || block_formatter_base_available(self)) { \
		block_formatter_base_append_msg(self, msg, len); \
		self->raw = &self->data.w; \
		self->size = 0; \
	} else { \
		self->raw = (block_t*) msg; \
		(*msg) += sizeof(block_t); \
		(*len) -= sizeof(block_t); \
		self->size = sizeof(block_t); \
	} \
} \
T* block_formatter_block(block_formatter_t* self) { return *self->raw; } \
void block_formatter_reset(block_formatter_t* self) { \
	block_formatter_base_reset(self); \
	self->raw = &self->data.w; \
	self->size = 0; \
} \
uint_fast8_t block_formatter_available(block_formatter_t* self) { return self->size + block_formatter_base_available(self); } \
bool block_formatter_full(block_formatter_t* self) { return block_formatter_available(self) == sizeof(block_t); } \
void block_formatter_xor_bytes(uint8_t* state, const void* ptr, uint_fast8_t len) { \
	const uint8_t* bytes = (const uint8_t*) ptr; \
	while (len--)* state++ ^= *bytes++; \
} \


#define MAKE_CIPHER(NROUND) \
MAKE_ROR_ROL(uint32_t) \
MAKE_BLOCK(uint32_t, 4) \
/*typedef struct cipher_state{ \
	block_t v;\
} cipher_state_t; \*/ \
inline void cipher_round(block_t self) { \
	self[0] += self[1]; \
	self[1] = rol(self[1], 5); \
	self[1] ^= self[0]; \
	self[0] = rol(self[0], 16); \
	self[2] += self[3]; \
	self[3] = rol(self[3], 8); \
	self[3] ^= self[2]; \
	self[0] += self[3]; \
	self[3] = rol(self[3], 13); \
	self[3] ^= self[0]; \
	self[2] += self[1]; \
	self[1] = rol(self[1], 7); \
	self[1] ^= self[2]; \
	self[2] = rol(self[2], 16); \
} \
inline void cipher_dnour(block_t self) { \
	self[2]  = ror(self[2],16); \
	self[1] ^= self[2]; \
	self[1] = ror(self[1], 7); \
	self[2] -= self[1]; \
	self[3] ^= self[0]; \
	self[3] = ror(self[3], 13); \
	self[0] -= self[3]; \
	self[3] ^= self[2]; \
	self[3] = ror(self[3], 8); \
	self[2] -= self[3]; \
	self[0] = ror(self[0], 16); \
	self[1] ^= self[0]; \
	self[1] = ror(self[1], 5); \
	self[0] -= self[1]; \
} \
inline void cipher_init(block_t self, block_t key) { \
	block_assign(self, key); \
} \
/**
 * Chaskey transformation
 */ \
inline void cipher_permute(block_t self) { \
	for (int i=NROUND; i--; ) cipher_round(self); \
} \
/**
 * Chaskey reverse transformation
 */ \
inline void cipher_etumrep(block_t self) { \
	for (int i=NROUND; i--; ) cipher_dnour(self); \
} \
/** shifts entire block one bit left and distorts lowest byte  */  \
inline void cipher_derive(block_t v, const block_t in) { \
	item_t C = (int32_t)(in[3]) >> (32-1); \
	v[3] = (in[3] << 1) | (in[2] >> (32 - 1)); \
	v[2] = (in[2] << 1) | (in[1] >> (32 - 1)); \
	v[1] = (in[1] << 1) | (in[0] >> (32 - 1)); \
	v[0] = (in[0] << 1) ^ (C & 0x87); \
}

#define MAKE_CLOC(NROUND) \
MAKE_CIPHER(NROUND) \
typedef struct cloc_state { \
	block_t key; \
	block_formatter_t buff; \
	block_t enc;				/* encryption cipher state 						*/ \
	block_t tag;		/* tag processing cipher state 					*/ \
	bool g1g2guard;			/* true, if g1 or g2 has been applied			*/ \
	bool fix0guard;			/* true, if fix0 has been applied				*/ \
	bool nonceguard;		/* true, if nonce() has been called				*/ \
	bool ozp;				/* associated data were OZP padded				*/ \
	bool finalized;	/* tag has been reordered as little endian		*/ \
} cloc_state_t; \
void cloc_set(cloc_state_t* self, const block_t akey) { \
	block_assign(self->key, akey); \
} \
void cloc_init(cloc_state_t* self) { \
	block_assign(self->enc, self->key); \
	self->ozp = false; \
	self->finalized = false; \
	self->fix0guard = false; \
	self->g1g2guard = false; \
	self->nonceguard = false; \
	block_formatter_reset(&self->buff); \
} \
/* CLOC-specific tweak function, chapter 3, [157]						*/ \
/* Courtesy to Markku-Juhani O. Saarinen (mjosaarinen)					*/ \
/* https://github.com/mjosaarinen/brutus/tree/master/crypto_aead_round1/aes128n12clocv1/ref */ \
/** f1(X) = (X[1, 3],X[2, 4],X[1, 2, 3],X[2, 3, 4])						*/ \
inline void cloc_f1(block_t b) { \
	b[0] ^= b[2];			/* X[1, 3]									*/ \
	auto t = b[1]; \
	b[1] ^= b[3];			/* X[2, 4]									*/ \
	b[3] = b[2] ^ b[1];	/* X[2, 3, 4]								*/ \
	b[2] = b[0] ^ t;		/* X[1, 2, 3]								*/ \
} \
/** f2(X) = (X[2],X[3],X[4],X[1, 2])									*/ \
inline void cloc_f2(block_t b) { \
	auto t = b[0] ^ b[1]; \
	b[0] = b[1];			/* X[2]										*/ \
	b[1] = b[2];			/* X[2]										*/ \
	b[2] = b[3];			/* X[4]										*/ \
	b[3] = t;				/* X[1, 2]									*/ \
} \
/** g1(X) = (X[3],X[4],X[1, 2],X[2, 3])									*/ \
inline void cloc_g1(block_t b) { \
	auto t = b[0]; \
	b[0] = b[2];			/* X[3]										*/ \
	b[2] = b[1] ^ t;		/* X[1, 2]									*/ \
	t = b[1]; \
	b[1] = b[3];			/* X[4]										*/ \
	b[3] = b[0] ^ t;		/* X[2, 3]									*/ \
} \
/** g2(X) = (X[2],X[3],X[4],X[1, 2])									*/ \
void cloc_g2(block_t b) { cloc_f2(b); } \
/** h(X) = (X[1, 2],X[2, 3],X[3, 4],X[1, 2, 4]) 						*/ \
inline void cloc_h(block_t b) { \
	b[0] ^= b[1]; 			/* X[1, 2]									*/ \
	b[1] ^= b[2];			/* X[2, 3]									*/ \
	b[2] ^= b[3];			/* X[3, 4]									*/ \
	b[3] ^= b[0];			/* X[1, 2, 4]								*/ \
} \
inline bool cloc_fix0(block_t b) { \
	bool fixed = b[0] & ((item_t)(1)<<31); \
	b[0] &= ~((item_t)(1) << 31); \
	return fixed; \
} \
inline void cloc_fix1(block_t b) { \
	b[0] |= (item_t)(1)<<31; \
} \
inline void cloc_finalize(cloc_state_t* self) { \
	if (!self->finalized) { \
		block_formatter_final(self->tag); \
		self->finalized = true; \
	} \
} \
\
inline void cloc_update_block(cloc_state_t* self, const block_t input) { \
	block_xor_assign(self->enc, input); \
	cipher_permute(self->enc); \
	block_xor_assign(self->enc, self->key); \
} \
inline void cloc_cipher(cloc_state_t* self) { \
	cipher_permute(self->tag); \
	block_xor_assign(self->tag, self->key); \
} \
\
inline bool cloc_nodata(cloc_state_t* self, bool final) { \
	if (final) { \
		if (!self->g1g2guard && !block_formatter_available(&self->buff)) { \
			cloc_g1(self->tag); \
			cloc_cipher(self); \
		} else { \
			block_formatter_pad(&self->buff, 0); \
			return false; \
		} \
	} \
	return true; \
} \
\
inline void cloc_apply_g2(cloc_state_t* self) { \
	cloc_g2(self->tag); \
	cloc_cipher(self); \
	self->g1g2guard = true; \
} \
\
inline uint_fast8_t cloc_process(cloc_state_t* self, const uint8_t** msg, size_t* len, bool final) { \
	block_formatter_append(&self->buff, msg, len); \
	uint_fast8_t size = block_formatter_available(&self->buff); \
	if (!block_formatter_full(&self->buff) && cloc_nodata(self, final)) return 0; \
	if (!self->g1g2guard) { /* g2 guard */ \
		cloc_apply_g2(self); \
	} \
	if (size == sizeof(block_t)) \
		block_assign_xor(self->enc, self->buff.data.w);  /* enc contains a block of cipher text 		*/ \
	else \
		block_formatter_xor_bytes((uint8_t*)self->enc, (void*)self->buff.data.w, size); \
	return size; \
} \
\
inline void cloc_prf(cloc_state_t* self, bool decrypt, uint_fast8_t size) { \
	if (decrypt) block_assign(self->enc, self->buff.data.w); \
	if (size == sizeof(block_t)) \
		block_xor_assign(self->tag, self->enc); \
	else \
		block_formatter_xor_bytes((uint8_t*)self->tag, (void*)self->enc, size); \
	block_xor_assign(self->tag, self->key); \
	cloc_cipher(self); \
	if (size != sizeof(block_t)) return; \
	cloc_fix1(self->enc); \
	block_xor_assign(self->enc, self->key); \
	cipher_permute(self->enc); \
	block_xor_assign(self->enc, self->key); \
} \
\
/** Processes chunk of associated data msg of length len,
 *  final finishes generation by padding the message to the size of
 *  block and applying one of derived keys.
 *  Corresponds to the first part of HASH, see Fig 3 of [157]			*/ \
inline void cloc_update(cloc_state_t* self, const uint8_t* msg, size_t len, bool final) { \
	do { \
		block_formatter_append(&self->buff, &msg, &len); \
		if (!len) { \
			if (!block_formatter_full(&self->buff)) { \
				if (final) \
					self->ozp = block_formatter_pad(&self->buff, 0x80);		/* apply ozp 			*/ \
				else \
					return; \
			} \
		} \
		bool fixed0 = !self->fix0guard && cloc_fix0(self->enc); \
		cloc_update_block(self, self->buff.data.w); \
		self->fix0guard = true; \
		if (fixed0) cloc_h(self->enc); \
		block_formatter_reset(&self->buff); \
	} while (len); \
} \
\
/** Processes nonce monce of length len in one chunk
 *  Corresponds to the last part of HASH, see Fig 3 of [157]			*/ \
inline void cloc_nonce(cloc_state_t* self, const uint8_t* monce, size_t len) { \
	/* if buffer is not empty call update for final block				*/ \
	if (block_formatter_available(&self->buff)) \
		cloc_update(self, monce, 0, true); \
	if (monce) \
		block_formatter_append(&self->buff, &monce, &len); \
	block_formatter_pad(&self->buff, 0x80);								/* apply ozp 			*/ \
	block_xor_assign(self->enc, self->buff.data.w); \
	if (self->ozp) \
		cloc_f2(self->enc); \
	else \
		cloc_f1(self->enc); \
	block_assign(self->tag, self->enc); \
	cipher_permute(self->enc);		/* corresponds to V->EK on fig.4				*/ \
	block_xor_assign(self->enc, self->key); \
	block_formatter_reset(&self->buff); \
	self->nonceguard = true; \
} \
typedef struct stream { \
	uint8_t buffer[256-sizeof(int)]; \
	int pos; \
} stream_t; \
\
void stream_write(stream_t* stream, const char* buf, size_t size) {\
	\
} \
\
/**
 * Encrypts message msg of length len and writes it to the output stream
 * if final == true, the message is padded o the size of block
 */ \
inline void cloc_encrypt(cloc_state_t* self, stream_t* output, const uint8_t* msg, size_t len, bool final) {	\
	if (!self->nonceguard) cloc_nonce(self, nullptr, 0); \
	do { \
		uint_fast8_t size; \
		if (!(size = cloc_process(self, msg, len, final))) \
			return; \
		char* result = (char*) block_formatter_result(&self->buff, self->enc); \
		stream_write(output, (const char*)(result), size); \
		cloc_prf(self, false, size); \
		block_formatter_reset(&self->buff); \
	} while (len); \
} \
/**
 * Decrypts ciphertext msg of length len and writes it to the output stream
 * if final == true, the message is padded o the size of block
 */ \
inline void cloc_decrypt(cloc_state_t* self, stream_t* output, const uint8_t* msg, size_t len, bool final) { \
	block_formatter_t buf; \
	if (!self->nonceguard) cloc_nonce(self, nullptr, 0); \
	do { \
		uint_fast8_t size; \
		if (!(size = cloc_process(self, msg, len, final))) \
			return; \
		char* result = (char*)block_formatter_result(&buf, self->enc); \
		stream_write(output, (const char*)(result), size); \
		cloc_prf(self, true, size); \
		block_formatter_reset(&self->buff); \
	} while (len); \
} \
/**
 * writes computed MAC to output
 * if all 16 bytes are not needed, use a stream that trims
 */ \
inline void cloc_write(cloc_state_t* self, stream_t* output) { \
	cloc_finalize(self); \
	/* TODO check: original: Cipher::size() */ \
	stream_write(output, (const char*)(self->tag), sizeof(block_t)); \
} \
\
inline bool equals(const void* a, const void* b, uint_fast8_t len) { \
	const uint8_t* l = (const uint8_t*)(a); \
	const uint8_t* r = (const uint8_t*)(b); \
	uint8_t res = 0; \
	while (len--) res |= l[len] ^ r[len]; \
	return res == 0; \
} \
\
/**
 * verifies computed MAC against provided externally tag
 */ \
inline bool verify(cloc_state_t* self, const void* _tag, uint_fast8_t len /*= sizeof(block_t)*/) { \
	cloc_finalize(self); \
	return equals(self->tag, _tag, len < sizeof(block_t) ? len : sizeof(block_t)); \
} \


MAKE_CLOC(8)