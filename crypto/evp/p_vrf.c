/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

static int legendre(BIGNUM *a, BIGNUM *p)
{
	BIGNUM *t[3];
	int i;
	for(i=0; i<3; i++) t[i] = BN_new();
	BN_set_word(t[1], 2);
	BN_sub(t[0], p, BN_value_one());
	BN_div(t[2], 0, t[0], t[1], 0);
	BIGNUM *r = BN_new();
	BN_mod_exp(r, a, t[2], p, 0);
	
	for(i=0; i<3; i++) BN_free(t[i]);

	if(BN_is_zero(r)) return 0;
	if(BN_is_one(r)) return 1;
	return -1;
}

static BIGNUM *substitute_right(const EC_GROUP *g, BIGNUM *x)
{
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *p = BN_new();
	EC_GROUP_get_curve_GFp(g, p, a, b, 0);

	BIGNUM *t[4];

	int i;
	for(i=0; i<4; i++) t[i] = BN_new();
	BN_set_word(t[0], 3);
	BN_mod_exp(t[1], x, t[0], p, 0);
	BN_mod_mul(t[2], x, a, p, 0);
	BN_mod_add(t[3], t[1], t[2], p, 0);

	BIGNUM *ret = BN_new();
	BN_mod_add(ret, t[3], b, p, 0);
	
	for(i=0; i<4; i++) BN_free(t[i]);
	return ret;
}

BIGNUM *hash_to_scalar(const unsigned char *data, size_t len)
{
	BIGNUM *ret = BN_new();
	unsigned char *norm = OPENSSL_malloc(32);
	if (len<32)
	{
		memcpy(norm, data, len);
		int i;
		for(i=len; i<32; i++)
		{
			norm[i] = 0x00;
		}
	}
	else
	{
		memcpy(norm, data, 32);
	}
	BN_bin2bn(norm, 32, ret);
	OPENSSL_free(norm);
	return ret;
}

EC_POINT *hash_to_point(const EC_GROUP *g, const unsigned char *data, size_t len)
{
	unsigned char is_on_curve = 0;
	
	EC_POINT *r = EC_POINT_new(g);
	BIGNUM *p = BN_new();
	EC_GROUP_get_curve_GFp(g, p, 0, 0, 0);
	unsigned int c = 1;
	unsigned char *hash_in = OPENSSL_malloc(len + sizeof(unsigned int));
	unsigned char *hash_out = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
	memcpy(hash_in, data, len);
	SHA256_CTX *sha_ctx = OPENSSL_malloc(sizeof(SHA256_CTX));
	BIGNUM *x;
	BIGNUM *sub;
	while(!is_on_curve)
	{
		memcpy(hash_in+len, &c, sizeof(unsigned int));
		SHA256_Init(sha_ctx);
		SHA256_Update(sha_ctx, hash_in, len+sizeof(unsigned int));
		SHA256_Final(hash_out, sha_ctx);
		x = hash_to_scalar(hash_out, SHA256_DIGEST_LENGTH);
		sub = substitute_right(g,x);
		is_on_curve = legendre(sub, p) == 1;
		c++;
	}
	BIGNUM *y = BN_new();
	BN_mod_sqr(y, x, p, 0);
	
	EC_POINT_set_affine_coordinates_GFp(g, r, x, y, 0);
	if(!EC_POINT_is_on_curve(g, r, 0))
	{
		fprintf(stderr, "%s:%d:Curve hash arithmetic error occured\n", __FILE__, __LINE__);
		return 0;
	}
	return r;

}


static inline size_t bufcat(unsigned char **ret, int count, ...)
{
	size_t tsize = 0;
	unsigned char *t;
	
	va_list ap;
	va_start(ap, count);
	int i;
	for(i=0; i<count; i++)
	{
		unsigned char *curr_buf = va_arg(ap, unsigned char*);
		size_t curr_len = va_arg(ap, size_t);
		t = realloc(*ret, tsize+curr_len);
		if(!t) return 0;
		*ret = t;
	
		memcpy(*ret+tsize, curr_buf, curr_len);
		tsize+=curr_len;
	}
	return tsize;
}

size_t
EVP_VRFProve(EVP_PKEY *key, EVP_MD *md, const unsigned char *input, size_t len, unsigned char **hash, unsigned char **proof)
{
	size_t ret = 0;
	DH *dh_keypair = EVP_PKEY_get1_DH(key);
	EC_KEY *ec_keypair = EVP_PKEY_get1_EC_KEY(key);
	BN_CTX *bnctx = BN_CTX_new();
	if(dh_keypair)
	{
		const BIGNUM *privkey = BN_new();
		const BIGNUM *pubkey = BN_new();
		DH_get0_key(dh_keypair, &pubkey, &privkey);
		BIGNUM *h = hash_to_scalar(input, len);
		BIGNUM *gamma = BN_new();
		BN_exp(gamma, h, privkey, bnctx);
		BN_free(h); h=0;
		const BIGNUM *p = BN_new();
		const BIGNUM *q = BN_new();
		const BIGNUM *g = BN_new();
		DH_get0_pqg(dh_keypair, &p, &q, &g);
		BIGNUM *k = BN_new();
		BN_rand_range(k, p);
		EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
		EVP_DigestInit_ex(md_ctx, md, 0);
		unsigned char *gbuf;
		unsigned char *hbuf;
		unsigned char *gxbuf;
		unsigned char *hxbuf;
		unsigned char *gkbuf;
		unsigned char *hkbuf;
		unsigned char *hi;
		size_t hi_len;
		{
			BIGNUM *gx = BN_new();
			BIGNUM *hx = BN_new();
			BIGNUM *gk = BN_new();
			BIGNUM *hk = BN_new();

			BN_mul(gx, g, privkey, bnctx);
			BN_mul(hx, g, privkey, bnctx);
			BN_mul(gk, g, k, bnctx);
			BN_mul(hk, g, k, bnctx);

			gbuf = OPENSSL_malloc(BN_num_bytes(g));
			hbuf = OPENSSL_malloc(BN_num_bytes(h));
			gxbuf = OPENSSL_malloc(BN_num_bytes(gx));
			hxbuf = OPENSSL_malloc(BN_num_bytes(hx));
			gkbuf = OPENSSL_malloc(BN_num_bytes(gk));
			hkbuf = OPENSSL_malloc(BN_num_bytes(hk));
			
			BN_bn2bin(g, gbuf);			
			BN_bn2bin(h, hbuf);			
			BN_bn2bin(gx, gxbuf);			
			BN_bn2bin(hx, hxbuf);			
			BN_bn2bin(gk, gkbuf);			
			BN_bn2bin(hk, hkbuf);
	
		 	hi_len = bufcat(&hi, 6, gbuf, BN_num_bytes(g),
									hbuf, BN_num_bytes(h),
									gxbuf, BN_num_bytes(gx),
								    hxbuf, BN_num_bytes(hx),
									gkbuf, BN_num_bytes(gk),
									hkbuf, BN_num_bytes(hk));
			BN_clear_free(gx);			
			BN_clear_free(hx);			
			BN_clear_free(gk);			
			BN_clear_free(hx);			
		}
		EVP_DigestUpdate(md_ctx, hi, hi_len);
		unsigned char *chash = OPENSSL_malloc(EVP_MD_size(md));
		unsigned int clen;
		EVP_DigestFinal_ex(md_ctx, chash, &clen);
		BIGNUM *c = BN_bin2bn(chash, clen, 0);
		BIGNUM *s = BN_new();

		BIGNUM *cx = BN_new();
		BN_mul(cx, c, privkey, bnctx);
		BN_sub(s, k, cx);
		BN_mod(s, s, p, bnctx);
		unsigned char *gammabuf = OPENSSL_malloc(BN_num_bytes(gamma));
		unsigned char *cbuf = OPENSSL_malloc(BN_num_bytes(c));
		unsigned char *sbuf = OPENSSL_malloc(BN_num_bytes(s));
		
		BN_bn2bin(gamma, gammabuf);
		BN_bn2bin(c, cbuf);
		BN_bn2bin(s, sbuf);
		
		BN_bn2bin(gamma, *hash);
		if(BN_num_bytes(gamma) < 256)
		{
			fprintf(stderr, "parameter lengths are not large enough for 128bit security!\n");
			goto err_paramlen;
		}
		*hash = OPENSSL_realloc(gammabuf, 256);
		
		*proof = OPENSSL_malloc(BN_num_bytes(gamma) + BN_num_bytes(c) + BN_num_bytes(s) + 3*(sizeof(int)));
		int nb = BN_num_bytes(gamma);
		memcpy(*proof, &nb, sizeof(int));
		memcpy(*proof+sizeof(int), gammabuf, nb);
	
		nb = BN_num_bytes(c);
		memcpy(*proof+BN_num_bytes(gamma)+sizeof(int), &nb, sizeof(int));
		memcpy(*proof+BN_num_bytes(gamma)+sizeof(int)*2, cbuf, nb);
	

		nb = BN_num_bytes(s);
		memcpy(*proof+BN_num_bytes(gamma)+BN_num_bytes(c)+sizeof(int)*2, &nb, sizeof(int));
		memcpy(*proof+BN_num_bytes(gamma)+BN_num_bytes(c)+sizeof(int)*3, sbuf, nb);

		ret = BN_num_bytes(gamma) + BN_num_bytes(s) + BN_num_bytes(c);
		
		// Cleanup DH
err_paramlen:
		OPENSSL_free(gammabuf);
		OPENSSL_free(sbuf);
		OPENSSL_free(cbuf);
		BN_clear_free(cx);
		BN_free(s);
		OPENSSL_free(chash);
		OPENSSL_free(hi);
		EVP_MD_CTX_free(md_ctx);
		BN_clear_free(k);
		BN_free(gamma);
		BN_CTX_free(bnctx);
	}
	else if(ec_keypair)
	{
		const EC_GROUP *curve = EC_KEY_get0_group(ec_keypair);
		const EC_POINT *g = EC_GROUP_get0_generator(curve);
		BIGNUM *p = BN_new();
		EC_GROUP_get_curve_GFp(curve, p, 0, 0, bnctx);		
		const BIGNUM *privkey = EC_KEY_get0_private_key(ec_keypair);
		const EC_POINT *pubkey = EC_KEY_get0_public_key(ec_keypair);
		EC_POINT *h = hash_to_point(curve, input, len);
		EC_POINT *gamma = EC_POINT_new(curve);
		
		EC_POINT_mul(curve, gamma, 0, g, privkey, bnctx);
		BIGNUM *k = BN_new();
		BN_rand_range(k, p);
		EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
		EVP_DigestInit_ex(md_ctx, md, 0);
		unsigned char *gbuf;
		unsigned char *hbuf;
		unsigned char *gxbuf;
		unsigned char *hxbuf; size_t hxbuf_len;
		unsigned char *gkbuf;
		unsigned char *hkbuf;
		unsigned char *hi;
		size_t hi_len;
		{
			EC_POINT *gk = EC_POINT_new(curve);
			EC_POINT *hk = EC_POINT_new(curve);

			EC_POINT_mul(curve, gk, 0, g, k, bnctx);
			EC_POINT_mul(curve, gk, 0, h, k, bnctx);

			size_t gbuf_len = EC_POINT_point2buf(curve, g, 
				POINT_CONVERSION_UNCOMPRESSED, &gbuf, bnctx);

			size_t hbuf_len = EC_POINT_point2buf(curve, h,
				POINT_CONVERSION_UNCOMPRESSED, &hbuf, bnctx);
			size_t gxbuf_len = EC_POINT_point2buf(curve, pubkey,
				POINT_CONVERSION_UNCOMPRESSED, &gxbuf, bnctx);
			hxbuf_len = EC_POINT_point2buf(curve, gamma,
				POINT_CONVERSION_UNCOMPRESSED, &hxbuf, bnctx);
			size_t gkbuf_len = EC_POINT_point2buf(curve, gk,
				POINT_CONVERSION_UNCOMPRESSED, &gkbuf, bnctx);
			size_t hkbuf_len = EC_POINT_point2buf(curve, hk,
				POINT_CONVERSION_UNCOMPRESSED, &hkbuf, bnctx);
	
		 	hi_len = bufcat(&hi, 6, gbuf, gbuf_len,
									hbuf, hbuf_len,
									gxbuf, gxbuf_len,
								    hxbuf, hxbuf_len,
									gkbuf, gkbuf_len,
									hkbuf, hkbuf_len);
			EC_POINT_clear_free(gk);
			EC_POINT_clear_free(hk);
			OPENSSL_free(gbuf);
			OPENSSL_free(hbuf);
			OPENSSL_free(gxbuf);
			OPENSSL_free(gkbuf);
			OPENSSL_free(hkbuf);
		}
		EVP_DigestUpdate(md_ctx, hi, hi_len);
		unsigned char *chash = OPENSSL_malloc(EVP_MD_size(md));
		unsigned int clen;
		EVP_DigestFinal_ex(md_ctx, chash, &clen);
		BIGNUM *c = BN_bin2bn(chash, clen, 0);
		BIGNUM *s = BN_new();

		BIGNUM *cx = BN_new();
		BN_mul(cx, c, privkey, bnctx);
		BN_sub(s, k, cx);
		BN_mod(s, s, p, 0);
		unsigned char *cbuf = OPENSSL_malloc(BN_num_bytes(c));
		unsigned char *sbuf = OPENSSL_malloc(BN_num_bytes(s));
		
		BN_bn2bin(c, cbuf);
		BN_bn2bin(s, sbuf);
		
		*hash = OPENSSL_realloc(hxbuf, 256);
		
		*proof = OPENSSL_malloc(hxbuf_len + BN_num_bytes(c) + BN_num_bytes(s) + 3*(sizeof(int)));
		int nb = (int)hxbuf_len;
		memcpy(*proof, &nb, sizeof(int));
		memcpy(*proof+sizeof(int), hxbuf, nb);
	
		nb = BN_num_bytes(c);
		memcpy(*proof+hxbuf_len+sizeof(int), &nb, sizeof(int));
		memcpy(*proof+hxbuf_len+sizeof(int)*2, cbuf, nb);
	

		nb = BN_num_bytes(s);
		memcpy(*proof+hxbuf_len+BN_num_bytes(c)+sizeof(int)*2, &nb, sizeof(int));
		memcpy(*proof+hxbuf_len+BN_num_bytes(c)+sizeof(int)*3, sbuf, nb);

		ret = hxbuf_len + BN_num_bytes(s) + BN_num_bytes(c);

		
		
		BN_clear_free(k);
		EC_POINT_free(gamma);
		EC_POINT_free(h);
		BN_free(p);
		return 0; // TODO
	}
	return ret;
}

int
EVP_VRFVerify(EVP_PKEY *pkey, EVP_MD *md, const unsigned char *input, size_t isize, const unsigned char *hash, size_t hsize, const unsigned char *proof)
{
	size_t ret = 1;
	DH *dh_keypair = EVP_PKEY_get1_DH(pkey);
	EC_KEY *ec_keypair = EVP_PKEY_get1_EC_KEY(pkey);
	BN_CTX *bnctx = BN_CTX_new();
	if(dh_keypair)
	{
		const BIGNUM *privkey = BN_new(); // will remain 0, not used
		const BIGNUM *pubkey = BN_new();
		DH_get0_key(dh_keypair, &pubkey, &privkey);
		BIGNUM *h = hash_to_scalar(input, isize);
		BIGNUM *gamma = BN_new();
		BN_exp(gamma, h, privkey, bnctx);
		BN_free(h); h=0;
		const BIGNUM *p = BN_new();
		const BIGNUM *q = BN_new();
		const BIGNUM *g = BN_new();
		DH_get0_pqg(dh_keypair, &p, &q, &g);
		EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
		EVP_DigestInit_ex(md_ctx, md, 0);
		unsigned char *gbuf;
		unsigned char *hbuf;
		unsigned char *gxbuf;
		unsigned char *hxbuf;
		unsigned char *gkbuf;
		unsigned char *hkbuf;
		unsigned char *c;
		size_t clen;
		unsigned char *s;
		size_t slen;
		unsigned char *hi;
		size_t hi_len;
		{
			gbuf = OPENSSL_malloc(BN_num_bytes(g));
			BN_bn2bin(g, gbuf);
			hbuf = OPENSSL_malloc(BN_num_bytes(h));
			BN_bn2bin(h, hbuf);
			gxbuf = OPENSSL_malloc(BN_num_bytes(pubkey));
			BN_bn2bin(pubkey, gxbuf);

			int curr_size = 0;
			memcpy(&curr_size, proof, sizeof(int));
			proof+=sizeof(int);
			if(curr_size<256) return 0;
			hxbuf = OPENSSL_malloc(curr_size);
			memcpy(hxbuf, proof, curr_size);
			unsigned char *beta = malloc(curr_size);
			memcpy(beta, hxbuf, curr_size);
			beta = realloc(beta, 256);
			if(memcmp(hash, beta, 256) != 0) return 0;
			BIGNUM *hx = BN_new();
			BN_bin2bn(hxbuf, curr_size, hx);
			proof+=sizeof(curr_size);
			memcpy(&curr_size, proof, sizeof(int));
			proof+=sizeof(int);
			clen = (size_t)((unsigned int)curr_size);
			memcpy(&c, proof, curr_size);
			proof+=curr_size;
			memcpy(&curr_size, proof, sizeof(int));
			proof+=sizeof(int);
			slen = (size_t)((unsigned int)curr_size);
			memcpy(&s, proof, curr_size);
			BIGNUM *cbn = BN_new();
			BIGNUM *sbn = BN_new();
			BN_bin2bn(c, clen, cbn);
			BN_bin2bn(s, slen, sbn);
			BIGNUM *t[2];
			t[0] = BN_new();
			t[1] = BN_new();

			BIGNUM *gk = BN_new();
			BN_mod_exp(t[0], pubkey, cbn, p, bnctx);
			BN_mod_exp(t[1], g, sbn, p, bnctx);
			BN_mod_mul(gk, t[0], t[1], p, bnctx);
			gkbuf = OPENSSL_malloc(BN_num_bytes(gk));
			BN_bn2bin(gk, gkbuf);
			
			BIGNUM *hk = BN_new();
			BN_mod_exp(t[0], hx, cbn, p, bnctx);
			BN_mod_exp(t[1], h, sbn, p, bnctx);
			BN_mod_mul(hk, t[0], t[1], p, bnctx);
			hkbuf = OPENSSL_malloc(BN_num_bytes(hk));
			BN_bn2bin(hk, hkbuf);			
		 	hi_len = bufcat(&hi, 6, gbuf, BN_num_bytes(g),
									hbuf, BN_num_bytes(h),
									gxbuf, BN_num_bytes(pubkey),
								    hxbuf, BN_num_bytes(hx),
									gkbuf, BN_num_bytes(gk),
									hkbuf, BN_num_bytes(hk));
			BN_clear_free(hx);
			BN_clear_free(gk);
			BN_clear_free(hx);
			BN_free(cbn);
			BN_free(sbn);
			OPENSSL_free(beta);
			OPENSSL_free(gbuf);
			OPENSSL_free(hbuf);
			OPENSSL_free(gxbuf);
			OPENSSL_free(hxbuf);
			OPENSSL_free(gkbuf);
			OPENSSL_free(hkbuf);
		}
		EVP_DigestUpdate(md_ctx, hi, hi_len);
		unsigned char *chash = OPENSSL_malloc(EVP_MD_size(md));
		unsigned int chashlen;
		EVP_DigestFinal_ex(md_ctx, chash, &chashlen);
		ret &= memcmp(chash, c, chashlen) == 0;
		
		
		// Cleanup DH
		OPENSSL_free(c);
		OPENSSL_free(s);
		OPENSSL_free(chash);
		OPENSSL_free(hi);
		EVP_MD_CTX_free(md_ctx);
		BN_free(gamma);
		BN_CTX_free(bnctx);
	}
	else if(ec_keypair)
	{
		return 0;
	}
	return ret;
}
