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

static EC_POINT* hash_to_point(EC_GROUP *g, const unsigned char *buf, size_t len)
{
	return EC_POINT_new(g); // TODO
}

static BIGNUM* hash_to_scalar(const unsigned char *buf, size_t len)
{
	return BN_new(); // TODO
}

size_t
EVP_VRFProve(EVP_PKEY *key, EVP_MD *md, const unsigned char *input, size_t len, unsigned char **hash, unsigned char **proof)
{
	size_t ret = 0;
	DH *dh_keypair = EVP_PKEY_get1_DH(key);
	if(dh_keypair)
	{
		BN_CTX *bnctx = BN_CTX_new();
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
	
			BN_clear_free(gx);			
			BN_clear_free(hx);			
			BN_clear_free(gk);			
			BN_clear_free(hx);			
		}
		unsigned char *hi;
		size_t hi_len = bufcat(&hi, 6, gbuf, hbuf, gxbuf, hxbuf, gkbuf, hkbuf);
		EVP_DigestUpdate(md_ctx, hi, hi_len);
		unsigned char *chash = OPENSSL_malloc(EVP_MD_size(md));
		unsigned int clen;
		EVP_DigestFinal_ex(md_ctx, chash, &clen);
		BIGNUM *c = BN_bin2bn(chash, clen, 0);
		BIGNUM *s = BN_new();

		BIGNUM *cx = BN_new();
		BN_mul(cx, c, privkey, bnctx);
		BN_sub(s, k, cx);
		
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
		
		*proof = OPENSSL_malloc(BN_num_bytes(gamma) + BN_num_bytes(c) + BN_num_bytes(s));
		memcpy(*proof, gammabuf, BN_num_bytes(gamma));
		memcpy(*proof+BN_num_bytes(gamma), cbuf, BN_num_bytes(c));
		memcpy(*proof+BN_num_bytes(gamma)+BN_num_bytes(c), sbuf, BN_num_bytes(s));
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
	return ret;
}

size_t
EVP_VRFVerify(const EVP_PKEY *pkey, EVP_MD *md, const unsigned char *hash, const unsigned char *proof)
{
	return 1;
}
