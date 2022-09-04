/*
 *  Declarations for "Blowfish" cipher algorithm
 *  (Based on Bruce Schneier's implementation at http://www.schneier.com
 *  subsequently edited by RW Penney for "cryptmount")
 */

/*
    This file is part of cryptmount
 */

#include <inttypes.h>


typedef struct cm_bf_ctxt {
    uint32_t p[18];
    uint32_t sbox[4][256];
} cm_bf_ctxt_t;


cm_bf_ctxt_t *cm_bf_init(uint8_t *key, size_t keybytes);
void cm_bf_encipher(const cm_bf_ctxt_t *ctxt, uint32_t *xl, uint32_t *xr);
void cm_bf_decipher(const cm_bf_ctxt_t *ctxt, uint32_t *xl, uint32_t *xr);
void cm_bf_free(cm_bf_ctxt_t *ctxt);
