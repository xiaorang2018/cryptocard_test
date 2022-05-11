#ifndef __BASIC_ALG__SM2_H_
#define __BASIC_ALG__SM2_H_

#include <stdint.h>
/* Optimization settings. Define as 1 to enable an optimization, 0 to disable it.
ECC_SQUARE_FUNC - If enabled, this will cause a specific function to be used for (scalar) squaring instead of the generic
                  multiplication function. Improves speed by about 8% .
*/
#define ECC_SQUARE_FUNC 1

/* Currently only support 256-bit SM2 */
#define NUM_ECC_DIGITS 32

typedef struct EccPoint
{
    uint8_t x[NUM_ECC_DIGITS];
    uint8_t y[NUM_ECC_DIGITS];
} EccPoint;

typedef struct EccSig
{
    uint8_t r[NUM_ECC_DIGITS];
    uint8_t s[NUM_ECC_DIGITS];
} EccSig;


/*ecc算法*/
void ecc_mod_add(uint8_t *result,uint8_t *k1,uint8_t *k2);
void ecc_mod_sub(uint8_t *result,uint8_t *k1,uint8_t *k2);
void ecc_mod_mult(uint8_t *result,uint8_t *k1,uint8_t *k2);
void ecc_mod_inv(uint8_t *result,uint8_t *k);
void ecc_k_mult_G(uint8_t *in_k,EccPoint *point);
void ecc_point_add(EccPoint *pointout, EccPoint *pointp1, EccPoint *pointp2);
int sm2_softeware_sign(uint8_t *r, uint8_t *s, uint8_t *p_privateKey,
    uint8_t *p_random, uint8_t *p_hash);
int sm2_softeware_verify(EccPoint *p_publicKey, uint8_t *p_hash, uint8_t *r, uint8_t *s);
int sm2_software_encrypt(uint8_t *cipher_text, uint16_t *cipher_len, 
                                EccPoint *p_publicKey, uint8_t *p_random, 
                                uint8_t *plain_text, unsigned int plain_len);


#endif 
