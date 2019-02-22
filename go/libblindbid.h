/* libblindbid Header Version 0.1.0 */

#include <stdlib.h>

void prover(const unsigned char *d_ptr,
            const uint8_t *k_ptr,
            const uint8_t *y_ptr,
            const uint8_t *y_inv_ptr,
            const uint8_t *q_ptr,
            const uint8_t *z_img_ptr,
            const uint8_t *seed_ptr,
            const uint8_t *pub_list_ptr,
            size_t pub_list_len);
