#if !defined(MBEDTLS_CTR_DRBG_HPP)
#define MBEDTLS_CTR_DRBG_HPP

#include <mbedtls/ctr_drbg.h>

namespace mbedtls_cpp {

class ctr_drbg_context {
public:
    mbedtls_ctr_drbg_context* impl() { return &impl_; }
    mbedtls_ctr_drbg_context const* impl() const { return &impl_; }

    ctr_drbg_context() {
        mbedtls_ctr_drbg_init(&impl_);
    }
    ~ctr_drbg_context() {
        mbedtls_ctr_drbg_free(&impl_);
    }

    int seed(
        int (*f_entropy)(void*, unsigned char*, size_t),
        void* p_entropy,
        unsigned char const* custom,
        size_t len) {
        return mbedtls_ctr_drbg_seed(&impl_, f_entropy, p_entropy, custom, len);
    }

    void set_prediction_resistance(int resistance) {
        mbedtls_ctr_drbg_set_prediction_resistance(&impl_, resistance);
    }

    void set_entropy_len(size_t len) {
        mbedtls_ctr_drbg_set_entropy_len(&impl_, len);
    }

    void set_reseed_interval(int interval) {
        mbedtls_ctr_drbg_set_reseed_interval(&impl_, interval);
    }

    int reseed(unsigned char const* additional, size_t len) {
        return mbedtls_ctr_drbg_reseed(&impl_, additional, len);
    }

    void update(unsigned char const* additional, size_t add_len) {
        mbedtls_ctr_drbg_update(&impl_, additional, add_len);
    }

    int random_with_add(
        unsigned char* output,
        size_t output_len,
        unsigned char const* additional,
        size_t add_len) {
        return mbedtls_ctr_drbg_random_with_add(&impl_, output, output_len, additional, add_len);
    }

    static int random(void* p_rng, unsigned char* output, size_t output_len) {
        return mbedtls_ctr_drbg_random(p_rng, output, output_len);
    }

 #if defined(MBEDTLS_FS_IO)
    int write_seed_file(char const* path) {
        return mbedtls_ctr_drbg_write_seed_file(&impl_, path);
    }

    int update_seed_file(char const* path) {
        return mbedtls_ctr_drbg_update_seed_file(&impl_, path);
    }
 #endif /* MBEDTLS_FS_IO */

    static int self_test(int verbose) {
        return mbedtls_ctr_drbg_self_test(verbose);
    }

private:
    mbedtls_ctr_drbg_context impl_;
};

} // namespace cpp

#endif // MBEDTLS_CTR_DRBG_HPP
