#if !defined(MBEDTLS_ENTROPY_HPP)
#define MBEDTLS_ENTROPY_HPP

#include <mbedtls/entropy.h>

namespace mbedtls_cpp {

class entropy_context {
public:
    mbedtls_entropy_context* impl() { return &impl_; }
    mbedtls_entropy_context const* impl() const { return &impl_; }

    entropy_context() {
        mbedtls_entropy_init(&impl_);
    }
    ~entropy_context() {
        mbedtls_entropy_free(&impl_);
    }

    int add_source(
        mbedtls_entropy_f_source_ptr f_source,
        void* p_source,
        size_t threshold,
        int strong) {
        return mbedtls_entropy_add_source(&impl_, f_source, p_source, threshold, strong);
    }

    int gather() {
        return mbedtls_entropy_gather(&impl_);
    }

    static int func(void* data, unsigned char* output, size_t len) {
        return mbedtls_entropy_func(data, output, len);
    }

    int update_manual(unsigned char const* data, size_t len) {
        return mbedtls_entropy_update_manual(&impl_, data, len);
    }

#if defined(MBEDTLS_ENTROPY_NV_SEED)
    int update_nv_seed() {
        return mbedtls_entropy_update_nv_seed(&impl_);
    }
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#if defined(MBEDTLS_FS_IO)
    int write_seed_file(char const* path) {
        return mbedtls_entropy_write_seed_file(&impl_, path);
    }

    int update_seed_file(char const* path) {
        return mbedtls_entropy_update_seed_file(&impl_, path);
    }
 #endif /* MBEDTLS_FS_IO */

 #if defined(MBEDTLS_SELF_TEST)
    static int self_test(int verbose) {
        return mbedtls_entropy_self_test(verbose);
    }

 #if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
    static int source_self_test(int verbose) {
        return mbedtls_entropy_source_self_test(verbose);
    }
 #endif /* MBEDTLS_ENTROPY_HARDWARE_ALT */
 #endif /* MBEDTLS_SELF_TEST */

private:
    mbedtls_entropy_context impl_;
};

} // namespace cpp

#endif // MBEDTLS_ENTROPY_HPP
