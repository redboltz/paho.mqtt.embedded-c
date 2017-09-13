#if !defined(MBEDTLS_X509_CRL_HPP)
#define MBEDTLS_X509_CRL_HPP

#include <mbedtls/x509_crl.h>

namespace mbedtls_cpp {

class x509_crl {
public:
    mbedtls_x509_crl* impl() { return &impl_; }
    mbedtls_x509_crl const* impl() const { return &impl_; }

    x509_crl() {
        mbedtls_x509_crl_init(&impl_);
    }
    ~x509_crl() {
        mbedtls_x509_crl_free(&impl_);
    }

    int parse_der(unsigned char const *buf, size_t buflen) {
        return mbedtls_x509_crl_parse_der(&impl_, buf, buflen);
    }

    int parse(unsigned char const *buf, size_t buflen) {
        return mbedtls_x509_crl_parse(&impl_, buf, buflen);
    }

#if defined(MBEDTLS_FS_IO)
    int parse_file(char const* path) {
        return mbedtls_x509_crl_parse_file(&impl_, path);
    }
#endif /* MBEDTLS_FS_IO */

    int info(char *buf, size_t size, char const* prefix) const {
        return mbedtls_x509_crl_info(buf, size, prefix, &impl_);
    }

private:
    mbedtls_x509_crl impl_;
};

} // namespace cpp

#endif // MBEDTLS_X509_CRL_HPP
