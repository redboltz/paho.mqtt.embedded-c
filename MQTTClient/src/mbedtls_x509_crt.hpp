#if !defined(MBEDTLS_X509_CRT_HPP)
#define MBEDTLS_X509_CRT_HPP

#include <mbedtls/x509_crt.h>
#include "mbedtls_x509_crl.hpp"

namespace mbedtls_cpp {

class x509_crt {
public:
    mbedtls_x509_crt* impl() { return &impl_; }
    mbedtls_x509_crt const* impl() const { return &impl_; }

    x509_crt() {
        mbedtls_x509_crt_init(&impl_);
    }
    ~x509_crt() {
        mbedtls_x509_crt_free(&impl_);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    int parse_der(unsigned char const* buf, size_t buflen) {
        return mbedtls_x509_crt_parse_der(&impl_, buf, buflen);
    }
    int parse(unsigned char const* buf, size_t buflen) {
        return mbedtls_x509_crt_parse(&impl_, buf, buflen);
    }

#if defined(MBEDTLS_FS_IO)
    int parse_file(char const* path) {
        return mbedtls_x509_crt_parse_file(&impl_, path);
    }
    int parse_path(char const* path) {
        return mbedtls_x509_crt_parse_path(&impl_, path);
    }
#endif /* MBEDTLS_FS_IO */

    int info(char *buf, size_t size, char const* prefix) const {
        return mbedtls_x509_crt_info(buf, size, prefix, &impl_);
    }
    static int verify_info( char *buf, size_t size, char const* prefix, uint32_t flags) {
        return mbedtls_x509_crt_verify_info(buf, size, prefix, flags);
    }
    int verify(
        x509_crt& trust_ca,
        x509_crl& ca_crl,
        char const* cn,
        uint32_t* flags,
        int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*),
        void* p_vrfy) {
        return mbedtls_x509_crt_verify(&impl_, trust_ca.impl(), ca_crl.impl(), cn, flags, f_vrfy, p_vrfy);
    }
    int verify_with_profile(
        x509_crt& trust_ca,
        x509_crl& ca_crl,
        mbedtls_x509_crt_profile const* profile,
        char const* cn,
        uint32_t* flags,
        int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*),
        void* p_vrfy) {
        return mbedtls_x509_crt_verify_with_profile(&impl_, trust_ca.impl(), ca_crl.impl(), profile, cn, flags, f_vrfy, p_vrfy);
    }

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
    int check_key_usage(unsigned int usage) const {
        return mbedtls_x509_crt_check_key_usage(&impl_, usage);
    }
#endif /* MBEDTLS_X509_CHECK_KEY_USAGE) */

#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
    int check_extended_key_usage(char const* usage_oid, size_t usage_len) const {
        return mbedtls_x509_crt_check_extended_key_usage(&impl_, usage_oid, usage_len);
    }
#endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE) */

#if defined(MBEDTLS_X509_CRL_PARSE_C)
    int is_revoked(x509_crl const& crl) const {
        return mbedtls_x509_crt_is_revoked(&impl_, crl.impl());
    }
#endif /* MBEDTLS_X509_CRL_PARSE_C */

#endif /* MBEDTLS_X509_CRT_PARSE_C */

private:
    mbedtls_x509_crt impl_;
};

class x509write_cert {
public:
    mbedtls_x509write_cert* impl() { return &impl_; }
    mbedtls_x509write_cert const* impl() const { return &impl_; }

    x509write_cert() {
        mbedtls_x509write_crt_init(&impl_);
    }
    ~x509write_cert() {
        mbedtls_x509write_crt_free(&impl_);
    }

#if defined(MBEDTLS_X509_CRT_WRITE_C)
    void set_version(int version) {
        mbedtls_x509write_crt_set_version(&impl_, version);
    }

    int set_serial(mbedtls_mpi const* serial) {
        return mbedtls_x509write_crt_set_serial(&impl_, serial);
    }

    int et_validity(char const* not_before, char const* not_after) {
        return mbedtls_x509write_crt_set_validity(&impl_, not_before, not_after);
    }

    int set_issuer_name(char const* issuer_name) {
        return mbedtls_x509write_crt_set_issuer_name(&impl_, issuer_name);
    }

    int set_subject_name(char const* subject_name) {
        return mbedtls_x509write_crt_set_subject_name(&impl_, subject_name);
    }

    void set_subject_key(mbedtls_pk_context* key) {
        mbedtls_x509write_crt_set_subject_key(&impl_, key);
    }

    void set_issuer_key(mbedtls_pk_context* key) {
        mbedtls_x509write_crt_set_issuer_key(&impl_, key);
    }

    void set_md_alg(mbedtls_md_type_t md_alg) {
        mbedtls_x509write_crt_set_md_alg(&impl_, md_alg);
    }

    int set_extension(
        char const* oid,
        size_t oid_len,
        int critical,
        unsigned char const* val,
        size_t val_len ) {
        return mbedtls_x509write_crt_set_extension(
            &impl_, oid, oid_len, critical, val, val_len);
    }

    int set_basic_constraints(int is_ca, int max_pathlen) {
        return mbedtls_x509write_crt_set_basic_constraints(&impl_, is_ca, max_pathlen);
    }

#if defined(MBEDTLS_SHA1_C)

    int set_subject_key_identifier(x509write_cert& ctx) {
        return mbedtls_x509write_crt_set_subject_key_identifier(ctx.impl());
    }

    int set_subject_key_aythority_identifier(x509write_cert& ctx) {
        return mbedtls_x509write_crt_set_authority_key_identifier(ctx.impl());
    }
#endif /* MBEDTLS_SHA1_C */

    int set_key_usage(unsigned int key_usage) {
        return mbedtls_x509write_crt_set_key_usage(&impl_, key_usage);
    }

    int set_ns_cert_type(unsigned char ns_cert_type) {
        return mbedtls_x509write_crt_set_ns_cert_type(&impl_, ns_cert_type);
    }

    int der(unsigned char* buf, size_t size,
            int (*f_rng)(void*, unsigned char*, size_t),
            void* p_rng) {
        return mbedtls_x509write_crt_der(&impl_, buf, size, f_rng, p_rng);
    }

#if defined(MBEDTLS_PEM_WRITE_C)
    int pem(unsigned char* buf, size_t size,
            int (*f_rng)(void*, unsigned char*, size_t),
            void*p_rng) {
        return mbedtls_x509write_crt_pem(&impl_, buf, size, f_rng, p_rng);
    }
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CRT_WRITE_C */

private:
    mbedtls_x509write_cert impl_;
};

} // namespace cpp

#endif // MBEDTLS_X509_CRT_HPP
