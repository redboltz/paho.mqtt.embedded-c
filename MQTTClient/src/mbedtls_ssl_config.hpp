#if !defined(MBEDTLS_SSL_CONFIG_HPP)
#define MBEDTLS_SSL_CONFIG_HPP

#include <mbedtls/ssl.h>
#include "mbedtls_x509_crt.hpp"
#include "mbedtls_x509_crl.hpp"

namespace mbedtls_cpp {

class ssl_config {
public:
    mbedtls_ssl_config* impl() { return &impl_; }
    mbedtls_ssl_config const* impl() const { return &impl_; }

    ssl_config() {
        mbedtls_ssl_config_init(&impl_);
    }
    ~ssl_config() {
        mbedtls_ssl_config_free(&impl_);
    }

    void endpoint(int endpoint) {
        mbedtls_ssl_conf_endpoint(&impl_, endpoint);
    }
    void transport(int transport) {
        mbedtls_ssl_conf_transport(&impl_, transport);
    }
    void authmode(int auth_mode) {
        mbedtls_ssl_conf_authmode(&impl_, auth_mode);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    void verify(
        int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*),
        void* p_vrfy) {
        mbedtls_ssl_conf_verify(&impl_, f_vrfy, p_vrfy);
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    void rng(
        int (*f_rng)(void*, unsigned char*, size_t),
        void* p_rng ) {
        mbedtls_ssl_conf_rng(&impl_, f_rng, p_rng);
    }
    void dbg(
        void (*f_dbg)(void*, int, char const*, int, char const*),
        void* p_dbg ) {
        mbedtls_ssl_conf_dbg(&impl_, f_dbg, p_dbg);
    }
    void read_timeout(uint32_t timeout) {
        mbedtls_ssl_conf_read_timeout(&impl_, timeout);
    }

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_SRV_C)
    void session_tickets_cb(
        mbedtls_ssl_ticket_write_t* f_ticket_write,
        mbedtls_ssl_ticket_parse_t* f_ticket_parse,
        void* p_ticket ) {
        mbedtls_ssl_conf_session_tickets_cb(&impl_, f_ticket_write, f_ticket_parse, p_ticket);
    }
#endif /* MBEDTLS_SSL_SESSION_TICKETS && MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_EXPORT_KEYS)
    void export_keys_cb(
        mbedtls_ssl_export_keys_t* f_export_keys,
        void* p_export_keys) {
        mbedtls_ssl_conf_export_keys_cb(&impl_, f_export_keys, p_export_keys);
    }
#endif /* MBEDTLS_SSL_EXPORT_KEYS */

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    void dtls_cookies(
        mbedtls_ssl_cookie_write_t* f_cookie_write,
        mbedtls_ssl_cookie_check_t* f_cookie_check,
        void* p_cookie ) {
        mbedtls_ssl_conf_dtls_cookies(&impl_, f_cookie_write, f_cookie_check, p_cookie);
    }
#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY && MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    void dtls_anti_replay(char mode) {
        mbedtls_ssl_conf_dtls_anti_replay(&impl_, mode);
    }
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
    void tls_badmac_limit(unsigned limit) {
        mbedtls_ssl_conf_dtls_badmac_limit(&impl_, limit);
    }
#endif /* MBEDTLS_SSL_DTLS_BADMAC_LIMIT */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    void handshake_timeout(uint32_t min, uint32_t max) {
        mbedtls_ssl_conf_handshake_timeout(&impl_, min, max);
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_SRV_C)
    void session_cache(
        void* p_cache,
        int (*f_get_cache)(void*, mbedtls_ssl_session*),
        int (*f_set_cache)(void*, mbedtls_ssl_session const*)) {
        mbedtls_ssl_conf_session_cache(&impl_, p_cache, f_get_cache, f_set_cache);
    }
#endif /* MBEDTLS_SSL_SRV_C */

    void ciphersuites_for_version(
        int const* ciphersuites,
        int major,
        int minor) {
        mbedtls_ssl_conf_ciphersuites_for_version(&impl_, ciphersuites, major, minor);
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    void cert_profile(
        mbedtls_x509_crt_profile const* profile) {
        mbedtls_ssl_conf_cert_profile(&impl_, profile);
    }

    void ca_chain(
        x509_crt& ca_chain,
        x509_crl& ca_crl) {
        mbedtls_ssl_conf_ca_chain(&impl_, ca_chain.impl(), ca_crl.impl());
    }

    void ca_chain(
        x509_crt& ca_chain) {
        mbedtls_ssl_conf_ca_chain(&impl_, ca_chain.impl(), 0);
    }

    int own_cert(x509_crt& own_cert, mbedtls_pk_context* pk_key) {
        return mbedtls_ssl_conf_own_cert(&impl_, own_cert.impl(), pk_key);
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    int psk(
        unsigned char const* psk, size_t psk_len,
        unsigned char const* psk_identity, size_t psk_identity_len) {
        return mbedtls_ssl_conf_psk(&impl_, psk, psk_len, psk_identity, psk_identity_len);
    }
    void psk_cb(
        int (*f_psk)(void*, mbedtls_ssl_context*, const unsigned char*, size_t),
        void* p_psk) {
        mbedtls_ssl_conf_psk_cb(&impl_, f_psk, p_psk);
    }
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
    int dh_param(char const* dhm_P, char const* dhm_G) {
        return mbedtls_ssl_conf_dh_param(&impl_, dhm_P, dhm_G);
    }

    int dh_param_ctx(mbedtls_dhm_context* dhm_ctx) {
        return mbedtls_ssl_conf_dh_param_ctx(&impl_, dhm_ctx);
    }
#endif /* MBEDTLS_DHM_C && defined(MBEDTLS_SSL_SRV_C) */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)

    void dhm_min_bitlen(unsigned int bitlen) {
        mbedtls_ssl_conf_dhm_min_bitlen(&impl_, bitlen);
    }
#endif /* MBEDTLS_DHM_C && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_ECP_C)
    void curves(mbedtls_ecp_group_id const* curves) {
        mbedtls_ssl_conf_curves(&impl_, curves);
    }
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
    void sig_hashes(int const* hashes) {
        mbedtls_ssl_conf_sig_hashes(&impl_, hashes);
    }
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    void sni(
        int (*f_sni)(void*, mbedtls_ssl_context*, unsigned char const*, size_t),
        void* p_sni) {
        mbedtls_ssl_conf_sni(&impl_, f_sni, p_sni);
    }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_ALPN)
    int alpn_protocols(char const** protos) {
        return mbedtls_ssl_conf_alpn_protocols(&impl_, protos);
    }
#endif /* MBEDTLS_SSL_ALPN */

    void max_version(int major, int minor) {
        mbedtls_ssl_conf_max_version(&impl_, major, minor);
    }

    void min_version(int major, int minor) {
        mbedtls_ssl_conf_min_version(&impl_, major, minor);
    }

#if defined(MBEDTLS_SSL_FALLBACK_SCSV) && defined(MBEDTLS_SSL_CLI_C)
    void fallback(char fallback) {
        mbedtls_ssl_conf_fallback(&impl_, fallback);
    }
#endif /* MBEDTLS_SSL_FALLBACK_SCSV && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    void encrypt_then_mac(char etm) {
        mbedtls_ssl_conf_encrypt_then_mac(&impl_, etm);
    }
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    void extended_master_secret(char ems) {
        mbedtls_ssl_conf_extended_master_secret(&impl_, ems);
    }
#endif /* MBEDTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(MBEDTLS_ARC4_C)
    void arc4_support(char arc4) {
        mbedtls_ssl_conf_arc4_support(&impl_, arc4);
    }
#endif /* MBEDTLS_ARC4_C */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    int max_flag_len(unsigned char mfl_code) {
        return mbedtls_ssl_conf_max_frag_len(&impl_, mfl_code);
    }
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    void truncated_hmac(int truncate) {
        mbedtls_ssl_conf_truncated_hmac(&impl_, truncate);
    }
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    void cbc_record_splitting(char split) {
        mbedtls_ssl_conf_cbc_record_splitting(&impl_, split);
    }
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    void session_tickets(int use_tickets) {
        mbedtls_ssl_conf_session_tickets(&impl_, use_tickets);
    }
#endif /* MBEDTLS_SSL_SESSION_TICKETS && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    void renegotiation(int renegotiation) {
        mbedtls_ssl_conf_renegotiation(&impl_, renegotiation);
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

    void legacy_renegotiation(int allow_legacy) {
        mbedtls_ssl_conf_legacy_renegotiation(&impl_, allow_legacy);
    }

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    void renegotiation_enforced(int max_records) {
        mbedtls_ssl_conf_renegotiation_enforced(&impl_, max_records);
    }

    void renegotiation_period(unsigned char const period[8]) {
        mbedtls_ssl_conf_renegotiation_period(&impl_, period);
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

    int defaults(int endpoint, int transport, int preset) {
        return mbedtls_ssl_config_defaults(&impl_, endpoint, transport, preset);
    }

 private:
    mbedtls_ssl_config impl_;
};

} // namespace cpp

#endif // MBEDTLS_SSL_CONFIG_HPP
