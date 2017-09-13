#if !defined(MBEDTLS_SSL_CONTEXT_HPP)
#define MBEDTLS_SSL_CONTEXT_HPP

#include <mbedtls/ssl.h>
#include "mbedtls_ssl_config.hpp"

namespace mbedtls_cpp {

class ssl_context {
public:
    mbedtls_ssl_context* impl() { return &impl_; }
    mbedtls_ssl_context const* impl() const { return &impl_; }

    ssl_context() {
        mbedtls_ssl_init(&impl_);
    }
    ~ssl_context() {
        mbedtls_ssl_free(&impl_);
    }

    int setup(ssl_config const& conf) {
        return mbedtls_ssl_setup(&impl_, conf.impl());
    }

    int session_reset() {
        return mbedtls_ssl_session_reset(&impl_);
    }

    void set_bio(
        void* p_bio,
        mbedtls_ssl_send_t* f_send,
        mbedtls_ssl_recv_t* f_recv,
        mbedtls_ssl_recv_timeout_t* f_recv_timeout) {
        mbedtls_ssl_set_bio(&impl_, p_bio, f_send, f_recv, f_recv_timeout);
    }

    void set_timer_cb(
        void* p_timer,
        mbedtls_ssl_set_timer_t* f_set_timer,
        mbedtls_ssl_get_timer_t* f_get_timer) {
        mbedtls_ssl_set_timer_cb(&impl_, p_timer, f_set_timer, f_get_timer);
    }

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    int set_client_transport_id(
        unsigned char const* info,
        size_t ilen) {
        return mbedtls_ssl_set_client_transport_id(&impl_, info, ilen);
    }
#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY && MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    int set_session(mbedtls_ssl_session const* session) {
        return mbedtls_ssl_set_session(&impl_, session);
    }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    int set_hs_psk(unsigned char const* psk, size_t psk_len) {
        return mbedtls_ssl_set_hs_psk(&impl_, psk, psk_len);
    }
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    int set_hostname(char const* hostname) {
        return mbedtls_ssl_set_hostname(&impl_, hostname);
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    int set_hs_own_cert(
        x509_crt& own_cert,
        mbedtls_pk_context* pk_key) {
        return mbedtls_ssl_set_hs_own_cert(&impl_, own_cert.impl(), pk_key);
    }

    void set_hs_ca_chain(
        x509_crt& ca_chain,
        x509_crl& ca_crl) {
        mbedtls_ssl_set_hs_ca_chain(&impl_, ca_chain.impl(), ca_crl.impl());
    }

    void set_hs_authmode(int authmode) {
        mbedtls_ssl_set_hs_authmode(&impl_, authmode);
    }
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    int set_hs_ecjpake_password(
        unsigned char const* pw,
        size_t pw_len) {
        return mbedtls_ssl_set_hs_ecjpake_password(&impl_, pw, pw_len);
    }
#endif /*MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */


#if defined(MBEDTLS_SSL_ALPN)
    char const* get_alpn_protocol() const {
        return mbedtls_ssl_get_alpn_protocol(&impl_);
    }
#endif /* MBEDTLS_SSL_ALPN */
    size_t get_bytes_avail() const {
        return mbedtls_ssl_get_bytes_avail(&impl_);
    }

    uint32_t get_verify_result() const {
        return mbedtls_ssl_get_verify_result(&impl_);
    }

    char const* get_ciphersuite() const {
        return mbedtls_ssl_get_ciphersuite(&impl_);
    }

    char const* get_version() const {
        return mbedtls_ssl_get_version(&impl_);
    }

    int get_record_expansion() const {
        return mbedtls_ssl_get_record_expansion(&impl_);
    }

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    size_t get_max_frag_len() const {
        return mbedtls_ssl_get_max_frag_len(&impl_);
    }
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt const* get_peer_cert() const {
        return mbedtls_ssl_get_peer_cert(&impl_);
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_CLI_C)
    int get_session(mbedtls_ssl_session* session) const {
        return mbedtls_ssl_get_session(&impl_, session);
    }
#endif /* MBEDTLS_SSL_CLI_C */

    int handshake() {
        return mbedtls_ssl_handshake(&impl_);
    }

    int handshake_step() {
        return mbedtls_ssl_handshake_step(&impl_);
    }

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int renegotiate() {
        return mbedtls_ssl_renegotiate(&impl_);
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

    int read(unsigned char* buf, size_t len) {
        return mbedtls_ssl_read(&impl_, buf, len);
    }

    int write(unsigned char const* buf, size_t len) {
        return mbedtls_ssl_write(&impl_, buf, len);
    }

    int send_alert_message(
        unsigned char level,
        unsigned char message) {
        return mbedtls_ssl_send_alert_message(&impl_, level, message);
    }

    int close_notify() {
        return mbedtls_ssl_close_notify(&impl_);
    }

private:
    mbedtls_ssl_context impl_;
};

} // namespace cpp

#endif // MBEDTLS_SSL_CONTEXT_HPP
