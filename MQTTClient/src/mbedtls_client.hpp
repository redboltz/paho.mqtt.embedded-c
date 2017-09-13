#if !defined(MBED_TLS_CLIENT_HPP)
#define MBED_TLS_CLIENT_HPP

#include <cstring>

#include "mbedtls_entropy.hpp"
#include "mbedtls_ctr_drbg.hpp"
#include "mbedtls_x509_crt.hpp"
#include "mbedtls_ssl_context.hpp"
#include "mbedtls_ssl_config.hpp"

namespace mbedtls_cpp {

template <typename TcpSocket>
class tls_client {
    typedef tls_client<TcpSocket> this_type;

public:
    // to meet paho mqtt embeddedconcept
    int read(unsigned char* buffer, int len, int timeout) {
        timeout_ms_ = timeout;
        return sctx_.read(buffer, len);
    }
    int write(unsigned char* buffer, int len, int timeout) {
        timeout_ms_ = timeout;
        return sctx_.write(buffer, len);
    }

public:
    tls_client(TcpSocket& tcp_socket)
        :tcp_socket_(tcp_socket),
         has_saved_session_(false),
         timeout_ms_(1000) {
        std::memset(&saved_session_, 0, sizeof(saved_session_));
    }

    int handshake(char const* hostname) {
        {
            int rc = sctx_.session_reset();
            printf("%d:%d\n", __LINE__, rc);
            if (rc != 0) return rc;
        }
#if defined(MBEDTLS_SSL_CLI_C)
        {
            if (has_saved_session_) {
                int rc = sctx_.set_session(&saved_session_);
            printf("%d:%d\n", __LINE__, rc);
                if (rc != 0) return rc;
            }
        }
#endif // defined(MBEDTLS_SSL_CLI_C)
        {
            sctx_.set_hostname(hostname);
            sctx_.set_bio(this, tls_send, tls_recv, 0);
        }
        {
            int rc = sctx_.handshake();
            printf("%d:%d\n", __LINE__, rc);
            if (rc != 0) return rc;
        }
        {
            uint32_t flags = sctx_.get_verify_result();
            printf("%d:%d\n", __LINE__, flags);
            if (flags != 0) return -1;
        }
#if defined(MBEDTLS_SSL_CLI_C)
        {
            int rc = sctx_.get_session(&saved_session_);
            printf("%d:%d\n", __LINE__, rc);
            if (rc != 0) {
                has_saved_session_ = false;
                return -1;
            }
            has_saved_session_ = true;
        }
#endif // defined(MBEDTLS_SSL_CLI_C)
        return 0;
    }

    int init(char const* cacert_file) {
        {
            unsigned char seed[] = "Custom seed";
            int rc = dc_.seed(
                mbedtls_entropy_func,
                ec_.impl(),
                seed,
                sizeof(seed));
            if (rc != 0) return rc;
        }
        {
            int rc = crt_.parse_file(cacert_file);
            if (rc != 0) return rc;
        }
        {
            int rc = scfg_.defaults(
                MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT);
            if (rc != 0) return rc;
        }
        scfg_.ca_chain(crt_);
        scfg_.rng(mbedtls_ctr_drbg_random, dc_.impl());
        scfg_.authmode(MBEDTLS_SSL_VERIFY_REQUIRED);
        {
            int rc = sctx_.setup(scfg_);
            if (rc != 0) return rc;
        }
        return 0;
    }

private:
    static int tls_send(void* ctx, unsigned char const* buf, size_t len) {
        this_type* self = static_cast<this_type*>(ctx);
        return self->tcp_socket_.write(buf, len, self->timeout_ms_);
    }
    static int tls_recv(void* ctx, unsigned char* buf, size_t len) {
        this_type* self = static_cast<this_type*>(ctx);
        return self->tcp_socket_.read(buf, len, self->timeout_ms_);
    }

private:
    TcpSocket& tcp_socket_;
    bool has_saved_session_;
    entropy_context ec_;
    ctr_drbg_context dc_;
    x509_crt crt_;
    ssl_context sctx_;
    ssl_config scfg_;
    mbedtls_ssl_context ssl_;
    mbedtls_ssl_session saved_session_;
    int timeout_ms_;
};

} // namespace mbedtls_cpp

#endif // !defined(MBED_TLS_CLIENT_HPP)
