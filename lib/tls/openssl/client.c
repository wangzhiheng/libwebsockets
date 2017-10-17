/*
 * libwebsockets - openSSL-specific client tls code
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"

extern int openssl_websocket_private_data_index,
    openssl_SSL_CTX_private_data_index;

#if !defined(USE_WOLFSSL)

static int
OpenSSL_client_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	SSL *ssl;
	int n;
	struct lws *wsi;

	/* keep old behaviour accepting self-signed server certs */
	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (err != X509_V_OK) {
			ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
			wsi = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);

			if ((err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
					err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) &&
					wsi->use_ssl & LCCSCF_ALLOW_SELFSIGNED) {
				lwsl_notice("accepting self-signed certificate (verify_callback)\n");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
				return 1;	// ok
			} else if ((err == X509_V_ERR_CERT_NOT_YET_VALID ||
					err == X509_V_ERR_CERT_HAS_EXPIRED) &&
					wsi->use_ssl & LCCSCF_ALLOW_EXPIRED) {
				if (err == X509_V_ERR_CERT_NOT_YET_VALID)
					lwsl_notice("accepting not yet valid certificate (verify_callback)\n");
				else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
					lwsl_notice("accepting expired certificate (verify_callback)\n");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
				return 1;	// ok
			}
		}
	}

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	wsi = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);

	n = lws_get_context_protocol(wsi->context, 0).callback(wsi,
			LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION,
			x509_ctx, ssl, preverify_ok);

	/* keep old behaviour if something wrong with server certs */
	/* if ssl error is overruled in callback and cert is ok,
	 * X509_STORE_CTX_set_error(x509_ctx, X509_V_OK); must be set and
	 * return value is 0 from callback */
	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (err != X509_V_OK) {	/* cert validation error was not handled in callback */
			int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
			const char* msg = X509_verify_cert_error_string(err);
			lwsl_err("SSL error: %s (preverify_ok=%d;err=%d;depth=%d)\n", msg, preverify_ok, err, depth);
			return preverify_ok;	// not ok
		}
	}
	/* convert callback return code from 0 = OK to verify callback return value 1 = OK */
	return !n;
}
#endif

int
lws_ssl_client_bio_create(struct lws *wsi)
{
#if defined LWS_HAVE_X509_VERIFY_PARAM_set1_host
	X509_VERIFY_PARAM *param;
#endif
	char hostname[128], *p;

	if (lws_hdr_copy(wsi, hostname, sizeof(hostname),
			 _WSI_TOKEN_CLIENT_HOST) <= 0) {
		lwsl_err("%s: Unable to get hostname\n", __func__);

		return -1;
	}

	/*
	 * remove any :port part on the hostname... necessary for network
	 * connection but typical certificates do not contain it
	 */
	p = hostname;
	while (*p) {
		if (*p == ':') {
			*p = '\0';
			break;
		}
		p++;
	}

	wsi->ssl = SSL_new(wsi->vhost->ssl_client_ctx);
	if (!wsi->ssl) {
		lwsl_err("SSL_new failed: %s\n",
		         ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
		lws_ssl_elaborate_error();
		return -1;
	}

#if defined (LWS_HAVE_SSL_SET_INFO_CALLBACK)
	if (wsi->vhost->ssl_info_event_mask)
		SSL_set_info_callback(wsi->ssl, lws_ssl_info_callback);
#endif

#if defined LWS_HAVE_X509_VERIFY_PARAM_set1_host
	if (!(wsi->use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)) {
		param = SSL_get0_param(wsi->ssl);
		/* Enable automatic hostname checks */
		X509_VERIFY_PARAM_set_hostflags(param,
						X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, hostname, 0);
	}
#endif

#if !defined(USE_WOLFSSL)
#ifndef USE_OLD_CYASSL
	/* OpenSSL_client_verify_callback will be called @ SSL_connect() */
	SSL_set_verify(wsi->ssl, SSL_VERIFY_PEER, OpenSSL_client_verify_callback);
#endif
#endif

#if !defined(USE_WOLFSSL)
	SSL_set_mode(wsi->ssl,  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
	/*
	 * use server name indication (SNI), if supported,
	 * when establishing connection
	 */
#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
#ifdef CYASSL_SNI_HOST_NAME
	CyaSSL_UseSNI(wsi->ssl, CYASSL_SNI_HOST_NAME, hostname, strlen(hostname));
#endif
#else
#ifdef WOLFSSL_SNI_HOST_NAME
	wolfSSL_UseSNI(wsi->ssl, WOLFSSL_SNI_HOST_NAME, hostname, strlen(hostname));
#endif
#endif
#else
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_set_tlsext_host_name(wsi->ssl, hostname);
#endif
#endif

#ifdef USE_WOLFSSL
	/*
	 * wolfSSL/CyaSSL does certificate verification differently
	 * from OpenSSL.
	 * If we should ignore the certificate, we need to set
	 * this before SSL_new and SSL_connect is called.
	 * Otherwise the connect will simply fail with error code -155
	 */
#ifdef USE_OLD_CYASSL
	if (wsi->use_ssl == 2)
		CyaSSL_set_verify(wsi->ssl, SSL_VERIFY_NONE, NULL);
#else
	if (wsi->use_ssl == 2)
		wolfSSL_set_verify(wsi->ssl, SSL_VERIFY_NONE, NULL);
#endif
#endif /* USE_WOLFSSL */

	wsi->client_bio = BIO_new_socket(wsi->desc.sockfd, BIO_NOCLOSE);
	SSL_set_bio(wsi->ssl, wsi->client_bio, wsi->client_bio);

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
	CyaSSL_set_using_nonblock(wsi->ssl, 1);
#else
	wolfSSL_set_using_nonblock(wsi->ssl, 1);
#endif
#else
	BIO_set_nbio(wsi->client_bio, 1); /* nonblocking */
#endif

	SSL_set_ex_data(wsi->ssl, openssl_websocket_private_data_index, wsi);

	return 0;
}

int
lws_tls_client_connect(struct lws *wsi)
{
	return SSL_connect(wsi->ssl);
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi)
{
#ifndef USE_WOLFSSL
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0];
	char *sb = p;
	int n;

	lws_latency_pre(wsi->context, wsi);
	n = SSL_get_verify_result(wsi->ssl);
	lws_latency(wsi->context, wsi,
		"SSL_get_verify_result LWS_CONNMODE..HANDSHAKE", n, n > 0);

	lwsl_debug("get_verify says %d\n", n);

	if (n != X509_V_OK) {
		if ((n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
		     n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) &&
		     (wsi->use_ssl & LCCSCF_ALLOW_SELFSIGNED)) {
			lwsl_notice("accepting self-signed certificate\n");
		} else if ((n == X509_V_ERR_CERT_NOT_YET_VALID ||
		            n == X509_V_ERR_CERT_HAS_EXPIRED) &&
		     (wsi->use_ssl & LCCSCF_ALLOW_EXPIRED)) {
			lwsl_notice("accepting expired certificate\n");
		} else if (n == X509_V_ERR_CERT_NOT_YET_VALID) {
			lwsl_notice("Cert is from the future... "
				    "probably our clock... accepting...\n");
		} else {
			lwsl_err("server's cert didn't look good, X509_V_ERR = %d: %s\n",
				 n, ERR_error_string(n, sb));
			lws_ssl_elaborate_error();
			return -1;
		}
	}
#endif /* USE_WOLFSSL */

	return 0;
}

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const char *cert_filepath,
				    const char *private_key_filepath)
{
	SSL_METHOD *method;
	unsigned long error;
	int n;

	/* basic openssl init already happened in context init */

	/* choose the most recent spin of the api */
#if defined(LWS_HAVE_TLS_CLIENT_METHOD)
	method = (SSL_METHOD *)TLS_client_method();
#elif defined(LWS_HAVE_TLSV1_2_CLIENT_METHOD)
	method = (SSL_METHOD *)TLSv1_2_client_method();
#else
	method = (SSL_METHOD *)SSLv23_client_method();
#endif

	if (!method) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl method %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)vh->context->pt[0].serv_buf));
		return 1;
	}
	/* create context */
	vh->ssl_client_ctx = SSL_CTX_new(method);
	if (!vh->ssl_client_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)vh->context->pt[0].serv_buf));
		return 1;
	}

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(vh->ssl_client_ctx, SSL_OP_NO_COMPRESSION);
#endif

	SSL_CTX_set_options(vh->ssl_client_ctx,
			    SSL_OP_CIPHER_SERVER_PREFERENCE);

	if (cipher_list)
		SSL_CTX_set_cipher_list(vh->ssl_client_ctx, cipher_list);

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	if (!lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS))
		/* loads OS default CA certs */
		SSL_CTX_set_default_verify_paths(vh->ssl_client_ctx);
#endif

	/* openssl init for cert verification (for client sockets) */
	if (!ca_filepath) {
		if (!SSL_CTX_load_verify_locations(
			vh->ssl_client_ctx, NULL, LWS_OPENSSL_CLIENT_CERTS))
			lwsl_err("Unable to load SSL Client certs from %s "
			    "(set by LWS_OPENSSL_CLIENT_CERTS) -- "
			    "client ssl isn't going to work\n",
			    LWS_OPENSSL_CLIENT_CERTS);
	} else
		if (!SSL_CTX_load_verify_locations(
			vh->ssl_client_ctx, ca_filepath, NULL)) {
			lwsl_err(
				"Unable to load SSL Client certs "
				"file from %s -- client ssl isn't "
				"going to work\n", ca_filepath);
			lws_ssl_elaborate_error();
		}
		else
			lwsl_info("loaded ssl_ca_filepath\n");

	/*
	 * callback allowing user code to load extra verification certs
	 * helping the client to verify server identity
	 */

	/* support for client-side certificate authentication */
	if (cert_filepath) {
		lwsl_notice("%s: doing cert filepath\n", __func__);
		n = SSL_CTX_use_certificate_chain_file(vh->ssl_client_ctx,
						       cert_filepath);
		if (n < 1) {
			lwsl_err("problem %d getting cert '%s'\n", n,
				 cert_filepath);
			lws_ssl_elaborate_error();
			return 1;
		}
		lwsl_notice("Loaded client cert %s\n", cert_filepath);
	}
	if (private_key_filepath) {
		lwsl_notice("%s: doing private key filepath\n", __func__);
		lws_ssl_bind_passphrase(vh->ssl_client_ctx, info);
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(vh->ssl_client_ctx,
		    private_key_filepath, SSL_FILETYPE_PEM) != 1) {
			lwsl_err("use_PrivateKey_file '%s'\n",
				 private_key_filepath);
			lws_ssl_elaborate_error();
			return 1;
		}
		lwsl_notice("Loaded client cert private key %s\n",
			    private_key_filepath);

		/* verify private key */
		if (!SSL_CTX_check_private_key(vh->ssl_client_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			return 1;
		}
	}

	return 0;
}

