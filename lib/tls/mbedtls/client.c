/*
 * libwebsockets - mbedtls-specific client TLS code
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

static int
OpenSSL_client_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	return 0;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	X509_VERIFY_PARAM *param;
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
		lwsl_err("SSL_new failed: %d\n", lws_ssl_get_error(wsi, 0));

		return -1;
	}

	if (wsi->vhost->ssl_info_event_mask)
		SSL_set_info_callback(wsi->ssl, lws_ssl_info_callback);

	if (!(wsi->use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)) {
		param = SSL_get0_param(wsi->ssl);
		/* Enable automatic hostname checks */
		X509_VERIFY_PARAM_set_hostflags(param,
					X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, hostname, 0);
	}

	/*
	 * use server name indication (SNI), if supported,
	 * when establishing connection
	 */
	if (wsi->vhost->x509_client_CA)
		SSL_set_verify(wsi->ssl, SSL_VERIFY_PEER,
			       OpenSSL_client_verify_callback);
	else
		SSL_set_verify(wsi->ssl, SSL_VERIFY_NONE,
			       OpenSSL_client_verify_callback);

	SSL_set_fd(wsi->ssl, wsi->desc.sockfd);

	return 0;
}

int ERR_get_error(void)
{
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
	X509 *peer = SSL_get_peer_certificate(wsi->ssl);

	if (!peer) {
		lwsl_info("peer did not provide cert\n");

		return -1;
	}
	lwsl_info("peer provided cert\n");

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
	X509 *d2i_X509(X509 **cert, const unsigned char *buffer, long len);
	SSL_METHOD *method = (SSL_METHOD *)TLS_client_method();
	unsigned long error;
	lws_filepos_t len;
	uint8_t *buf;

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

	if (!ca_filepath)
		return 0;

	if (alloc_file(vh->context, ca_filepath, &buf, &len)) {
		lwsl_err("Load CA cert file %s failed\n", ca_filepath);
		return 1;
	}

	vh->x509_client_CA = d2i_X509(NULL, buf, len);
	free(buf);
	if (!vh->x509_client_CA) {
		lwsl_err("client CA: x509 parse failed\n");
		return 1;
	}

	SSL_CTX_add_client_CA(vh->ssl_client_ctx, vh->x509_client_CA);

	lwsl_notice("client loaded CA for verification %s\n", ca_filepath);

	return 0;
}
