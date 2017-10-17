/*
 * libwebsockets - client-related ssl code independent of backend
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

int
lws_ssl_client_connect1(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	int n = 0;

	lws_latency_pre(context, wsi);

	n = lws_tls_client_connect(wsi);

	lws_latency(context, wsi,
	  "SSL_connect LWSCM_WSCL_ISSUE_HANDSHAKE", n, n > 0);

	if (n < 0) {
		n = lws_ssl_get_error(wsi, n);

		if (n == SSL_ERROR_WANT_READ)
			goto some_wait;

		if (n == SSL_ERROR_WANT_WRITE) {
			/*
			 * wants us to retry connect due to
			 * state of the underlying ssl layer...
			 * but since it may be stalled on
			 * blocked write, no incoming data may
			 * arrive to trigger the retry.
			 * Force (possibly many times if the SSL
			 * state persists in returning the
			 * condition code, but other sockets
			 * are getting serviced inbetweentimes)
			 * us to get called back when writable.
			 */
			lwsl_info("%s: WANT_WRITE... retrying\n", __func__);
			lws_callback_on_writable(wsi);
some_wait:
			wsi->mode = LWSCM_WSCL_WAITING_SSL;

			return 0; /* no error */
		}

		n = -1;
	}

	if (n <= 0) {
		/*
		 * retry if new data comes until we
		 * run into the connection timeout or win
		 */

		unsigned long error = ERR_get_error();

		if (error != SSL_ERROR_NONE) {
			lwsl_err("SSL connect error %lu\n", error);

			return -1;
		}

		return 0;
	}

	return 1;
}

int
lws_ssl_client_connect2(struct lws *wsi)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0];
	char *sb = p;
	int n = 0;

	if (wsi->mode == LWSCM_WSCL_WAITING_SSL) {
		lws_latency_pre(context, wsi);

		n = lws_tls_client_connect(wsi);
		lwsl_debug("%s: SSL_connect says %d\n", __func__, n);
		lws_latency(context, wsi,
			    "SSL_connect LWSCM_WSCL_WAITING_SSL", n, n > 0);
		if (n < 0) {
			n = lws_ssl_get_error(wsi, n);

			if (n == SSL_ERROR_WANT_READ) {
				lwsl_info("SSL_connect WANT_READ... retrying\n");

				wsi->mode = LWSCM_WSCL_WAITING_SSL;

				return 0; /* no error */
			}

			if (n == SSL_ERROR_WANT_WRITE) {
				/*
				 * wants us to retry connect due to
				 * state of the underlying ssl layer...
				 * but since it may be stalled on
				 * blocked write, no incoming data may
				 * arrive to trigger the retry.
				 * Force (possibly many times if the SSL
				 * state persists in returning the
				 * condition code, but other sockets
				 * are getting serviced inbetweentimes)
				 * us to get called back when writable.
				 */
				lwsl_info("SSL_connect WANT_WRITE... retrying\n");
				lws_callback_on_writable(wsi);

				wsi->mode = LWSCM_WSCL_WAITING_SSL;

				return 0; /* no error */
			}

			n = -1;
		}

		if (n <= 0) {
			/*
			 * retry if new data comes until we
			 * run into the connection timeout or win
			 */
			unsigned long error = ERR_get_error();
			if (error != SSL_ERROR_NONE) {
				lwsl_err("SSL connect error %lu: %s\n",
					 error, ERR_error_string(error, sb));
				return -1;
			}
		}
	}

	if (lws_tls_client_confirm_peer_cert(wsi))
		return -1;

	return 1;
}


int lws_context_init_client_ssl(struct lws_context_creation_info *info,
				struct lws_vhost *vhost)
{
	const char *ca_filepath = info->ssl_ca_filepath;
	const char *cipher_list = info->ssl_cipher_list;
	const char *private_key_filepath = info->ssl_private_key_filepath;
	const char *cert_filepath = info->ssl_cert_filepath;
	struct lws wsi;

	if (vhost->options & LWS_SERVER_OPTION_ONLY_RAW)
		return 0;

	/*
	 *  for backwards-compatibility default to using ssl_... members, but
	 * if the newer client-specific ones are given, use those
	 */
	if (info->client_ssl_cipher_list)
		cipher_list = info->client_ssl_cipher_list;
	if (info->client_ssl_cert_filepath)
		cert_filepath = info->client_ssl_cert_filepath;
	if (info->client_ssl_private_key_filepath)
		private_key_filepath = info->client_ssl_private_key_filepath;

	if (info->client_ssl_ca_filepath)
		ca_filepath = info->client_ssl_ca_filepath;

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return 0;

	if (vhost->ssl_client_ctx)
		return 0;

	if (info->provided_client_ssl_ctx) {
		/* use the provided OpenSSL context if given one */
		vhost->ssl_client_ctx = info->provided_client_ssl_ctx;
		/* nothing for lib to delete */
		vhost->user_supplied_ssl_ctx = 1;

		return 0;
	}

	if (lws_tls_client_create_vhost_context(vhost, info, cipher_list,
						ca_filepath, cert_filepath,
						private_key_filepath))
		return 1;

	lwsl_notice("created client ssl context for %s\n", vhost->name);

	/*
	 * give him a fake wsi with context set, so he can use
	 * lws_get_context() in the callback
	 */
	memset(&wsi, 0, sizeof(wsi));
	wsi.vhost = vhost;
	wsi.context = vhost->context;

	vhost->protocols[0].callback(&wsi,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
				       vhost->ssl_client_ctx, NULL, 0);

	return 0;
}
