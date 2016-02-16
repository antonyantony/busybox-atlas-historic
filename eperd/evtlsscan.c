/*
 * Copyright (c) 2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "json-macros.h"
#include "libbb.h"
#include "atlas_bb64.h"
#include "atlas_probe.h"
#include <netdb.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <math.h>
#include <assert.h>

#include "eperd.h"

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "tls_hostname_validation.h"

#define SAFE_PREFIX ATLAS_DATA_NEW

#define DEFAULT_LINE_LENGTH 1024
#define DEFAULT_NOREPLY_TIMEOUT 5000
#define O_RETRY  200

#define STATUS_FREE 0
#define STATUS_START 1001


enum readstate { READ_FIRST, READ_STATUS, READ_HEADER, READ_BODY, READ_SIMPLE,
	READ_CHUNKED, READ_CHUNK_BODY, READ_CHUNK_END,
	READ_CHUNKED_TRAILER,
	READ_DONE };
enum writestate { WRITE_FIRST, WRITE_HEADER, WRITE_POST_HEADER,
	WRITE_POST_FILE, WRITE_POST_FOOTER, WRITE_DONE };


/* struct common for all quries */
struct ssl_base {
	struct event_base *event_base;
};

static void crondlog_aa(const char *ctl, char *fmt, ...);

/* How to keep track of each user sslscan query */
struct ssl_state {
	char *host;
	char *str_Atlas;
	char *out_filename;
	int state; 
	int q_serial;  /* on parent it is the total queries sent */
	int q_done;
	int q_success;

	struct buf err;
	struct buf *result; /* all children share same result structure as parent */

	struct evutil_addrinfo *addr;
	struct timeval start_time;

	char *port;
	char do_get;
	char do_head;
	char do_http10;
	char *user_agent;
	char *path;

	int dns_count; /* resolved addresses to query */
	struct timeval timeout_tv;

	int active; /* how many pending additional quries per query */
	int retry;

	int opt_retry_max;
	int opt_ignore_cert;

	int opt_v4;
	int opt_v6;
	int opt_max_con; /* maximum concurrent queries per destination */
	int opt_max_bytes; /*  max size of output buffer */

	bool opt_all_tests; 

	int opt_ssl_v3;
	int opt_tls_v1;
	int opt_tls_v11;
	int opt_tls_v12;

	struct ssl_child *c;
	struct evutil_addrinfo hints;
	struct event done_ev;
	void (*done)(void *state);
};

struct ssl_child {
	/* per instance variables. Unshared after duplicate */
	struct ssl_child *next;
	int serial;  /* serial number of each additional query. First is zero */

	struct ssl_state *p; /* parent object */
	struct buf *result; /* all children share same result structure as parent */

	struct buf err;

	SSL_CTX *ssl_ctx; 
	SSL *ssl;
	int sslv; /* version of child query from parent opt_ */
	const char *sslv_str; /* string for sslv */
	const char *cipher_list; /* for this child query */
	struct bufferevent *bev;
	struct evutil_addrinfo *addr_curr;

	struct timeval start_time;
	double triptime;
	double ttc;
	int retry;

	struct event timeout_ev;
	struct event free_child_ev;
	struct event free_pqry_ev;
	bool gc;
	bool ssl_incomplete;
	enum readstate readstate;
	enum writestate writestate;
	struct sockaddr_in6 loc_sin6;
	socklen_t loc_socklen;
	char addrstr[INET6_ADDRSTRLEN];
};

static char line[(DEFAULT_LINE_LENGTH+1)];
static struct option longopts[]=
{
	{ "retry",  required_argument, NULL, O_RETRY },
};

bufferevent_data_cb event_cb(struct bufferevent *bev, short events, void *ptr);
static void write_cb(struct bufferevent *bev, void *ptr);
void print_ssl_resp(struct ssl_child *qry);
static void http_read_cb(struct bufferevent *bev UNUSED_PARAM, void *ptr);

static struct ssl_base *ssl_base = NULL; 


static void done_cb(int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h) {
	struct ssl_state *pqry = h;
	pqry->done(pqry);
}

static void free_qry_inst_cb (int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{
	struct ssl_state *pqry = h;
	if(pqry->err.size)
	{
		buf_cleanup(&pqry->err);
	}

	if ((pqry->result != NULL) && pqry->result->size)
	{
		buf_cleanup(pqry->result);
	}

	if (pqry->addr != NULL) {
		evutil_freeaddrinfo(pqry->addr);
		pqry->addr = NULL;
	}
}

static void free_child_cb  (int unused  UNUSED_PARAM, const short event UNUSED_PARAM, void *h)
{

	struct ssl_child *qry = h;
	/* only free ephemeral data for the qury */ 
	if(qry->err.size)
	{
		buf_cleanup(&qry->err);
	}

	 
	if (qry->bev != NULL && qry->ssl_incomplete){
		bufferevent_free(qry->bev);
		qry->bev = NULL;
	}
	/*
	if(qry->ssl != NULL) {
		SSL_free(qry->ssl);
		qry->ssl = NULL;
	}

	if(qry->ssl_ctx !=  NULL) {
		SSL_CTX_free(qry->ssl_ctx);
		qry->ssl_ctx = NULL;
	}
	*/
	evtimer_del(&qry->timeout_ev);
}

int sslscan_delete (void *st) 
{
	struct ssl_state *pqry = st;
	if (pqry->state )
		return 0;

	if (pqry->result != NULL) {
		free(pqry->result);
		pqry->result = NULL;
	}

	if(pqry->out_filename)
	{
		free(pqry->out_filename);
		pqry->out_filename = NULL ;
	}

	if( pqry->str_Atlas)
	{
		free(pqry->str_Atlas);
		pqry->str_Atlas = NULL;
	}

	if( pqry->host)
	{
		free(pqry->host);
		pqry->host = NULL;
	}

	return 1;
}

static void timeout_cb(int unused  UNUSED_PARAM, const short event
		UNUSED_PARAM, void *h)
{
	struct ssl_child *qry = (struct ssl_child *)h;
	crondlog_aa(LVL7, "%s %s %s active = %d %s %s",  __func__,
			qry->p->host, qry->addrstr, qry->p->active, qry->sslv_str, qry->cipher_list);

	snprintf(line, DEFAULT_LINE_LENGTH, "%s \"timeout\" : %d", qry->err.size ? ", " : "", DEFAULT_NOREPLY_TIMEOUT);
	buf_add(&qry->err, line, strlen(line));

	if(qry->ssl != NULL) {
		SSL_free(qry->ssl);
		qry->ssl = NULL;
	}

	print_ssl_resp(qry);
}

/* Initialize a struct timeval by converting milliseconds */
static void msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	char cert_str[256];
	const char *host = (const char *) arg;
	const char *res_str = "X509_verify_cert failed";
	HostnameValidationResult res = Error;

	/* This is the function that OpenSSL would call if we hadn't called
	 * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
	 * the default functionality, rather than replacing it. */
	int ok_so_far = 0;

	X509 *server_cert = NULL;

	/* AA  fixme
	if (qry->opt_ignore_cert) { */
		return 1;
		/*
	}
	*/

	ok_so_far = X509_verify_cert(x509_ctx);

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (server_cert  == NULL) 
		return 0;

	if (ok_so_far) {
		res = validate_hostname(host, server_cert);

		switch (res) {
		case MatchFound:
			res_str = "MatchFound";
			break;
		case MatchNotFound:
			res_str = "MatchNotFound";
			break;
		case NoSANPresent:
			res_str = "NoSANPresent";
			break;
		case MalformedCertificate:
			res_str = "MalformedCertificate";
			break;
		case Error:
			res_str = "Error";
			break;
		default:
			res_str = "WTF!";
			break;
		}
	}

	X509_NAME_oneline(X509_get_subject_name (server_cert),
			  cert_str, sizeof (cert_str));
	X509_free(server_cert);

	if (res == MatchFound) {
		printf("https server '%s' has this certificate, "
		       "which looks good to me:\n%s\n",
		       host, cert_str);
		return 1;
	}
	else {
		printf("Got '%s' for hostname '%s' and certificate:\n%s\n",
		       res_str, host, cert_str);
		return 1;
	}
}




static bool verify_ssl_cert (struct ssl_child *qry) {

	/* Attempt to use the system's trusted root certificates.
	 * (This path is only valid for Debian-based systems.) */
	 //if (1 != SSL_CTX_load_verify_locations(qry->ssl_ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) crondlog(LVL7,"SSL_CTX_load_verify_locations"); 

	/* Ask OpenSSL to verify the server certificate.  Note that this
	 * does NOT include verifying that the hostname is correct.
	 * So, by itself, this means anyone with any legitimate
	 * CA-issued certificate for any website, can impersonate any
	 * other website in the world.  This is not good.  See "The
	 * Most Dangerous Code in the World" article at
	 * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
	 */

	SSL_CTX_set_verify(qry->ssl_ctx, SSL_VERIFY_PEER, NULL);
	
	/* This is how we solve the problem mentioned in the previous
	 * comment.  We "wrap" OpenSSL's validation routine in our
	 * own routine, which also validates the hostname by calling
	 * the code provided by iSECPartners.  Note that even though
	 * the "Everything You've Always Wanted to Know About
	 * Certificate Validation With OpenSSL (But Were Afraid to
	 * Ask)" paper from iSECPartners says very explicitly not to
	 * call SSL_CTX_set_cert_verify_callback (at the bottom of
	 * page 2), what we're doing here is safe because our
	 * cert_verify_callback() calls X509_verify_cert(), which is
	 * OpenSSL's built-in routine which would have been called if
	 * we hadn't set the callback.  Therefore, we're just
	 * "wrapping" OpenSSL's routine, not replacing it. */ 

	SSL_CTX_set_cert_verify_callback (qry->ssl_ctx, cert_verify_callback, (void *) qry->p->host);
}


static bool ssl_child_start (struct ssl_child *qry, const char * cipher_list)
{
	/* OpenSSL is initialized, SSL_library_init() should be called already */

	/* 
	 ssl_ctx are not shared between quries. It could but not sure how to 
	 set structures with specific versions and algorithms. Instead using
	 one ctx per query.
	 */
	
	switch(qry->sslv) 
	{
		case SSL3_VERSION:
			qry->ssl_ctx = SSL_CTX_new(SSLv3_client_method());
			qry->sslv_str = SSL_TXT_SSLV3;
			break;
		case TLS1_VERSION:
			qry->ssl_ctx = SSL_CTX_new(TLSv1_client_method());
			qry->sslv_str = SSL_TXT_TLSV1;
			break;
		case TLS1_1_VERSION:
			qry->ssl_ctx = SSL_CTX_new(TLSv1_1_client_method());
			qry->sslv_str = SSL_TXT_TLSV1_1;
			break;
		case TLS1_2_VERSION:
			qry->ssl_ctx = SSL_CTX_new(TLSv1_2_client_method());
			qry->sslv_str = SSL_TXT_TLSV1_2;
			break;
		default:
			qry->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
			qry->sslv_str = "TLSv1/SSL2/SSL3";
			break;

	}

	qry->cipher_list =  cipher_list;

	/* Do we want to do any sort of vericiation the probe? */
	/* if we don't we might be hitting a proxy server in the way */
	// verify_ssl_cert(qry);
	

	/* this cipher per context . we are setting per connection */
 	// SSL_CTX_set_cipher_list(qry->ssl_ctx, "ALL:COMPLEMENTOFALL");
	// SSL_CTX_set_cipher_list(qry->ssl_ctx, "HIGH");

	if (!qry->ssl_ctx) {
		crondlog_aa(LVL9, "SSL_CTX_new");
		return TRUE;
	}

	qry->ssl = SSL_new(qry->ssl_ctx);
	if (qry->ssl == NULL) {
		crondlog_aa(LVL9, "SSL_new()");
		return TRUE;
	}
	SSL_set_cipher_list(qry->ssl, cipher_list);

	/* Set hostname for SNI extension */
	SSL_set_tlsext_host_name(qry->ssl, qry->p->host);

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &qry->p->timeout_tv);
	evtimer_add(&qry->timeout_ev, &qry->p->timeout_tv);

	qry->bev = bufferevent_openssl_socket_new(EventBase, -1, qry->ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE);

	//bufferevent_openssl_set_allow_dirty_shutdown(qry->bev, 1);
	bufferevent_setcb(qry->bev, http_read_cb, write_cb, event_cb, qry);

	{
		void *ptr = NULL;
		if (qry->addr_curr->ai_family == AF_INET) {
			ptr = &((struct sockaddr_in *) qry->addr_curr->ai_addr)->sin_addr;
		}
		else if (qry->addr_curr->ai_family == AF_INET6) {
			ptr = &((struct sockaddr_in6 *)
					qry->addr_curr->ai_addr)->sin6_addr;
		}
		inet_ntop (qry->addr_curr->ai_family, ptr, qry->addrstr, INET6_ADDRSTRLEN);
		crondlog_aa(LVL7, "connect to %s %s active = %d %s %s", 
				qry->addrstr, qry->p->host, qry->p->active, qry->sslv_str, qry->cipher_list);
	}

	if (bufferevent_socket_connect(qry->bev,
				qry->addr_curr->ai_addr,
				qry->addr_curr->ai_addrlen)) {
		crondlog_aa(LVL8, "ERROR bufferevent_socket_connect to %s %s" 
				"ctive = %d %s %s - %s", qry->addrstr, qry->p->host, 
				qry->p->active, qry->sslv_str, qry->cipher_list,
				evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR())
				);

		// warnx("could not connect to %s : %s", qry->p->host, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		bufferevent_free(qry->bev);
		qry->bev = NULL;
		return TRUE;
	}
	else{
		gettimeofday(&qry->start_time, NULL);
		return FALSE;
	}
	return FALSE;
}


static void ssl_gc_init(struct ssl_child *qry)
{
	int i;
	const char *p;
	SSL *ssl = SSL_new(qry->ssl_ctx);

	for (i=0; ; i++)
	{
		p=SSL_get_cipher_list(ssl,i);

		if (p == NULL) {
			printf ("%d got null" , i);
			break;
		}
		if (strlen(p) && strncmp(p, qry->cipher_list, strlen(p)) == 0)
			continue;

		qry->p->active++;
		struct  ssl_child *gcqry = xzalloc(sizeof(struct ssl_child));
		gcqry->next = qry->p->c;
		qry->p->c = gcqry;
		qry->ssl_incomplete = TRUE;

		gcqry->p = qry->p;

		qry->p->q_serial++;
		qry->serial =  qry->p->q_serial;
		
		gcqry->addr_curr = qry->addr_curr;
		gcqry->result = qry->result;
		evtimer_assign(&gcqry->timeout_ev, EventBase, timeout_cb, gcqry);
		evtimer_assign(&gcqry->free_child_ev, EventBase, free_child_cb, gcqry);
		gcqry->sslv  = qry->sslv;
		crondlog_aa(LVL7, "grand child %s %s %s active = %d %s %s",  __func__,
				qry->p->host, qry->addrstr, qry->p->active, qry->sslv_str, p);
		ssl_child_start(gcqry, p);
		gcqry->gc = TRUE;
	}
}	

void fmt_ssl_resp(struct ssl_child *qry) {
	char addrstr[INET6_ADDRSTRLEN];
        char dst_addr_str[(INET6_ADDRSTRLEN+1)];
	void *ptr = NULL;
	struct timeval asap = { 0, 100 };

	int fw = get_atlas_fw_version();
	int lts =  -1 ; /*  get_timesync(); */

	qry->p->active--;
	qry->p->q_done++;


	/* if it is failed grand child qury do not print anything */
	if (qry->gc && qry->ssl_incomplete ){
		if(qry->err.size)
		{
			buf_cleanup(&qry->err);
		}
		return;
	}

	if (qry->result->size == 0){
		AS("RESULT { ");
		if(qry->p->str_Atlas) 
		{
			JS(id, qry->p->str_Atlas);
		}
		JD(fw, fw);
		JD(dnscout, qry->p->dns_count);
		JS1(time, %ld, qry->p->start_time.tv_sec);
		JD(lts,lts); // fix me take lts when I create start time.
		AS("\"resultset\" : [ {");
	}
	else {
		AS (",{");
	}

	if(qry->retry) {
		JD(retry, qry->retry);
	}

	JS1(time, %ld,  qry->start_time.tv_sec);
	JD(lts,lts);

	if (qry->addrstr[0] !=  '\0') {
		if(strcmp(qry->addrstr, qry->p->host)) {
			JS(dst_name, qry->p->host);
		}
		JS(dst_addr , qry->addrstr);

		if(qry->loc_sin6.sin6_family) {
			getnameinfo((struct sockaddr *)&qry->loc_sin6,
					qry->loc_socklen, addrstr, INET6_ADDRSTRLEN,
					NULL, 0, NI_NUMERICHOST);
			if(strlen(addrstr))
				JS(src_addr, addrstr);
			JD(af, qry->addr_curr->ai_family == PF_INET6 ? 6 : 4);
		}
	}
	else if (qry->p->host) {
		JS(dst_name, qry->p->host);
	}

	JS(ciphers, qry->cipher_list);
	JS_NC(version, qry->sslv_str);

	if ((qry->ssl_ctx != NULL) && (qry->ssl != NULL) && (qry->ssl_incomplete != 0)) {
		X509 *x509 = NULL;
		qry->p->q_success++;
		AS(","); 
		JS_NC(cipher, SSL_CIPHER_get_name(SSL_get_current_cipher(qry->ssl)));

		if ((qry->gc == FALSE) && (qry->p->opt_all_tests == TRUE))  {
			/* this is a successful child. 
			 * create grand children with algorithm varients 
			 */
			ssl_gc_init(qry);
		}		
		x509 = SSL_get_peer_certificate(qry->ssl);
		if (x509 != NULL) {
			BUF_MEM *bptr;
			int i;
		       	int j = 0;
			BIO *b64 = BIO_new (BIO_s_mem());
			printf ("check the cert \n");
			PEM_write_bio_X509(b64, x509);
			BIO_get_mem_ptr(b64, &bptr); 
			
			if (bptr->length < 0) {
				AS(", cert : [\""); 
				for (i  = 0; i < bptr->length;  i++) {
					if (bptr->data[i] == '\n') {
						AS("\\");
					}
					/* this could be more efficient ? */
					buf_add(qry->result, bptr->data[i], 1);
				} 
				AS("\""); 
			}
			
		}
	}

	if(qry->err.size) 
	{
		AS(", \"error\" : {");
		buf_add(qry->result, qry->err.buf, qry->err.size);
		AS("}"); 
	}

	AS (" }"); //result 
}

void print_ssl_resp(struct ssl_child *qry) {

	bool write_out = FALSE;
	struct timeval asap = { 0, 10 };
	FILE *fh;
	struct ssl_state *pqry = qry->p;

	fmt_ssl_resp(qry);
	evtimer_add(&qry->free_child_ev, &asap);

	if (qry->p->active < 1) {
		write_out = TRUE;
	}
	else {
		crondlog_aa(LVL5, "waiting for more %d queries", qry->p->active);
	}

	if(write_out) {
		write_out = TRUE;
		if (qry->p->done) 
			evtimer_add(&qry->p->done_ev, &asap);
	}

	if(write_out && qry->result->size) {
		/* end of result only JSON closing brackets from here on */
		AS("]");  /* resultset : [{}..] */

		AS (",");
		JD(queries, qry->p->q_serial);
		JD_NC(success, qry->p->q_success);
		AS (" }\n");   /* RESULT { } . end of RESULT line */
		
		if (qry->p->out_filename)
		{
			fh= fopen(qry->p->out_filename, "a");
			if (!fh) {
				crondlog(LVL8 "unable to append to '%s'",
						qry->p->out_filename);
			}
		}
		else
			fh = stdout;

		if (fh) {
			fwrite(qry->result->buf, qry->result->size, 1 , fh);
		}
		buf_cleanup(qry->result);

		if (qry->p->out_filename)
			fclose(fh);


		qry->p->state = STATUS_FREE;
		qry->retry = 0;
		asap.tv_usec *= 2;
		evtimer_add(&qry->free_pqry_ev, &asap);
	} 
	else {
		crondlog_aa(LVL7, "%s no output yet. %s %s active = %d %s %s",  __func__,
				qry->p->host, qry->addrstr, qry->p->active, qry->sslv_str, qry->cipher_list);
	}

}


bufferevent_data_cb event_cb(struct bufferevent *bev, short events, void *ptr)
{
	struct ssl_child *qry = ptr;
	struct timeval rectime ;
	if (events & BEV_EVENT_ERROR)
	{
		crondlog_aa(LVL7, "ERROR %s %s %s active = %d %s %s",  __func__,
				qry->p->host, qry->addrstr, qry->p->active, qry->sslv_str, qry->cipher_list);

		evtimer_del(&qry->timeout_ev);
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"connect\" : \"connect failed\"", qry->err.size ? ", " : "");
		buf_add(&qry->err, line, strlen(line));
		print_ssl_resp(qry);
		return;
	}

	if (events & BEV_EVENT_CONNECTED)
	{
		if (qry->loc_socklen == 0) {
			qry->loc_socklen= sizeof(qry->loc_sin6);
			getsockname(bufferevent_getfd(bev), &qry->loc_sin6, &qry->loc_socklen);
		}

		gettimeofday(&rectime, NULL);

		qry->triptime = (rectime.tv_sec - qry->start_time.tv_sec)*1000 +
			(rectime.tv_usec - qry->start_time.tv_usec)/1e3;

		crondlog_aa(LVL7, "BEV_EVENT_CONNECTED %s %s %s active = %d %s %s",  __func__,
				qry->p->host, qry->addrstr, qry->p->active, qry->sslv_str, qry->cipher_list);
		write_cb(qry->bev, qry);
		return;
	}
	else {
		printf (" called %s unknown event 0x%x\n", __func__, events);
	}
}

static void http_read_cb(struct bufferevent *bev UNUSED_PARAM, void *ptr)
{
	struct ssl_child  *qry = ptr;

	crondlog_aa(LVL7, "%s %s %s active = %d %s %s",  __func__,
			qry->p->host, qry->addrstr, qry->p->active, qry->sslv_str, qry->cipher_list);
	evtimer_del(&qry->timeout_ev);
	print_ssl_resp(qry);
	qry->ssl_incomplete = FALSE;
	bufferevent_free(qry->bev);
	qry->bev = NULL;
}
static void write_cb(struct bufferevent *bev, void *ptr)
{
	int r;
	struct evbuffer *output;
	off_t cLength;
	struct stat sb;
	struct timeval endtime;
	struct ssl_child *qry = ptr;

	// printf("%s: start:\n", __func__);
	
	for(;;)
	{
		switch(qry->writestate)
		{
		case WRITE_FIRST:
			gettimeofday(&endtime, NULL);
			qry->ttc= (endtime.tv_sec-
				qry->start_time.tv_sec)*1e3 +
				(endtime.tv_usec - qry->start_time.tv_usec)/1e3;
			qry->writestate= WRITE_HEADER;
			continue;
		case WRITE_HEADER:
			output= bufferevent_get_output(bev);
			evbuffer_add_printf(output, "%s %s HTTP/1.%c\r\n",
				qry->p->do_get ? "GET" :
				qry->p->do_head ? "HEAD" : "POST", qry->p->path,
				qry->p->do_http10 ? '0' : '1');
			evbuffer_add_printf(output, "Host: %s\r\n",
				qry->p->host);
			evbuffer_add_printf(output, "Connection: close\r\n");
			evbuffer_add_printf(output, "User-Agent: %s\r\n",
				qry->p->user_agent);
			evbuffer_add_printf(output, "\r\n");

			qry->writestate = WRITE_DONE;
			// printf("%s: done: \n", __func__);
			return;

		case WRITE_DONE:
			return;
		default:
			printf("writecb: unknown write state: %d\n",
				qry->writestate);
			return;
		}
	}
}

static void local_exit(void *state UNUSED_PARAM)
{

	struct timeval asap = { 0, 0 };
	fprintf(stderr, "And we are done\n");
	event_base_loopexit (EventBase,  &asap);
	return;
}

/* called only once. Initialize ssl_base variables here */
static void ssl_base_new(struct event_base *event_base)
{
	ssl_base = xzalloc(sizeof( struct ssl_base));
}

static bool ssl_arg_validate (int argc, char *argv[], struct ssl_state *pqry )
{
	if (optind != argc-1)  {
		crondlog(LVL9 "ERROR no server IP address in input");
		sslscan_delete(pqry);
		return FALSE;
	}
	else {
		pqry->host = strdup(argv[optind]); 
	}
	if (pqry->opt_all_tests ) {
		// pqry->opt_ssl_v3 = SSL3_VERSION;
		// pqry->opt_tls_v1 =  TLS1_VERSION;
		// pqry->opt_tls_v11 = TLS1_1_VERSION;
		pqry->opt_tls_v12 = TLS1_2_VERSION;
	} 
	return TRUE;
}

/* eperd call this to initialize */
static struct ssl_state * sslscan_init (int argc, char *argv[], void (*done)(void *state))
{
	int c;
	struct ssl_state *pqry = NULL;
	LogFile = "/dev/tty";

	if (ssl_base == NULL) {
		ssl_base_new(EventBase);
		RAND_poll();
		SSL_library_init(); /* call only once this is not reentrant. */
		ERR_load_crypto_strings();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();
	}

	if (ssl_base == NULL) {
		crondlog(LVL8 "ssl_base_new failed");
		return NULL;
	}

	/* initialize a query object */
	pqry = xzalloc(sizeof(struct ssl_state));
	pqry->opt_retry_max = 0;
	pqry->port = "443";
	pqry->opt_ignore_cert = 0;
	buf_init(&pqry->err, -1);
	buf_init(&pqry->result, -1);
	pqry->do_http10= 0;
	pqry->do_get= 0;
	pqry->do_head= 1;
	pqry->user_agent= "httpget for atlas.ripe.net";
	pqry->path = "/";
	pqry->result = xzalloc(sizeof(struct buf));
	pqry->done = done;
	pqry->opt_all_tests = FALSE;
	pqry->timeout_tv.tv_sec = 5;

	if (done != NULL)
		evtimer_assign(&pqry->done_ev, EventBase, done_cb, pqry);

	optind = 0;
	while (c= getopt_long(argc, argv, "46:A:?", longopts, NULL), c != -1) {
		switch (c) {
			case '4':
				pqry->opt_v4 = 1;
				break;
			case '6':
				pqry->opt_v6 = 1;
				break;

		}
	}

	if (!ssl_arg_validate(argc, argv, pqry))
	{
		crondlog(LVL8 "ssl_arg_validate failed");
		return NULL; 
	} 


	return pqry;
}
 
static bool ssl_child_init(struct ssl_state *pqry, struct evutil_addrinfo *addr_curr, int sslv) 
{

	pqry->active++;
	struct  ssl_child *qry = xzalloc(sizeof(struct ssl_child));
	qry->next = pqry->c;
	pqry->c = qry;
	qry->addr_curr = addr_curr;
	qry->p = pqry;
	qry->p->q_serial++;
	qry->serial =  qry->p->q_serial;
	qry->result = pqry->result;
	evtimer_assign(&qry->timeout_ev, EventBase, timeout_cb, qry);
	evtimer_assign(&qry->free_child_ev, EventBase, free_child_cb, qry);
	evtimer_assign(&qry->free_pqry_ev, EventBase, free_qry_inst_cb, qry);
	qry->sslv  = sslv;
	qry->ssl_incomplete = TRUE;
	ssl_child_start(qry, "ALL:COMPLEMENTOFALL");

}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	struct ssl_state *pqry = (struct ssl_state *) ctx;
	struct bufferevent *bev;
	struct evutil_addrinfo *cur;

	if (result != 0)
	{
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"EVDNS\" : \"%s\"",
				pqry->err.size ? ", " : "",
				evutil_gai_strerror(result));
		buf_add(&pqry->err, line, strlen(line));
		// buf_add(&pqry->err, line, strlen(line));
		// fixme print_ssl_resp(qry);
		return;
	}
	pqry->addr = res;
	pqry->dns_count =  0;

	for (cur = res; cur != NULL; cur = cur->ai_next) {
		pqry->dns_count++;
		if (pqry->opt_all_tests) {
			ssl_child_init(pqry, cur, pqry->opt_ssl_v3);
			ssl_child_init(pqry, cur, pqry->opt_tls_v1);
			ssl_child_init(pqry, cur, pqry->opt_tls_v11);
			ssl_child_init(pqry, cur, pqry->opt_tls_v12); 
		}
		else  {
			ssl_child_init(pqry, cur, 0);
		}
	}
}

/* entry point for eperd */
 
static void printErrorQuick (struct ssl_state *pqry) 
{
	FILE *fh;

	/* careful not to use json macros they will write over real results */

	struct timeval now;
	if (pqry->out_filename)
	{
		fh= fopen(pqry->out_filename, "a");
		if (!fh){
			crondlog(LVL8 "unable to append to '%s'",
					pqry->out_filename);
			return;
		}
	}
	else
		fh = stdout;

	fprintf(fh, "RESULT { ");
	fprintf(fh, "\"fw\" : \"%d\",", get_atlas_fw_version());
	fprintf(fh, "\"id\" : 9203 ,");
	gettimeofday(&now, NULL);
	fprintf(fh, "\"time\" : %ld ,",  now.tv_sec);

	fprintf(fh, "\"error\" : [{ ");
	fprintf(fh, "\"query busy\": \"not starting a new one. previous one is not done yet\"}");
	if(pqry->str_Atlas)
	{
		fprintf(fh, ",{");
		fprintf(fh, "\"id\" : \"%s\"",  pqry->str_Atlas);
		fprintf(fh, ",\"start time\" : %ld",  pqry->start_time.tv_sec);
		if(pqry->retry) {
			fprintf(fh, ",\"retry\": %d",  pqry->retry);

		}
		if(pqry->opt_retry_max) {
			fprintf(fh, ",\"retry max\": %d",  pqry->opt_retry_max);
		}
		fprintf(fh, "}");
	}
	fprintf(fh,"]}");


	if (pqry->out_filename)
		fclose(fh);
}

void sslscan_start (struct ssl_state *pqry)
{
	switch(pqry->state) 
	{
		case STATUS_FREE:
			pqry->state = STATUS_START;
			break;
		default:
			printErrorQuick(pqry);
			/* this query is still active. can't start another one */
			return;

	}

	gettimeofday(&pqry->start_time, NULL);

	pqry->hints.ai_family = AF_UNSPEC;
	
	if(pqry->opt_v6 && !pqry->opt_v4) 
		pqry->hints.ai_family = AF_INET6;

	if(pqry->opt_v4 && !pqry->opt_v6) 
		pqry->hints.ai_family = AF_INET;

	pqry->hints.ai_flags = 0;
	pqry->hints.ai_socktype = SOCK_STREAM;
	pqry->hints.ai_flags = 0;

	(void) evdns_getaddrinfo(DnsBase, pqry->host, "443", &pqry->hints,
			dns_cb, pqry);
} 

int evtlsscan_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evtlsscan_main(int argc, char **argv)
{
	struct ssl_state *qry = NULL;

	EventBase = event_base_new();
	if (!EventBase)
	{
		crondlog(LVL9 "ERROR: critical event_base_new failed"); /* exits */
	}

	DnsBase = evdns_base_new(EventBase, 1);
	if (!DnsBase) {
		crondlog(DIE9 "ERROR: critical evdns_base_new failed"); /* exits */
		event_base_free (EventBase);
		return 1;
	}

	qry = sslscan_init(argc, argv, local_exit);

	if(qry == NULL) {
		crondlog(DIE9 "ERROR: critical sslscan_init failed"); /* exits */
		event_base_free (EventBase);
		return 1;
	}

	sslscan_start(qry);

	event_base_dispatch(EventBase);
	event_base_loopbreak (EventBase);

	if(EventBase)
		event_base_free(EventBase);

	return 0;
}

static void crondlog_aa(const char *ctl, char *fmt, ...)
{
	va_list va;
	char buff[1000];
	va_start(va, fmt);
	vsnprintf(buff, 1000 - 1, fmt, va);
	printf("%s\n", buff);
}
