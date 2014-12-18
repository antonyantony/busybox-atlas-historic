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
#include "openssl_hostname_validation.h"


#define SAFE_PREFIX ATLAS_DATA_NEW

#define DEFAULT_LINE_LENGTH 1024
#define DEFAULT_NOREPLY_TIMEOUT 5000
#define O_RETRY  200

struct ssl_base {
	struct event_base *event_base;
};

enum readstate { READ_FIRST, READ_STATUS, READ_HEADER, READ_BODY, READ_SIMPLE,
	READ_CHUNKED, READ_CHUNK_BODY, READ_CHUNK_END,
	READ_CHUNKED_TRAILER,
	READ_DONE };
enum writestate { WRITE_FIRST, WRITE_HEADER, WRITE_POST_HEADER,
	WRITE_POST_FILE, WRITE_POST_FOOTER, WRITE_DONE };

/* How to keep track of each user sslscan query */
struct ssl_state {
	char *host;
	char *str_Atlas;
	char *out_filename;

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

	int opt_retry_max;
	int opt_ignore_cert;
	int opt_rset;

	int opt_v4_only;
	int opt_v6_only;
	int opt_max_con; /* maximum concurrent queries per destination */
	int opt_max_bytes; /*  max size of output buffer */
	struct ssl_state *c;
};

struct ssl_child {
	/* per instance variables. Unshared after duplicate */
	int serial;  /* serial number of each additional query. First is zero */

	struct ssl_state *p; /* parent object */
	struct buf *result; /* all children share same result structure as parent */

	struct buf err;
	struct bufferevent *bev_tcp;

	SSL_CTX *ssl_ctx; 
	SSL *ssl;
	struct bufferevent *bev;
	struct evutil_addrinfo *addr_curr;

	struct timeval start_time;
	double triptime;
	double ttc;
	int retry;

	struct event  timeout;
	struct evutil_addrinfo hints;
	enum readstate readstate;
	enum writestate writestate;
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

void print_ssl_resp(struct ssl_child *qry) {
	FILE *fh;
	char addrstr[INET6_ADDRSTRLEN];
        char dst_addr_str[(INET6_ADDRSTRLEN+1)];
	void *ptr = NULL;
	bool write_out = FALSE;

	int fw = get_atlas_fw_version();
	int lts =  -1 ;//get_timesync();

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

	JS1(time, %ld,  qry->start_time.tv_sec);
	JD(lts,lts);

	if (qry->addr_curr->ai_family && qry->p->host){

		switch (qry->addr_curr->ai_family) 
		{
			case AF_INET: 
				ptr = &((struct sockaddr_in *) qry->addr_curr->ai_addr)->sin_addr;
			break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6 *) qry->addr_curr->ai_addr)->sin6_addr; 
			break; 
		}
		inet_ntop (qry->addr_curr->ai_family, ptr, addrstr, INET6_ADDRSTRLEN);
		if(strcmp(addrstr, qry->p->host)) {
			JS(dst_name, qry->p->host);
		}
		JS(dst_addr , addrstr);
		// JD(af, qry->addr_curr->ai_family == PF_INET6 ? 6 : 4);
	}
	else if (qry->p->host) {
		JS(dst_name, qry->p->host);
	}

	if (qry->ssl_ctx != NULL) {
		JS(cipher, SSL_CIPHER_get_name(SSL_get_current_cipher(qry->ssl)));
		JS(version, SSL_CIPHER_get_version(SSL_get_current_cipher(qry->ssl)));
	}

	if(qry->retry) {
		JS1(retry, %d,  qry->retry);
	}

	if(qry->err.size) 
	{
		AS(", \"error\" : {");
		buf_add(qry->result, qry->err.buf, qry->err.size);
		AS("}"); 
	}
	AS (" }"); //result 

	qry->p->active--;

	if (qry->p->active < 1) {
		write_out = TRUE;
	}

	if(write_out && qry->result->size){
		/* end of result only JSON closing brackets from here on */
		AS("]");  /* resultset : [{}..] */

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
			AS (" }\n");   /* RESULT { } */
			fwrite(qry->result->buf, qry->result->size, 1 , fh);
		}
		buf_cleanup(qry->result);

		if (qry->p->out_filename)
			fclose(fh);
	}

	qry->retry = 0;
	//free_qry_inst(qry);
}

static void timeout_cb(int unused  UNUSED_PARAM, const short event
		UNUSED_PARAM, void *h)
{
	struct ssl_child *qry = h;
	crondlog(LVL9, "timeout called");
	printf("timeout called");
	event_base_loopexit(EventBase, NULL);
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
	if (qry->opt_ignore_cert) {
		return 1;
	}
	*/

	ok_so_far = X509_verify_cert(x509_ctx);

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

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


/* Initialize a struct timeval by converting milliseconds */
static void msecstotv(time_t msecs, struct timeval *tv)
{
	tv->tv_sec  = msecs / 1000;
	tv->tv_usec = msecs % 1000 * 1000;
}

bufferevent_data_cb event_cb(struct bufferevent *bev, short events, void *ptr)
{
	struct ssl_child *qry = ptr;
	struct timeval rectime ;

	if (events & BEV_EVENT_CONNECTED)
	{
		gettimeofday(&rectime, NULL);

		qry->triptime = (rectime.tv_sec - qry->start_time.tv_sec)*1000 +
			(rectime.tv_usec - qry->start_time.tv_usec)/1e3;

		printf (" called %s event BEV_EVENT_CONNECTED 0x%02x\n", __func__, events);
		write_cb(qry->bev, qry);
		//print_ssl_resp(qry);
		//bufferevent_free(bev);
		//event_base_loopexit(EventBase, NULL);
		return;
	}
	else {
		printf (" called %s unknown event 0x%02x\n", __func__, events);
	}
}

static void http_read_cb(struct bufferevent *bev UNUSED_PARAM, void *ptr)
{
	struct ssl_state  *qry = ptr;
	fprintf(stderr, " got read call the rest should be fine %s \n", __func__);
	print_ssl_resp(qry);
	bufferevent_free(bev);
	event_base_loopexit(EventBase, NULL);
}
static void write_cb(struct bufferevent *bev, void *ptr)
{
	int r;
	struct evbuffer *output;
	off_t cLength;
	struct stat sb;
	struct timeval endtime;
	struct ssl_child *qry = ptr;

	printf("%s: start:\n", __func__);

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
			printf("%s: done: \n", __func__);
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
	fprintf(stderr, "And we are done\n");
	exit(0);
}

/* called only once. Initialize ssl_base variables here */
static void ssl_base_new(struct event_base *event_base)
{
	ssl_base = xzalloc(sizeof( struct ssl_base));
}

static void ssl_delete (struct ssl_child *qry )
{
}

static bool ssl_arg_validate (int argc, char *argv[], struct ssl_child *qry )
{
	if (optind != argc-1)  {
		crondlog(LVL9 "ERROR no server IP address in input");
		ssl_delete(qry);
		return FALSE;
	}
	else {
		qry->p->host = strdup(argv[optind]); 
	}
	return TRUE;
}

/* eperd call this to initialize */
static struct ssl_state * sslscan_init (int argc, char *argv[], void (*done)(void *state))
{
	int c;
	struct ssl_state *pqry = NULL;
	LogFile = "/dev/tty";

	if (ssl_base == NULL)
		ssl_base_new(EventBase);

	if (ssl_base == NULL) {
		crondlog(LVL8 "ssl_base_new failed");
		return NULL;
	}

	/* initialize a query object */
	pqry = xzalloc(sizeof(*qry));
	pqry->retry  = 0;
	pqry->opt_retry_max = 0;
	pqry->opt_rset = 1;
	pqry->port = "443";
	pqry->opt_ignore_cert = 0;
	buf_init(&pqry->err, -1);
	buf_init(&pqry->result, -1);
	pqry->do_http10= 0;
	pqry->do_get= 0;
	pqry->do_head= 1;
	pqry->user_agent= "httpget for atlas.ripe.net";
	pqry->path = "/";
	pqry->ttc = 0;
	pqry->triptime = 0;
	pqry->result = xzalloc(sizeof(struct buf));
	pqry->ref_cnt = xzalloc(sizeof(int));

	optind = 0;
	while (c= getopt_long(argc, argv, "46:A:?", longopts, NULL), c != -1) {
		switch (c) {
		}
	}

	if (!ssl_arg_validate(argc, argv, pqry))
	{
		crondlog(LVL8 "ssl_arg_validate failed");
		return NULL; 
	} 

	evtimer_assign(&qry->timeout, EventBase, timeout_cb, pqry);

	return pqry;
}
                
static bool ssl_child_init(struct ssl_state pqry, struct evutil_addrinfo *addr_curr) 
{
	struct  ssl_child *qry = xzalloc(sizeof(struct ssl_child));
	qry->serial = 0;
	if (pqry->c != NULL) {
		c->serial = pqry->next->serial + 1;
	}
	c->next = pqry->c;
	pqry->c = c;
	c->addr_curr = addr_curr;
	c->p = pqry;
}

static void dns_cb(int result, struct evutil_addrinfo *res, void *ctx)
{
	struct ssl_parent *pqry = (struct ssl_state *) ctx;
	struct bufferevent *bev;
	struct evutil_addrinfo *cur;

	if (result != 0)
	{
		snprintf(line, DEFAULT_LINE_LENGTH, "%s \"EVDNS\" : \"%s\"",
				pqry->err.size ? ", " : "",
				evutil_gai_strerror(result));
		buf_add(&qry->err, line, strlen(line));
		print_ssl_resp(pqry);
		buf_add(&pqry->err, line, strlen(line));
		// fixme print_ssl_resp(qry);
		return;
	}
	pqry->addr = res;
	pqry->dns_count =  0;
	pqry->serial = 1;

	for (cur = res; cur != NULL; cur = cur->ai_next) {
		pqry->dns_count++;
		pqry->active++; // fixme to check max allowed queries
		ssl_child_init(pqry, cur);
		if (qry->c != NULL) {
			ssl_q_start(pqry->c);
		}
	}
}

/* entry point for eperd */
 
void ssl_start (struct ssl_state *pqry)
{
	gettimeofday(&pqry->start_time, NULL);
	pqry->hints.ai_family = AF_UNSPEC;
	pqry->hints.ai_flags = 0;
	pqry->hints.ai_socktype = SOCK_STREAM;
	pqry->hints.ai_flags = 0;

	(void) evdns_getaddrinfo(DnsBase, pqry->host, "443", &qry->hints,
			dns_cb, qry);
} 

void ssl_q_start (struct ssl_child *qry) 
{
	int r = RAND_poll();

	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	if (r == 0) {
		crondlog(LVL9, "RAND_poll");
	}

	/* Create a new OpenSSL context */
	// qry->ssl_ctx = SSL_CTX_new(SSLv23_method());
	
	qry->ssl_ctx = SSL_CTX_new(TLSv1_method());


//	SSL_CTX_set_cipher_list(qry->ssl_ctx, "ALL:COMPLEMENTOFALL");
	SSL_CTX_set_cipher_list(qry->ssl_ctx, "HIGH");

	if (!qry->ssl_ctx)
		crondlog(LVL9, "SSL_CTX_new");

	/* TODO: Add certificate loading on Windows as well */

	/* Attempt to use the system's trusted root certificates.
	 * (This path is only valid for Debian-based systems.) */
	 if (1 != SSL_CTX_load_verify_locations(qry->ssl_ctx, "/etc/ssl/certs/ca-certificates.crt", NULL)) crondlog(LVL7,"SSL_CTX_load_verify_locations");
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
	SSL_CTX_set_cert_verify_callback (qry->ssl_ctx, cert_verify_callback, (void *) qry->host);
	


	qry->ssl = SSL_new(qry->ssl_ctx);
	if (qry->ssl == NULL) {
		crondlog(LVL9, "SSL_new()");
	}

	// Set hostname for SNI extension
	SSL_set_tlsext_host_name(qry->ssl, qry->host);

	msecstotv(DEFAULT_NOREPLY_TIMEOUT, &qry->timeout_tv);

	evtimer_add(&qry->timeout, &qry->timeout_tv);

	qry->bev = bufferevent_openssl_socket_new(EventBase, -1, qry->ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE);

	//bufferevent_openssl_set_allow_dirty_shutdown(qry->bev, 1);
	bufferevent_setcb(qry->bev, http_read_cb, write_cb, event_cb, qry);

	if (bufferevent_socket_connect(qry->bev,
				qry->addr_curr->ai_addr,
				qry->addr_curr->ai_addrlen)) {
		crondlog(LVL9, "bufferevent_socket_connect error");
		bufferevent_free(qry->bev);
	}
	else{
		gettimeofday(&qry->start_time, NULL);
		/* AA fixme error */
	}

	if (r < 0) {
		warnx("could not connect to %s : %s", qry->host,
				evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		bufferevent_free(qry->bev);
		return;
	}
	return;
}

int evsslscan_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int evsslscan_main(int argc, char **argv)
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

	ssl_start(qry);

	event_base_dispatch(EventBase);
	event_base_loopbreak (EventBase);

	if(EventBase)
		event_base_free(EventBase);

	return 0;
}
