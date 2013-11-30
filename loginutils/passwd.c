/* vi: set sw=4 ts=4: */
/*
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//usage:#define passwd_trivial_usage
//usage:       "[OPTIONS] [USER]"
//usage:#define passwd_full_usage "\n\n"
//usage:       "Change USER's password (default: current user)"
//usage:     "\n"
//usage:     "\n	-a ALG	Encryption method"
//usage:     "\n	-d	Set password to ''"
//usage:     "\n	-l	Lock (disable) account"
//usage:     "\n	-u	Unlock (enable) account"

#include "libbb.h"
#include <syslog.h>
#include <sys/resource.h> /* setrlimit */

<<<<<<< HEAD
static char* new_password(const struct passwd *pw, uid_t myuid, const char *algo)
{
	char salt[MAX_PW_SALT_LEN];
	char *orig = (char*)"";
	char *newp = NULL;
	char *cp = NULL;
	char *ret = NULL; /* failure so far */

	if (myuid != 0 && pw->pw_passwd[0]) {
		char *encrypted;

		orig = bb_ask_stdin("Old password: "); /* returns ptr to static */
		if (!orig)
			goto err_ret;
		encrypted = pw_encrypt(orig, pw->pw_passwd, 1); /* returns malloced str */
		if (strcmp(encrypted, pw->pw_passwd) != 0) {
			syslog(LOG_WARNING, "incorrect password for %s", pw->pw_name);
			bb_do_delay(LOGIN_FAIL_DELAY);
			puts("Incorrect password");
			goto err_ret;
		}
		if (ENABLE_FEATURE_CLEAN_UP)
			free(encrypted);
	}
	orig = xstrdup(orig); /* or else bb_ask_stdin() will destroy it */
	newp = bb_ask_stdin("New password: "); /* returns ptr to static */
	if (!newp)
		goto err_ret;
	newp = xstrdup(newp); /* we are going to bb_ask_stdin() again, so save it */
	if (ENABLE_FEATURE_PASSWD_WEAK_CHECK
	 && obscure(orig, newp, pw)
	 && myuid != 0
	) {
		goto err_ret; /* non-root is not allowed to have weak passwd */
	}

	cp = bb_ask_stdin("Retype password: ");
	if (!cp)
		goto err_ret;
	if (strcmp(cp, newp) != 0) {
		puts("Passwords don't match");
		goto err_ret;
	}

	crypt_make_pw_salt(salt, algo);

=======

static char* new_password( int algo, char *pass)
{
	char salt[sizeof("$N$XXXXXXXX")]; /* "$N$XXXXXXXX" or "XX" */
	char *ret = NULL; /* failure so far */

	crypt_make_salt(salt, 1, 0); /* des */
	if (algo) { /* MD5 */
		strcpy(salt, "$1$");
		crypt_make_salt(salt + 3, 4, 0);
	}
>>>>>>> ripe-atlas-fw-4550
	/* pw_encrypt returns malloced str */
	ret = pw_encrypt(pass, salt, 1);
	/* whee, success! */

<<<<<<< HEAD
 err_ret:
	nuke_str(orig);
	if (ENABLE_FEATURE_CLEAN_UP) free(orig);

	nuke_str(newp);
	if (ENABLE_FEATURE_CLEAN_UP) free(newp);

	nuke_str(cp);
=======
>>>>>>> ripe-atlas-fw-4550
	return ret;
}

int passwd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int passwd_main(int argc UNUSED_PARAM, char **argv)
{
	enum {
		OPT_algo   = (1 << 0), /* -a - password algorithm */
		OPT_lock   = (1 << 1), /* -l - lock account */
		OPT_unlock = (1 << 2), /* -u - unlock account */
		OPT_delete = (1 << 3), /* -d - delete password */
		OPT_lud    = OPT_lock | OPT_unlock | OPT_delete,
	};
	unsigned opt;
	int rc;
	const char *opt_a = CONFIG_FEATURE_DEFAULT_PASSWD_ALGO;
	const char *filename;
	char *myname;
	char *name;
	char *newp;
	char *pass;
	struct passwd *pw;
	uid_t myuid;
	struct rlimit rlimit_fsize;
#if ENABLE_FEATURE_SHADOWPASSWDS
	/* Using _r function to avoid pulling in static buffers */
	struct spwd spw;
	char buffer[256];
#endif

	logmode = LOGMODE_BOTH;
	openlog(applet_name, 0, LOG_AUTH);
	opt = getopt32(argv, "a:lud", &opt_a);
	//argc -= optind;
	argv += optind;

	myuid = getuid();
	/* -l, -u, -d require root priv and username argument */
	if ((opt & OPT_lud) && (myuid != 0 || !argv[0]))
		bb_show_usage();

	/* Will complain and die if username not found */
<<<<<<< HEAD
	myname = xstrdup(xuid2uname(myuid));
	name = argv[0] ? argv[0] : myname;

	pw = xgetpwnam(name);
	if (myuid != 0 && pw->pw_uid != myuid) {
=======
	myname = xstrdup(bb_getpwuid(NULL, -1, myuid));

	if( argc<3 ) {
		bb_error_msg_and_die("You should supply a name ans a password");
	}

	name = argv[0];
	pass = argv[1];
	pw = getpwnam(name);
	if (!pw)
		bb_error_msg_and_die("unknown user %s", name);
	if (myuid && pw->pw_uid != myuid) {
>>>>>>> ripe-atlas-fw-4550
		/* LOGMODE_BOTH */
		bb_error_msg_and_die("%s can't change password for %s", myname, name);
	}

	newp = new_password( opt & STATE_ALGO_md5, pass);

#if ENABLE_FEATURE_SHADOWPASSWDS
	{
		/* getspnam_r may return 0 yet set result to NULL.
		 * At least glibc 2.4 does this. Be extra paranoid here. */
		struct spwd *result = NULL;
		errno = 0;
		if (getspnam_r(pw->pw_name, &spw, buffer, sizeof(buffer), &result) != 0
		 || !result /* no error, but no record found either */
		 || strcmp(result->sp_namp, pw->pw_name) != 0 /* paranoia */
		) {
			if (errno != ENOENT) {
				/* LOGMODE_BOTH */
				bb_perror_msg("no record of %s in %s, using %s",
					name, bb_path_shadow_file,
					bb_path_passwd_file);
			}
			/* else: /etc/shadow does not exist,
			 * apparently we are on a shadow-less system,
			 * no surprise there */
		} else {
			pw->pw_passwd = result->sp_pwdp;
		}
	}
#endif

<<<<<<< HEAD
	/* Decide what the new password will be */
	newp = NULL;
	c = pw->pw_passwd[0] - '!';
	if (!(opt & OPT_lud)) {
		if (myuid != 0 && !c) { /* passwd starts with '!' */
			/* LOGMODE_BOTH */
			bb_error_msg_and_die("can't change "
					"locked password for %s", name);
		}
		printf("Changing password for %s\n", name);
		newp = new_password(pw, myuid, opt_a);
		if (!newp) {
			logmode = LOGMODE_STDIO;
			bb_error_msg_and_die("password for %s is unchanged", name);
		}
	} else if (opt & OPT_lock) {
		if (!c)
			goto skip; /* passwd starts with '!' */
		newp = xasprintf("!%s", pw->pw_passwd);
	} else if (opt & OPT_unlock) {
		if (c)
			goto skip; /* not '!' */
		/* pw->pw_passwd points to static storage,
		 * strdup'ing to avoid nasty surprizes */
		newp = xstrdup(&pw->pw_passwd[1]);
	} else if (opt & OPT_delete) {
		newp = (char*)"";
	}

=======
>>>>>>> ripe-atlas-fw-4550
	rlimit_fsize.rlim_cur = rlimit_fsize.rlim_max = 512L * 30000;
	setrlimit(RLIMIT_FSIZE, &rlimit_fsize);
	bb_signals(0
		+ (1 << SIGHUP)
		+ (1 << SIGINT)
		+ (1 << SIGQUIT)
		, SIG_IGN);
	umask(077);
	xsetuid(0);

#if ENABLE_FEATURE_SHADOWPASSWDS
	filename = bb_path_shadow_file;
<<<<<<< HEAD
	rc = update_passwd(bb_path_shadow_file, name, newp, NULL);
	if (rc > 0)
		/* password in /etc/shadow was updated */
		newp = (char*) "x";
	if (rc >= 0)
		/* 0 = /etc/shadow missing (not an error), >0 = passwd changed in /etc/shadow */
=======
	rc = update_passwd(bb_path_shadow_file, name, newp );
	if (rc == 0) /* no lines updated, no errors detected */
>>>>>>> ripe-atlas-fw-4550
#endif
	{
		filename = bb_path_passwd_file;
		rc = update_passwd(bb_path_passwd_file, name, newp, NULL);
	}
	/* LOGMODE_BOTH */
	if (rc < 0)
		bb_error_msg_and_die("can't update password file %s", filename);
	bb_info_msg("Password for %s changed by %s", name, myname);

<<<<<<< HEAD
	/*if (ENABLE_FEATURE_CLEAN_UP) free(newp); - can't, it may be non-malloced */
 skip:
=======
	//if (ENABLE_FEATURE_CLEAN_UP) free(newp);

>>>>>>> ripe-atlas-fw-4550
	if (!newp) {
		bb_error_msg_and_die("password for %s is already %slocked",
			name, (opt & OPT_unlock) ? "un" : "");
	}

	if (ENABLE_FEATURE_CLEAN_UP)
		free(myname);
	return 0;
}
