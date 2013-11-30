/* vi: set sw=4 ts=4: */
/*
 * perd formerly crond but now heavily hacked for Atlas
 *
 * crond -d[#] -c <crondir> -f -b
 *
 * run as root, but NOT setuid root
 *
 * Copyright 1994 Matthew Dillon (dillon@apollo.west.oic.com)
 * (version 2.3.2)
 * Vladimir Oleynik <dzo@simtreas.ru> (C) 2002
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//usage:#define crond_trivial_usage
//usage:       "-fbS -l N " IF_FEATURE_CROND_D("-d N ") "-L LOGFILE -c DIR"
//usage:#define crond_full_usage "\n\n"
//usage:       "	-f	Foreground"
//usage:     "\n	-b	Background (default)"
//usage:     "\n	-S	Log to syslog (default)"
//usage:     "\n	-l	Set log level. 0 is the most verbose, default 8"
//usage:	IF_FEATURE_CROND_D(
//usage:     "\n	-d	Set log level, log to stderr"
//usage:	)
//usage:     "\n	-L	Log to file"
//usage:     "\n	-c	Working dir"

#include "libbb.h"
#include <syslog.h>

#define ATLAS 1
#define ATLAS_NEW_FORMAT 1

#define DBQ(str) "\"" #str "\""

/* glibc frees previous setenv'ed value when we do next setenv()
 * of the same variable. uclibc does not do this! */
#if (defined(__GLIBC__) && !defined(__UCLIBC__)) /* || OTHER_SAFE_LIBC... */
# define SETENV_LEAKS 0
#else
# define SETENV_LEAKS 1
#endif


<<<<<<< HEAD:miscutils/crond.c
#define TMPDIR          CONFIG_FEATURE_CROND_DIR
#define CRONTABS        CONFIG_FEATURE_CROND_DIR "/crontabs"
#ifndef SENDMAIL
# define SENDMAIL       "sendmail"
#endif
#ifndef SENDMAIL_ARGS
# define SENDMAIL_ARGS  "-ti"
=======
#ifndef CRONTABS
#define CRONTABS        "/var/spool/cron/crontabs"
#endif
#ifndef TMPDIR
#define TMPDIR          "/var/spool/cron"
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
#endif
#ifndef CRONUPDATE
# define CRONUPDATE     "cron.update"
#endif
#ifndef MAXLINES
# define MAXLINES       256  /* max lines in non-root crontabs */
#endif

#ifdef ATLAS
#include <cmdtable.h>

#define SAFE_PREFIX ATLAS_DATA_NEW
#endif

#if ATLAS_NEW_FORMAT
#define URANDOM_DEV	"/dev/urandom"
#endif


typedef struct CronFile {
<<<<<<< HEAD:miscutils/crond.c
	struct CronFile *cf_next;
	struct CronLine *cf_lines;
	char *cf_username;
	smallint cf_wants_starting;     /* bool: one or more jobs ready */
	smallint cf_has_running;        /* bool: one or more jobs running */
	smallint cf_deleted;            /* marked for deletion (but still has running jobs) */
} CronFile;

typedef struct CronLine {
	struct CronLine *cl_next;
	char *cl_cmd;                   /* shell command */
	pid_t cl_pid;                   /* >0:running, <0:needs to be started in this minute, 0:dormant */
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
	int cl_empty_mail_size;         /* size of mail header only, 0 if no mailfile */
	char *cl_mailto;                /* whom to mail results, may be NULL */
#endif
	/* ordered by size, not in natural order. makes code smaller: */
	char cl_Dow[7];                 /* 0-6, beginning sunday */
	char cl_Mons[12];               /* 0-11 */
	char cl_Hrs[24];                /* 0-23 */
	char cl_Days[32];               /* 1-31 */
	char cl_Mins[60];               /* 0-59 */
=======
	struct CronFile *cf_Next;
	struct CronLine *cf_LineBase;
	char *cf_User;                  /* username                     */
	smallint cf_Ready;              /* bool: one or more jobs ready */
	smallint cf_Running;            /* bool: one or more jobs running */
	smallint cf_ToBeDeleted;        /* marked for deletion, ignore  */
	smallint cf_Deleted;            /* deleted but some entries are
					 * still busy
					 */
} CronFile;

typedef struct CronLine {
	struct CronLine *cl_Next;
	char *cl_Shell;         /* shell command                        */
	pid_t cl_Pid;           /* running pid, 0, or armed (-1)        */
#if ATLAS_NEW_FORMAT
	unsigned interval;
	time_t nextcycle;
	time_t start_time;
	time_t end_time;
	enum distribution { DISTR_NONE, DISTR_UNIFORM } distribution;
	int distr_param;	/* Parameter for distribution, if any */
	int distr_offset;	/* Current offset to randomize the interval */

	/* For debugging */
	time_t lasttime;
#else
	/* ordered by size, not in natural order. makes code smaller: */
	char cl_Dow[7];         /* 0-6, beginning sunday                */
	char cl_Mons[12];       /* 0-11                                 */
	char cl_Hrs[24];        /* 0-23                                 */
	char cl_Days[32];       /* 1-31                                 */
	char cl_Mins[60];       /* 0-59                                 */
#endif /* ATLAS_NEW_FORMAT */
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
} CronLine;


#define DAEMON_UID 0


enum {
	OPT_l = (1 << 0),
	OPT_L = (1 << 1),
	OPT_f = (1 << 2),
	OPT_b = (1 << 3),
	OPT_S = (1 << 4),
	OPT_c = (1 << 5),
	OPT_A = (1 << 6),
	OPT_D = (1 << 7),
	OPT_d = (1 << 8) * ENABLE_FEATURE_CROND_D,
};
#if ENABLE_FEATURE_CROND_D
# define DebugOpt (option_mask32 & OPT_d)
#else
# define DebugOpt 0
#endif


struct globals {
<<<<<<< HEAD:miscutils/crond.c
	unsigned log_level; /* = 8; */
	time_t crontab_dir_mtime;
	const char *log_filename;
	const char *crontab_dir_name; /* = CRONTABS; */
	CronFile *cron_files;
=======
	unsigned LogLevel; /* = 8; */
	const char *LogFile;
	const char *CDir; /* = CRONTABS; */
	CronFile *FileBase;
	CronFile *oldFile;
	CronLine *oldLine;
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
#if SETENV_LEAKS
	char *env_var_user;
	char *env_var_home;
#endif
<<<<<<< HEAD:miscutils/crond.c
} FIX_ALIASING;
#define G (*(struct globals*)&bb_common_bufsiz1)
=======
};
#ifdef ATLAS
static struct globals G;
#else
#define G (*(struct globals*)&bb_common_bufsiz1)
#endif
#define LogLevel           (G.LogLevel               )
#define LogFile            (G.LogFile                )
#define CDir               (G.CDir                   )
#define FileBase           (G.FileBase               )
#define oldFile            (G.oldFile                )
#define oldLine            (G.oldLine                )
#define env_var_user       (G.env_var_user           )
#define env_var_home       (G.env_var_home           )
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
#define INIT_G() do { \
	G.log_level = 8; \
	G.crontab_dir_name = CRONTABS; \
} while (0)

#ifdef ATLAS
static int do_kick_watchdog;
static char *atlas_id= NULL;
static char *out_filename= NULL;

static int atlas_run(char *cmdline);
#endif

<<<<<<< HEAD:miscutils/crond.c
/* 0 is the most verbose, default 8 */
=======
static void CheckUpdates(void);
static void SynchronizeDir(void);
#if ATLAS_NEW_FORMAT
static int TestJobs(time_t *nextp);
#else
static int TestJobs(time_t t1, time_t t2);
#endif
static void RunJobs(void);
static int CheckJobs(void);
static void RunJob(const char *user, CronLine *line);
#define EndJob(user, line)  ((line)->cl_Pid = 0)
static void DeleteFile(CronFile *tfile);
static void SetOld(const char *userName);
static void CopyFromOld(CronLine *line);


>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
#define LVL5  "\x05"
#define LVL7  "\x07"
#define LVL8  "\x08"
#define WARN9 "\x49"
#define DIE9  "\xc9"
/* level >= 20 is "error" */
#define ERR20 "\x14"

static void crondlog(const char *ctl, ...) __attribute__ ((format (printf, 1, 2)));
static void crondlog(const char *ctl, ...)
{
	va_list va;
	int level = (ctl[0] & 0x1f);

	va_start(va, ctl);
	if (level >= (int)G.log_level) {
		/* Debug mode: all to (non-redirected) stderr, */
		/* Syslog mode: all to syslog (logmode = LOGMODE_SYSLOG), */
		if (!DebugOpt && G.log_filename) {
			/* Otherwise (log to file): we reopen log file at every write: */
			int logfd = open_or_warn(G.log_filename, O_WRONLY | O_CREAT | O_APPEND);
			if (logfd >= 0)
				xmove_fd(logfd, STDERR_FILENO);
		}
		/* When we log to syslog, level > 8 is logged at LOG_ERR
		 * syslog level, level <= 8 is logged at LOG_INFO. */
		if (level > 8) {
			bb_verror_msg(ctl + 1, va, /* strerr: */ NULL);
		} else {
			char *msg = NULL;
			vasprintf(&msg, ctl + 1, va);
			bb_info_msg("%s: %s", applet_name, msg);
			free(msg);
		}
	}
	va_end(va);
	if (ctl[0] & 0x80)
		exit(20);
}

<<<<<<< HEAD:miscutils/crond.c
=======
static void my_exit(void)
{
	crondlog(LVL8 "in my_exit (exit was called!)");
	abort();
}

static void kick_watchdog(void)
{
	if(do_kick_watchdog) 
	{
		int fdwatchdog = open("/dev/watchdog", O_RDWR);
		write(fdwatchdog, "1", 1);
		close(fdwatchdog);
	}
}

int perd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int perd_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned opt;
#if ATLAS_NEW_FORMAT
	int fd;
	unsigned seed;
#endif

	const char *PidFileName = NULL;
	atexit(my_exit);

	INIT_G();

	/* "-b after -f is ignored", and so on for every pair a-b */
	opt_complementary = "f-b:b-f:S-L:L-S" USE_FEATURE_PERD_D(":d-l")
			":l+:d+"; /* -l and -d have numeric param */
	opt = getopt32(argv, "l:L:fbSc:A:DP:" USE_FEATURE_PERD_D("d:") "O:",
			&LogLevel, &LogFile, &CDir, &atlas_id, &PidFileName
			USE_FEATURE_PERD_D(,&LogLevel), &out_filename);
	/* both -d N and -l N set the same variable: LogLevel */

	if (!(opt & OPT_f)) {
		/* close stdin, stdout, stderr.
		 * close unused descriptors - don't need them. */
		bb_daemonize_or_rexec(DAEMON_CLOSE_EXTRA_FDS, argv);
	}

	if (!DebugOpt && LogFile == NULL) {
		/* logging to syslog */
		openlog(applet_name, LOG_CONS | LOG_PID, LOG_LOCAL6);
		logmode = LOGMODE_SYSLOG;
	}

	do_kick_watchdog= !!(opt & OPT_D);

	xchdir(CDir);
	//signal(SIGHUP, SIG_IGN); /* ? original crond dies on HUP... */
	xsetenv("SHELL", DEFAULT_SHELL); /* once, for all future children */
	crondlog(LVL9 "crond (busybox "BB_VER") started, log level %d", LogLevel);

#if ATLAS_NEW_FORMAT
	fd= open(URANDOM_DEV, O_RDONLY);

	/* Best effort, just ignore errors */
	if (fd != -1)
	{
		read(fd, &seed, sizeof(seed));
		close(fd);
	}
	crondlog(LVL7 "using seed '%u'", seed);
	srandom(seed);
#endif

	SynchronizeDir();

	/* main loop - synchronize to 1 second after the minute, minimum sleep
	 * of 1 second. */
	{
		time_t t1 = time(NULL);
#if ATLAS_NEW_FORMAT
		time_t next;
		time_t last_minutely= 0;
		time_t last_hourly= 0;
#else
		time_t t2;
		long dt;
		int rescan = 60;
#endif
		int sleep_time = 10; /* AA previously 60 */
		if(PidFileName)
		{
			write_pidfile(PidFileName);
		}
		else 
		{
			write_pidfile("/var/run/crond.pid");
		}
		for (;;) {
			kick_watchdog();
#if ATLAS_NEW_FORMAT
			sleep(sleep_time);
#else
			sleep((sleep_time + 1) - (time(NULL) % sleep_time));
#endif

			kick_watchdog();

#if ATLAS_NEW_FORMAT
			if (t1 >= last_minutely + 60)
			{
				last_minutely= t1;
				CheckUpdates();
			}
			if (t1 >= last_hourly + 3600)
			{
				last_hourly= t1;
				SynchronizeDir();
			}
#else
			t2 = time(NULL);
			dt = (long)t2 - (long)t1;

			/*
			 * The file 'cron.update' is checked to determine new cron
			 * jobs.  The directory is rescanned once an hour to deal
			 * with any screwups.
			 *
			 * check for disparity.  Disparities over an hour either way
			 * result in resynchronization.  A reverse-indexed disparity
			 * less then an hour causes us to effectively sleep until we
			 * match the original time (i.e. no re-execution of jobs that
			 * have just been run).  A forward-indexed disparity less then
			 * an hour causes intermediate jobs to be run, but only once
			 * in the worst case.
			 *
			 * when running jobs, the inequality used is greater but not
			 * equal to t1, and less then or equal to t2.
			 */
			if (--rescan == 0) {
				rescan = 60;
				SynchronizeDir();
			}
			CheckUpdates();
			if (DebugOpt)
				crondlog(LVL5 "wakeup dt=%ld", dt);
			if (dt < -60 * 60 || dt > 60 * 60) {
				crondlog(WARN9 "time disparity of %d minutes detected", dt / 60);
			} else if (dt > 0)
#endif /* ATLAS_NEW_FORMAT */
			{
#if ATLAS_NEW_FORMAT
				sleep_time= 60;
				if (do_kick_watchdog)
					sleep_time= 10;
				TestJobs(&next);
				crondlog(LVL7 "got next %d, now %d",
					next, time(NULL));
				if (!next)
				{
					crondlog(LVL7 "calling RunJobs at %d",
						time(NULL));
					RunJobs();
					crondlog(LVL7 "RunJobs ended at %d",
						time(NULL));
					sleep_time= 1;
				} else if (next > t1 && next < t1+sleep_time)
					sleep_time= next-t1;
				if (CheckJobs() > 0) {
					sleep_time = 10;
				}
				crondlog(
				LVL7 "t1 = %d, next = %d, sleep_time = %d",
					t1, next, sleep_time);
#else
				TestJobs(t1, t2);
				RunJobs();
				sleep(4);
				if (CheckJobs() > 0) {
					sleep_time = 10;
				} else {
					sleep_time = 10; /* AA previously 60 */
				}
#endif
			}
#if ATLAS_NEW_FORMAT
			t1= time(NULL);
#else
			t1 = t2;
#endif
		}
	}
	return 0; /* not reached */
}

#if SETENV_LEAKS
/* We set environment *before* vfork (because we want to use vfork),
 * so we cannot use setenv() - repeated calls to setenv() may leak memory!
 * Using putenv(), and freeing memory after unsetenv() won't leak */
static void safe_setenv4(char **pvar_val, const char *var, const char *val /*, int len*/)
{
	const int len = 4; /* both var names are 4 char long */
	char *var_val = *pvar_val;

	if (var_val) {
		var_val[len] = '\0'; /* nuke '=' */
		unsetenv(var_val);
		free(var_val);
	}
	*pvar_val = xasprintf("%s=%s", var, val);
	putenv(*pvar_val);
}
#endif

static void SetEnv(struct passwd *pas)
{
#if SETENV_LEAKS
	safe_setenv4(&env_var_user, "USER", pas->pw_name);
	safe_setenv4(&env_var_home, "HOME", pas->pw_dir);
	/* if we want to set user's shell instead: */
	/*safe_setenv(env_var_user, "SHELL", pas->pw_shell, 5);*/
#else
	xsetenv("USER", pas->pw_name);
	xsetenv("HOME", pas->pw_dir);
#endif
	/* currently, we use constant one: */
	/*setenv("SHELL", DEFAULT_SHELL, 1); - done earlier */
}

static void ChangeUser(struct passwd *pas)
{
	/* careful: we're after vfork! */
	change_identity(pas); /* - initgroups, setgid, setuid */
	if (chdir(pas->pw_dir) < 0) {
		crondlog(LVL9 "can't chdir(%s)", pas->pw_dir);
		if (chdir(TMPDIR) < 0) {
			crondlog(DIE9 "can't chdir(%s)", TMPDIR); /* exits */
		}
	}
}

>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
static const char DowAry[] ALIGN1 =
	"sun""mon""tue""wed""thu""fri""sat"
	/* "Sun""Mon""Tue""Wed""Thu""Fri""Sat" */
;

static const char MonAry[] ALIGN1 =
	"jan""feb""mar""apr""may""jun""jul""aug""sep""oct""nov""dec"
	/* "Jan""Feb""Mar""Apr""May""Jun""Jul""Aug""Sep""Oct""Nov""Dec" */
;

#if !ATLAS_NEW_FORMAT
static void ParseField(char *user, char *ary, int modvalue, int off,
				const char *names, char *ptr)
/* 'names' is a pointer to a set of 3-char abbreviations */
{
	char *base = ptr;
	int n1 = -1;
	int n2 = -1;

	// this can't happen due to config_read()
	/*if (base == NULL)
		return;*/

	while (1) {
		int skip = 0;

		/* Handle numeric digit or symbol or '*' */
		if (*ptr == '*') {
			n1 = 0;  /* everything will be filled */
			n2 = modvalue - 1;
			skip = 1;
			++ptr;
		} else if (isdigit(*ptr)) {
			char *endp;
			if (n1 < 0) {
				n1 = strtol(ptr, &endp, 10) + off;
			} else {
				n2 = strtol(ptr, &endp, 10) + off;
			}
			ptr = endp; /* gcc likes temp var for &endp */
			skip = 1;
		} else if (names) {
			int i;

			for (i = 0; names[i]; i += 3) {
				/* was using strncmp before... */
				if (strncasecmp(ptr, &names[i], 3) == 0) {
					ptr += 3;
					if (n1 < 0) {
						n1 = i / 3;
					} else {
						n2 = i / 3;
					}
					skip = 1;
					break;
				}
			}
		}

		/* handle optional range '-' */
		if (skip == 0) {
			goto err;
		}
		if (*ptr == '-' && n2 < 0) {
			++ptr;
			continue;
		}

		/*
		 * collapse single-value ranges, handle skipmark, and fill
		 * in the character array appropriately.
		 */
		if (n2 < 0) {
			n2 = n1;
		}
		if (*ptr == '/') {
			char *endp;
			skip = strtol(ptr + 1, &endp, 10);
			ptr = endp; /* gcc likes temp var for &endp */
		}

		/*
		 * fill array, using a failsafe is the easiest way to prevent
		 * an endless loop
		 */
		{
			int s0 = 1;
			int failsafe = 1024;

			--n1;
			do {
				n1 = (n1 + 1) % modvalue;

				if (--s0 == 0) {
					ary[n1 % modvalue] = 1;
					s0 = skip;
				}
				if (--failsafe == 0) {
					goto err;
				}
			} while (n1 != n2);
		}
		if (*ptr != ',') {
			break;
		}
		++ptr;
		n1 = -1;
		n2 = -1;
	}

	if (*ptr) {
 err:
		crondlog(WARN9 "user %s: parse error at %s", user, base);
		return;
	}

	if (DebugOpt && (G.log_level <= 5)) { /* like LVL5 */
		/* can't use crondlog, it inserts '\n' */
		int i;
		for (i = 0; i < modvalue; ++i)
			fprintf(stderr, "%d", (unsigned char)ary[i]);
		bb_putchar_stderr('\n');
	}
}
#endif /* !ATLAS_NEW_FORMAT */

#if !ATLAS_NEW_FORMAT
static void FixDayDow(CronLine *line)
{
	unsigned i;
	int weekUsed = 0;
	int daysUsed = 0;

	for (i = 0; i < ARRAY_SIZE(line->cl_Dow); ++i) {
		if (line->cl_Dow[i] == 0) {
			weekUsed = 1;
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(line->cl_Days); ++i) {
		if (line->cl_Days[i] == 0) {
			daysUsed = 1;
			break;
		}
	}
	if (weekUsed != daysUsed) {
		if (weekUsed)
			memset(line->cl_Days, 0, sizeof(line->cl_Days));
		else /* daysUsed */
			memset(line->cl_Dow, 0, sizeof(line->cl_Dow));
	}
}
#endif /* !ATLAS_NEW_FORMAT */

static void do_distr(CronLine *line)
{
	long n, r, modulus, max;

	line->distr_offset= 0;		/* Safe default */
	if (line->distribution == DISTR_UNIFORM)
	{
		/* Generate a random number in the range [0..distr_param] */
		modulus= line->distr_param+1;
		n= LONG_MAX/modulus;
		max= n*modulus;
		do
		{
			r= random();
		} while (r >= max);
		r %= modulus;
		line->distr_offset= r - line->distr_param/2;
	}
	crondlog(LVL7 "do_distr: using %d", line->distr_offset);
}

/*
 * delete_cronfile() - delete user database
 *
 * Note: multiple entries for same user may exist if we were unable to
 * completely delete a database due to running processes.
 */
//FIXME: we will start a new job even if the old job is running
//if crontab was reloaded: crond thinks that "new" job is different from "old"
//even if they are in fact completely the same. Example
//Crontab was:
// 0-59 * * * * job1
// 0-59 * * * * long_running_job2
//User edits crontab to:
// 0-59 * * * * job1_updated
// 0-59 * * * * long_running_job2
//Bug: crond can now start another long_running_job2 even if old one
//is still running.
//OTOH most other versions of cron do not wait for job termination anyway,
//they end up with multiple copies of jobs if they don't terminate soon enough.
static void delete_cronfile(const char *userName)
{
	CronFile **pfile = &G.cron_files;
	CronFile *file;

	while ((file = *pfile) != NULL) {
		if (strcmp(userName, file->cf_username) == 0) {
			CronLine **pline = &file->cf_lines;
			CronLine *line;

			file->cf_has_running = 0;
			file->cf_deleted = 1;

			while ((line = *pline) != NULL) {
				if (line->cl_pid > 0) {
					file->cf_has_running = 1;
					pline = &line->cl_next;
				} else {
					*pline = line->cl_next;
					free(line->cl_cmd);
					free(line);
				}
			}
			if (file->cf_has_running == 0) {
				*pfile = file->cf_next;
				free(file->cf_username);
				free(file);
				continue;
			}
		}
		pfile = &file->cf_next;
	}
}

static void load_crontab(const char *fileName)
{
	struct parser_t *parser;
	struct stat sbuf;
	int maxLines;
	char *tokens[6];
#if ATLAS_NEW_FORMAT
	char *check0, *check1, *check2;
	time_t now;
#endif

	delete_cronfile(fileName);

	if (!getpwnam(fileName)) {
		crondlog(LVL7 "ignoring file '%s' (no such user)", fileName);
		return;
	}

<<<<<<< HEAD:miscutils/crond.c
=======
	SetOld(fileName);

>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
	parser = config_open(fileName);
	if (!parser)
	{
		/* We have to get rid of the old entries if the file is not
		 * there. Assume a non-existant file is the only reason for
		 * failure.
		 */
		DeleteFile(oldFile);
		return;
	}

	maxLines = (strcmp(fileName, "root") == 0) ? 65535 : MAXLINES;

<<<<<<< HEAD:miscutils/crond.c
	if (fstat(fileno(parser->fp), &sbuf) == 0 && sbuf.st_uid == DAEMON_UID) {
=======
#if ATLAS_NEW_FORMAT
	now= time(NULL);
#endif

	if (fstat(fileno(parser->fp), &sbuf) == 0 /* && sbuf.st_uid == DaemonUid */ ) {
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
		CronFile *file = xzalloc(sizeof(CronFile));
		CronLine **pline;
		int n;

		file->cf_username = xstrdup(fileName);
		pline = &file->cf_lines;

		while (1) {
			CronLine *line;

			if (!--maxLines)
				break;
			n = config_read(parser, tokens, 6, 1, "# \t", PARSE_NORMAL | PARSE_KEEP_COPY);
			if (!n)
				break;

			if (DebugOpt)
				crondlog(LVL5 "user:%s entry:%s", fileName, parser->data);

			/* check if line is setting MAILTO= */
			if (0 == strncmp(tokens[0], "MAILTO=", 7)) {
				continue;
			}
			/* check if a minimum of tokens is specified */
			if (n < 6)
				continue;
			*pline = line = xzalloc(sizeof(*line));
#if ATLAS_NEW_FORMAT
			line->interval= strtoul(tokens[0], &check0, 10);
			line->start_time= strtoul(tokens[1], &check1, 10);
			line->end_time= strtoul(tokens[2], &check2, 10);

			line->nextcycle= (now-line->start_time)/
				line->interval + 1;

			if (check0[0] != '\0' ||
				check1[0] != '\0' ||
				check2[0] != '\0')
			{
				crondlog(LVL9 "bad crontab line");
				free(line);
				continue;
			}

			if (strcmp(tokens[3], "NONE") == 0)
			{
				line->distribution= DISTR_NONE;
			}
			else if (strcmp(tokens[3], "UNIFORM") == 0)
			{
				line->distribution= DISTR_UNIFORM;
				line->distr_param=
					strtoul(tokens[4], &check0, 10);
				if (check0[0] != '\0')
				{
					crondlog(LVL9 "bad crontab line");
					free(line);
					continue;
				}
				if (line->distr_param == 0 ||
					LONG_MAX/line->distr_param == 0)
				{
					line->distribution= DISTR_NONE;
				}
			}
			do_distr(line);

			line->lasttime= 0;
#else
			/* parse date ranges */
			ParseField(file->cf_username, line->cl_Mins, 60, 0, NULL, tokens[0]);
			ParseField(file->cf_username, line->cl_Hrs, 24, 0, NULL, tokens[1]);
			ParseField(file->cf_username, line->cl_Days, 32, 0, NULL, tokens[2]);
			ParseField(file->cf_username, line->cl_Mons, 12, -1, MonAry, tokens[3]);
			ParseField(file->cf_username, line->cl_Dow, 7, 0, DowAry, tokens[4]);
			/*
			 * fix days and dow - if one is not "*" and the other
			 * is "*", the other is set to 0, and vise-versa
			 */
			FixDayDow(line);
<<<<<<< HEAD:miscutils/crond.c
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL
			/* copy mailto (can be NULL) */
			line->cl_mailto = xstrdup(mailTo);
#endif
=======
#endif /* ATLAS_NEW_FORMAT */
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
			/* copy command */
			line->cl_cmd = xstrdup(tokens[5]);
			if (DebugOpt) {
				crondlog(LVL5 " command:%s", tokens[5]);
			}
			pline = &line->cl_next;
//bb_error_msg("M[%s]F[%s][%s][%s][%s][%s][%s]", mailTo, tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5]);

			CopyFromOld(line);

			kick_watchdog();
		}
		*pline = NULL;

		file->cf_next = G.cron_files;
		G.cron_files = file;

		if (maxLines == 0) {
			crondlog(WARN9 "user %s: too many lines", fileName);
		}
	}
	config_close(parser);

	DeleteFile(oldFile);
}

static void process_cron_update_file(void)
{
	FILE *fi;
	char buf[256];

	fi = fopen_for_read(CRONUPDATE);
	if (fi != NULL) {
		unlink(CRONUPDATE);
		while (fgets(buf, sizeof(buf), fi) != NULL) {
			/* use first word only */
			skip_non_whitespace(buf)[0] = '\0';
			load_crontab(buf);
		}
		fclose(fi);
	}
}

static void rescan_crontab_dir(void)
{
	CronFile *file;

<<<<<<< HEAD:miscutils/crond.c
	/* Delete all files until we only have ones with running jobs (or none) */
 again:
	for (file = G.cron_files; file; file = file->cf_next) {
		if (!file->cf_deleted) {
			delete_cronfile(file->cf_username);
			goto again;
		}
=======
	/* Mark all file in the current database for deletion */
	for (file = FileBase; file; file = file->cf_Next) {
		file->cf_ToBeDeleted= 1;
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
	}

	/* Remove cron update file */
	unlink(CRONUPDATE);
	/* Re-chdir, in case directory was renamed & deleted */
	if (chdir(G.crontab_dir_name) < 0) {
		crondlog(DIE9 "chdir(%s)", G.crontab_dir_name);
	}

	/* Scan directory and add associated users */
	{
		DIR *dir = opendir(".");
		struct dirent *den;

		if (!dir)
			crondlog(DIE9 "chdir(%s)", "."); /* exits */
		while ((den = readdir(dir)) != NULL) {
			if (strchr(den->d_name, '.') != NULL) {
				continue;
			}
			load_crontab(den->d_name);
		}
		closedir(dir);
	}

	/* Clear the cf_Deleted flags on all file and try to delete everything
	 * marked as cf_ToBeDeleted.
	 */
	for (file = FileBase; file; file = file->cf_Next) {
		file->cf_Deleted= 0;
	}

 again:
	for (file = FileBase; file; file = file->cf_Next) {
		if (file->cf_ToBeDeleted && !file->cf_Deleted) {
			DeleteFile(file);
			goto again;
		}
	}

}

/*
 * SetOld() - find a user database that is not marked for deletion set.
 */
static void SetOld(const char *userName)
{
	CronFile *file;

	oldFile= NULL;
	oldLine= NULL;
	for (file = FileBase; file; file = file->cf_Next) {
		if (file->cf_ToBeDeleted)
			continue;
		if (strcmp(file->cf_User, userName) != 0)
			continue;
		file->cf_ToBeDeleted= 1;
		oldFile= file;
		break;
	}
}

/*
 * CopyFromOld - copy nextcycle from old entry
 */
static void CopyFromOld(CronLine *line)
{
	if (!oldFile)
		return;		/* Nothing to do */

	if (oldLine)
	{
		/* Try to match line expected to be next */
		if (oldLine->interval == line->interval &&
			oldLine->start_time == line->start_time &&
			strcmp(oldLine->cl_Shell, line->cl_Shell) == 0)
		{
			crondlog(LVL7 "next line matches");
			; /* okay */
		}
		else
			oldLine= NULL;
	}

	if (!oldLine)
	{
		/* Try to find one */
		for (oldLine= oldFile->cf_LineBase; oldLine;
			oldLine= oldLine->cl_Next)
		{
			if (oldLine->interval == line->interval &&
				oldLine->start_time == line->start_time &&
				strcmp(oldLine->cl_Shell, line->cl_Shell) == 0)
			{
				crondlog(LVL7 "found matching line");
				break;
			}
		}
	}

	if (!oldLine)
	{
		crondlog(LVL7 "found no match for line '%s'", 
			line->cl_Shell);
		return;
	}

	crondlog(LVL7 "found old line for '%s'", oldLine->cl_Shell);
	if (line->nextcycle != oldLine->nextcycle)
	{
		crondlog(LVL9 "nextcycle %d -> %d for '%s'",
			line->nextcycle, oldLine->nextcycle,
			oldLine->cl_Shell);
	}
	line->nextcycle= oldLine->nextcycle;

	if (oldLine->distribution == line->distribution &&
		oldLine->distr_param == line->distr_param)
	{
		line->distr_offset= oldLine->distr_offset;
	}

	oldLine= oldLine->cl_Next;
}

<<<<<<< HEAD:miscutils/crond.c
#if SETENV_LEAKS
/* We set environment *before* vfork (because we want to use vfork),
 * so we cannot use setenv() - repeated calls to setenv() may leak memory!
 * Using putenv(), and freeing memory after unsetenv() won't leak */
static void safe_setenv(char **pvar_val, const char *var, const char *val)
{
	char *var_val = *pvar_val;

	if (var_val) {
		bb_unsetenv_and_free(var_val);
=======
/*
 *  DeleteFile() - delete user database
 *
 *  Note: multiple entries for same user may exist if we were unable to
 *  completely delete a database due to running processes.
 */
static void DeleteFile(CronFile *tfile)
{
	CronFile **pfile = &FileBase;
	CronFile *file;

	while ((file = *pfile) != NULL) {
		if (file == tfile) {
			CronLine **pline = &file->cf_LineBase;
			CronLine *line;

			file->cf_Running = 0;
			file->cf_Deleted = 1;

			while ((line = *pline) != NULL) {
				if (line->cl_Pid > 0) {
					file->cf_Running = 1;
					pline = &line->cl_Next;
				} else {
					*pline = line->cl_Next;
					free(line->cl_Shell);
					free(line);
				}
				kick_watchdog();
			}
			if (file->cf_Running == 0) {
				*pfile = file->cf_Next;
				free(file->cf_User);
				free(file);
			} else {
				pfile = &file->cf_Next;
			}
		} else {
			pfile = &file->cf_Next;
		}
	}
}

/*
 * TestJobs()
 *
 * determine which jobs need to be run.  Under normal conditions, the
 * period is about a minute (one scan).  Worst case it will be one
 * hour (60 scans).
 */
#if ATLAS_NEW_FORMAT
static int TestJobs(time_t *nextp)
#else
static int TestJobs(time_t t1, time_t t2)
#endif
{
	int nJobs = 0;
#if ATLAS_NEW_FORMAT
	time_t now;
#else
	time_t t;
#endif

#if ATLAS_NEW_FORMAT
	now= time(NULL);
	*nextp= now+3600;	/* Enough */

	{
		CronFile *file;
		CronLine *line;
#else
	/* Find jobs > t1 and <= t2 */

	for (t = t1 - t1 % 60; t <= t2; t += 60) {
		struct tm *tp;
		CronFile *file;
		CronLine *line;

		if (t <= t1)
			continue;

		tp = localtime(&t);
#endif /* ATLAS_NEW_FORMAT */
		for (file = FileBase; file; file = file->cf_Next) {
			if (DebugOpt)
				crondlog(LVL5 "file %s:", file->cf_User);
			if (file->cf_Deleted)
				continue;
			for (line = file->cf_LineBase; line; line = line->cl_Next) {
				if (DebugOpt)
					crondlog(LVL5 " line %s", line->cl_Shell);
#if ATLAS_NEW_FORMAT
				if (line->lasttime != 0)
				{
					if (now > line->lasttime+
						line->interval+
						line->distr_param)
					{
						crondlog(
LVL7 "(TestJobs) job is late. Now %d, lasttime %d, max %d, should %d: %s",
							now, line->lasttime,
							line->lasttime+
							line->interval+
							line->distr_param,
							line->start_time +
							line->nextcycle*
							line->interval+
							line->distr_offset,
							line->cl_Shell);
					}
				}

				if (now >= line->start_time +
					line->nextcycle*line->interval +
					line->distr_offset &&
					now >= line->start_time &&
					now <= line->end_time
				)
#else
				if (line->cl_Mins[tp->tm_min] && line->cl_Hrs[tp->tm_hour]
				 && (line->cl_Days[tp->tm_mday] || line->cl_Dow[tp->tm_wday])
				 && line->cl_Mons[tp->tm_mon]
				)
#endif
				{
					if (DebugOpt) {
						crondlog(LVL5 " job: %d %s",
							(int)line->cl_Pid, line->cl_Shell);
					}
					if (line->cl_Pid > 0) {
						crondlog(LVL8 "user %s: process already running: %s",
							file->cf_User, line->cl_Shell);
					} else if (line->cl_Pid == 0) {
						line->cl_Pid = -1;
						file->cf_Ready = 1;
						++nJobs;
#if ATLAS_NEW_FORMAT
						*nextp= 0;
						line->nextcycle++;
						if (line->start_time +
							line->nextcycle*
							line->interval <= now)
						{
							line->nextcycle=
							(now-line->start_time)/
							line->interval + 1;
						}
						do_distr(line);
#endif
					}
				}
#if ATLAS_NEW_FORMAT
				else if (now >= line->start_time &&
					now <= line->end_time)
				{
					/* Compute next time */
					time_t next;

					next= line->start_time +
						line->nextcycle*line->interval +
						line->distr_offset;
					if (next < *nextp)
						*nextp= next;
				}
#endif /* ATLAS_NEW_FORMAT */
			}
		}
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
	}
	*pvar_val = xasprintf("%s=%s", var, val);
	putenv(*pvar_val);
}
#endif

static void set_env_vars(struct passwd *pas)
{
<<<<<<< HEAD:miscutils/crond.c
#if SETENV_LEAKS
	safe_setenv(&G.env_var_user, "USER", pas->pw_name);
	safe_setenv(&G.env_var_home, "HOME", pas->pw_dir);
	/* if we want to set user's shell instead: */
	/*safe_setenv(G.env_var_shell, "SHELL", pas->pw_shell);*/
#else
	xsetenv("USER", pas->pw_name);
	xsetenv("HOME", pas->pw_dir);
#endif
	/* currently, we use constant one: */
	/*setenv("SHELL", DEFAULT_SHELL, 1); - done earlier */
=======
	CronFile *file;
	CronLine *line;

	for (file = FileBase; file; file = file->cf_Next) {
		if (!file->cf_Ready)
			continue;

		file->cf_Ready = 0;
		for (line = file->cf_LineBase; line; line = line->cl_Next) {
			if (line->cl_Pid >= 0)
				continue;

			kick_watchdog();

			RunJob(file->cf_User, line);
			crondlog(LVL8 "USER %s pid %3d cmd %s",
				file->cf_User, (int)line->cl_Pid, line->cl_Shell);
			if (line->cl_Pid < 0) {
				file->cf_Ready = 1;
			} else if (line->cl_Pid > 0) {
				file->cf_Running = 1;
			}
			// AA make it wait till the job is finished
			while (CheckJobs() > 0)                        
			{
                         	// crondlog(LVL9 "waiting for job %s ", line->cl_Shell);
                                sleep(5);
                        }

		}
	}
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
}

static void change_user(struct passwd *pas)
{
	/* careful: we're after vfork! */
	change_identity(pas); /* - initgroups, setgid, setuid */
	if (chdir(pas->pw_dir) < 0) {
		crondlog(WARN9 "chdir(%s)", pas->pw_dir);
		if (chdir(TMPDIR) < 0) {
			crondlog(DIE9 "chdir(%s)", TMPDIR); /* exits */
		}
	}
}

<<<<<<< HEAD:miscutils/crond.c
// TODO: sendmail should be _run-time_ option, not compile-time!
#if ENABLE_FEATURE_CROND_CALL_SENDMAIL

static pid_t
fork_job(const char *user, int mailFd,
		const char *prog,
		const char *shell_cmd /* if NULL, we run sendmail */
) {
	struct passwd *pas;
	pid_t pid;

	/* prepare things before vfork */
	pas = getpwnam(user);
	if (!pas) {
		crondlog(WARN9 "can't get uid for %s", user);
		goto err;
	}
	set_env_vars(pas);

	pid = vfork();
	if (pid == 0) {
		/* CHILD */
		/* initgroups, setgid, setuid, and chdir to home or TMPDIR */
		change_user(pas);
		if (DebugOpt) {
			crondlog(LVL5 "child running %s", prog);
		}
		if (mailFd >= 0) {
			xmove_fd(mailFd, shell_cmd ? 1 : 0);
			dup2(1, 2);
		}
		/* crond 3.0pl1-100 puts tasks in separate process groups */
		bb_setpgrp();
		execlp(prog, prog, (shell_cmd ? "-c" : SENDMAIL_ARGS), shell_cmd, (char *) NULL);
		crondlog(ERR20 "can't execute '%s' for user %s", prog, user);
		if (shell_cmd) {
			fdprintf(1, "Exec failed: %s -c %s\n", prog, shell_cmd);
		}
		_exit(EXIT_SUCCESS);
=======
static void skip_space(char *cp, char **ncpp)
{
	while (cp[0] != '\0' && isspace(*(unsigned char *)cp))
		cp++;
	*ncpp= cp;
}

static void skip_nonspace(char *cp, char **ncpp)
{
	while (cp[0] != '\0' && !isspace(*(unsigned char *)cp))
		cp++;
	*ncpp= cp;
}

static void find_eos(char *cp, char **ncpp)
{
	while (cp[0] != '\0' && cp[0] != '"')
		cp++;
	*ncpp= cp;
}


#define ATLAS_NARGS	20	/* Max arguments to a built-in command */
#define ATLAS_ARGSIZE	512	/* Max size of the command line */

static int atlas_run(char *cmdline)
{
	char c;
	int i, r, argc, atlas_fd, saved_fd, do_append, flags;
	size_t len;
	char *cp, *ncp;
	struct builtin *bp;
	char *outfile;
	FILE *fn;
	char *reason;
	char *argv[ATLAS_NARGS];
	char args[ATLAS_ARGSIZE];

	crondlog(LVL7 "atlas_run: looking for %p '%s'", cmdline, cmdline);

	reason= NULL;
	for (bp= builtin_cmds; bp->cmd != NULL; bp++)
	{
		len= strlen(bp->cmd);
		if (strncmp(cmdline, bp->cmd, len) != 0)
			continue;
		if (cmdline[len] != ' ')
			continue;
		break;
	}
	if (bp->cmd == NULL)
	{
		crondlog(LVL8 "cmd not found '%s'", cmdline);
		r= -1;
		reason="cmd not found";
		goto error;
	}
	
	crondlog(LVL7 "found cmd '%s' for '%s'", bp->cmd, cmdline);

	outfile= NULL;
	do_append= 0;

	len= strlen(cmdline);
	if (len+1 > ATLAS_ARGSIZE)
	{
		crondlog(LVL8 "atlas_run: command line too big: '%s'", cmdline);
		r= -1;
		reason="command line too big";
		goto error;
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
	}
	strcpy(args, cmdline);

<<<<<<< HEAD:miscutils/crond.c
	if (pid < 0) {
		/* FORK FAILED */
		crondlog(ERR20 "can't vfork");
 err:
		pid = 0;
	} /* else: PARENT, FORK SUCCESS */

	/*
	 * Close the mail file descriptor.. we can't just leave it open in
	 * a structure, closing it later, because we might run out of descriptors
	 */
	if (mailFd >= 0) {
		close(mailFd);
	}
	return pid;
}

static void start_one_job(const char *user, CronLine *line)
{
	char mailFile[128];
	int mailFd = -1;

	line->cl_pid = 0;
	line->cl_empty_mail_size = 0;

	if (line->cl_mailto) {
		/* Open mail file (owner is root so nobody can screw with it) */
		snprintf(mailFile, sizeof(mailFile), "%s/cron.%s.%d", TMPDIR, user, getpid());
		mailFd = open(mailFile, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL | O_APPEND, 0600);

		if (mailFd >= 0) {
			fdprintf(mailFd, "To: %s\nSubject: cron: %s\n\n", line->cl_mailto,
				line->cl_cmd);
			line->cl_empty_mail_size = lseek(mailFd, 0, SEEK_CUR);
		} else {
			crondlog(ERR20 "can't create mail file %s for user %s, "
					"discarding output", mailFile, user);
		}
	}

	line->cl_pid = fork_job(user, mailFd, DEFAULT_SHELL, line->cl_cmd);
	if (mailFd >= 0) {
		if (line->cl_pid <= 0) {
			unlink(mailFile);
		} else {
			/* rename mail-file based on pid of process */
			char *mailFile2 = xasprintf("%s/cron.%s.%d", TMPDIR, user, (int)line->cl_pid);
			rename(mailFile, mailFile2); // TODO: xrename?
			free(mailFile2);
		}
	}
}

/*
 * process_finished_job - called when job terminates and when mail terminates
 */
static void process_finished_job(const char *user, CronLine *line)
{
	pid_t pid;
	int mailFd;
	char mailFile[128];
	struct stat sbuf;

	pid = line->cl_pid;
	line->cl_pid = 0;
	if (pid <= 0) {
		/* No job */
		return;
	}
	if (line->cl_empty_mail_size <= 0) {
		/* End of job and no mail file, or end of sendmail job */
		return;
	}

	/*
	 * End of primary job - check for mail file.
	 * If size has changed and the file is still valid, we send it.
	 */
	snprintf(mailFile, sizeof(mailFile), "%s/cron.%s.%d", TMPDIR, user, (int)pid);
	mailFd = open(mailFile, O_RDONLY);
	unlink(mailFile);
	if (mailFd < 0) {
		return;
	}

	if (fstat(mailFd, &sbuf) < 0
	 || sbuf.st_uid != DAEMON_UID
	 || sbuf.st_nlink != 0
	 || sbuf.st_size == line->cl_empty_mail_size
	 || !S_ISREG(sbuf.st_mode)
	) {
		close(mailFd);
		return;
	}
	line->cl_empty_mail_size = 0;
	/* if (line->cl_mailto) - always true if cl_empty_mail_size was nonzero */
		line->cl_pid = fork_job(user, mailFd, SENDMAIL, NULL);
}

#else /* !ENABLE_FEATURE_CROND_CALL_SENDMAIL */
=======
	/* Split the command line */
	cp= args;
	argc= 0;
	argv[argc]= cp;
	skip_nonspace(cp, &ncp);
	cp= ncp;

	for(;;)
	{
		/* End of list */
		if (cp[0] == '\0')
		{
			argc++;
			break;
		}

		/* Find start of next argument */
		skip_space(cp, &ncp);

		/* Terminate current one */
		cp[0]= '\0';

		/* Special case for '>' */
		if (argv[argc][0] == '>')
		{
			cp= argv[argc]+1;
			if (cp[0] == '>')
			{
				/* Append */
				do_append= 1;
				cp++;
			}
			if (cp[0] != '\0')
			{
				/* Filename immediately follows '>' */
				outfile= cp;
				
				/* And move on with the next option */
			}
			else
			{
				/* Get the next argument */
				outfile= ncp;
				cp= ncp;
				skip_nonspace(cp, &ncp);
				cp= ncp;

				if (cp[0] == '\0')
					break;

				/* Find start of next argument */
				skip_space(cp, &ncp);
				*cp= '\0';
			}
		}
		else
		{
			argc++;
		}

		if (argc >= ATLAS_NARGS-1)
		{
			crondlog(
			LVL8 "atlas_run: command line '%s', too many arguments",
				cmdline);
			r= -1;
			reason="too many arguments";
			goto error;
		}

		cp= ncp;
		argv[argc]= cp;
		if (cp[0] == '"')
		{
			/* Special code for strings */
			find_eos(cp+1, &ncp);
			if (ncp[0] != '"')
			{
				crondlog(
		LVL8 "atlas_run: command line '%s', end of string not found",
					cmdline);
				r= -1;
				reason="end of string not found";
				goto error;
			}
			argv[argc]= cp+1;
			cp= ncp;
			cp[0]= '\0';
			cp++;
		}
		else
		{
			skip_nonspace(cp, &ncp);
			cp= ncp;
		}
	}

	if (argc >= ATLAS_NARGS)
	{
		crondlog(	
			LVL8 "atlas_run: command line '%s', too many arguments",
			cmdline);
		r= -1;
		reason="too many arguments";
		goto error;
	}
	argv[argc]= NULL;

	for (i= 0; i<argc; i++)
		crondlog(LVL7 "atlas_run: argv[%d] = '%s'", i, argv[i]);

	saved_fd= -1;	/* lint */
	if (outfile)
	{
		/* Redirect I/O */
		crondlog(LVL7 "sending output to '%s'", outfile);
		if (!validate_filename(outfile, SAFE_PREFIX))
		{
			crondlog(
			LVL8 "atlas_run: insecure output file '%s'",
				outfile);
			r= -1;
			reason="insecure output file";
			goto error;
		}
		flags= O_CREAT | O_WRONLY;
		if (do_append)
			flags |= O_APPEND;
		atlas_fd= open(outfile, flags, 0644);
		if (atlas_fd == -1)
		{
			crondlog(
			LVL8 "atlas_run: unable to create output file '%s'",
				outfile);
			r= -1;
			reason="unable to create output file";
			goto error;
		}
		fflush(stdout);
		saved_fd= dup(1);
		if (saved_fd == -1)
		{
			crondlog(LVL8 "atlas_run: unable to dub stdout");
			close(atlas_fd);
			r= -1;
			reason="unable to dub stdout";
			goto error;
		}
		dup2(atlas_fd, 1);
		close(atlas_fd);
	}

	r= bp->func(argc, argv);

	alarm(0);

	if (outfile)
	{
		fflush(stdout);
		dup2(saved_fd, 1);
		close(saved_fd);
	}

error:
	if (r != 0 && out_filename)
	{
		fn= fopen(out_filename, "a");
		if (!fn)
			crondlog(DIE9 "unable to append to '%s'", out_filename);
		fprintf(fn, "RESULT { ");
		if (atlas_id)
			fprintf(fn, DBQ(id) ":" DBQ(%s) ", ", atlas_id);
		fprintf(fn, DBQ(fw) ":" DBQ(%d) ", " DBQ(time) ":%d, ",
			get_atlas_fw_version(), time(NULL));
		if (reason != NULL)
			fprintf(fn, DBQ(reason) ":" DBQ(%s) ", ", reason);
		fprintf(fn, DBQ(err) ":%d, " DBQ(cmd) ": \"", r);
		for (cp= cmdline; *cp; cp++)
		{
			c= *cp;
			if (c == '"' || c == '\\')
				fprintf(fn, "\\%c", c);
			else if (isprint((unsigned char)c))
				fputc(c, fn);
			else
				fprintf(fn, "\\u%04x", (unsigned char)c);
		}
		fprintf(fn, "\"");
		fprintf(fn, " }\n");
		fclose(fn);
	}

	return 1;
}
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c

static void start_one_job(const char *user, CronLine *line)
{
	struct passwd *pas;
	pid_t pid;

<<<<<<< HEAD:miscutils/crond.c
=======
	if (line->lasttime != 0)
	{
		time_t now= time(NULL);
		if (now > line->lasttime+line->interval+line->distr_param)
		{
			crondlog(LVL7 "job is late. Now %d, lasttime %d, max %d, should %d: %s",
				now, line->lasttime,
				line->lasttime+line->interval+line->distr_param,
				line->start_time +
				line->nextcycle*line->interval+
				line->distr_offset,
				line->cl_Shell);
		}
	}
	line->lasttime= time(NULL);

	if (atlas_run(line->cl_Shell))
	{
		/* Internal command */
		line->cl_Pid = 0;
		return;
	}

	/* Don't run external commands */
	line->cl_Pid = 0;
#if 0
	/* prepare things before vfork */
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
	pas = getpwnam(user);
	if (!pas) {
		crondlog(WARN9 "can't get uid for %s", user);
		goto err;
	}

	/* Prepare things before vfork */
	set_env_vars(pas);

	/* Fork as the user in question and run program */
	pid = vfork();
	if (pid == 0) {
		/* CHILD */
		/* initgroups, setgid, setuid, and chdir to home or TMPDIR */
		change_user(pas);
		if (DebugOpt) {
			crondlog(LVL5 "child running %s", DEFAULT_SHELL);
		}
		/* crond 3.0pl1-100 puts tasks in separate process groups */
		bb_setpgrp();
<<<<<<< HEAD:miscutils/crond.c
		execl(DEFAULT_SHELL, DEFAULT_SHELL, "-c", line->cl_cmd, (char *) NULL);
		crondlog(ERR20 "can't execute '%s' for user %s", DEFAULT_SHELL, user);
=======
		/* Disable execl for securty reasons */
		//execl(DEFAULT_SHELL, DEFAULT_SHELL, "-c", line->cl_Shell, NULL);
		crondlog(ERR20 "can't exec, user %s cmd %s %s %s", user,
				 DEFAULT_SHELL, "-c", line->cl_Shell);
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
		_exit(EXIT_SUCCESS);
	}
	if (pid < 0) {
		/* FORK FAILED */
		crondlog(ERR20 "can't vfork");
 err:
		pid = 0;
	}
<<<<<<< HEAD:miscutils/crond.c
	line->cl_pid = pid;
}

#define process_finished_job(user, line)  ((line)->cl_pid = 0)

#endif /* !ENABLE_FEATURE_CROND_CALL_SENDMAIL */

/*
 * Determine which jobs need to be run.  Under normal conditions, the
 * period is about a minute (one scan).  Worst case it will be one
 * hour (60 scans).
 */
static void flag_starting_jobs(time_t t1, time_t t2)
{
	time_t t;

	/* Find jobs > t1 and <= t2 */

	for (t = t1 - t1 % 60; t <= t2; t += 60) {
		struct tm *ptm;
		CronFile *file;
		CronLine *line;

		if (t <= t1)
			continue;

		ptm = localtime(&t);
		for (file = G.cron_files; file; file = file->cf_next) {
			if (DebugOpt)
				crondlog(LVL5 "file %s:", file->cf_username);
			if (file->cf_deleted)
				continue;
			for (line = file->cf_lines; line; line = line->cl_next) {
				if (DebugOpt)
					crondlog(LVL5 " line %s", line->cl_cmd);
				if (line->cl_Mins[ptm->tm_min]
				 && line->cl_Hrs[ptm->tm_hour]
				 && (line->cl_Days[ptm->tm_mday] || line->cl_Dow[ptm->tm_wday])
				 && line->cl_Mons[ptm->tm_mon]
				) {
					if (DebugOpt) {
						crondlog(LVL5 " job: %d %s",
							(int)line->cl_pid, line->cl_cmd);
					}
					if (line->cl_pid > 0) {
						crondlog(LVL8 "user %s: process already running: %s",
							file->cf_username, line->cl_cmd);
					} else if (line->cl_pid == 0) {
						line->cl_pid = -1;
						file->cf_wants_starting = 1;
					}
				}
			}
		}
	}
}

static void start_jobs(void)
{
	CronFile *file;
	CronLine *line;

	for (file = G.cron_files; file; file = file->cf_next) {
		if (!file->cf_wants_starting)
			continue;

		file->cf_wants_starting = 0;
		for (line = file->cf_lines; line; line = line->cl_next) {
			pid_t pid;
			if (line->cl_pid >= 0)
				continue;

			start_one_job(file->cf_username, line);
			pid = line->cl_pid;
			crondlog(LVL8 "USER %s pid %3d cmd %s",
				file->cf_username, (int)pid, line->cl_cmd);
			if (pid < 0) {
				file->cf_wants_starting = 1;
			}
			if (pid > 0) {
				file->cf_has_running = 1;
			}
		}
	}
}

/*
 * Check for job completion, return number of jobs still running after
 * all done.
 */
static int check_completions(void)
{
	CronFile *file;
	CronLine *line;
	int num_still_running = 0;

	for (file = G.cron_files; file; file = file->cf_next) {
		if (!file->cf_has_running)
			continue;

		file->cf_has_running = 0;
		for (line = file->cf_lines; line; line = line->cl_next) {
			int r;

			if (line->cl_pid <= 0)
				continue;

			r = waitpid(line->cl_pid, NULL, WNOHANG);
			if (r < 0 || r == line->cl_pid) {
				process_finished_job(file->cf_username, line);
				if (line->cl_pid == 0) {
					/* sendmail was not started for it */
					continue;
				}
				/* else: sendmail was started, job is still running, fall thru */
			}
			/* else: r == 0: "process is still running" */
			file->cf_has_running = 1;
		}
//FIXME: if !file->cf_has_running && file->deleted: delete it!
//otherwise deleted entries will stay forever, right?
		num_still_running += file->cf_has_running;
	}
	return num_still_running;
}

int crond_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int crond_main(int argc UNUSED_PARAM, char **argv)
{
	time_t t2;
	int rescan;
	int sleep_time;
	unsigned opts;

	INIT_G();

	/* "-b after -f is ignored", and so on for every pair a-b */
	opt_complementary = "f-b:b-f:S-L:L-S" IF_FEATURE_CROND_D(":d-l")
			/* -l and -d have numeric param */
			":l+" IF_FEATURE_CROND_D(":d+");
	opts = getopt32(argv, "l:L:fbSc:" IF_FEATURE_CROND_D("d:"),
			&G.log_level, &G.log_filename, &G.crontab_dir_name
			IF_FEATURE_CROND_D(,&G.log_level));
	/* both -d N and -l N set the same variable: G.log_level */

	if (!(opts & OPT_f)) {
		/* close stdin, stdout, stderr.
		 * close unused descriptors - don't need them. */
		bb_daemonize_or_rexec(DAEMON_CLOSE_EXTRA_FDS, argv);
	}

	if (!(opts & OPT_d) && G.log_filename == NULL) {
		/* logging to syslog */
		openlog(applet_name, LOG_CONS | LOG_PID, LOG_CRON);
		logmode = LOGMODE_SYSLOG;
	}

	xchdir(G.crontab_dir_name);
	//signal(SIGHUP, SIG_IGN); /* ? original crond dies on HUP... */
	xsetenv("SHELL", DEFAULT_SHELL); /* once, for all future children */
	crondlog(LVL8 "crond (busybox "BB_VER") started, log level %d", G.log_level);
	rescan_crontab_dir();
	write_pidfile(CONFIG_PID_FILE_PATH "/crond.pid");

	/* Main loop */
	t2 = time(NULL);
	rescan = 60;
	sleep_time = 60;
	for (;;) {
		struct stat sbuf;
		time_t t1;
		long dt;

		t1 = t2;

		/* Synchronize to 1 minute, minimum 1 second */
		sleep(sleep_time - (time(NULL) % sleep_time) + 1);

		t2 = time(NULL);
		dt = (long)t2 - (long)t1;

		/*
		 * The file 'cron.update' is checked to determine new cron
		 * jobs.  The directory is rescanned once an hour to deal
		 * with any screwups.
		 *
		 * Check for time jump.  Disparities over an hour either way
		 * result in resynchronization.  A negative disparity
		 * less than an hour causes us to effectively sleep until we
		 * match the original time (i.e. no re-execution of jobs that
		 * have just been run).  A positive disparity less than
		 * an hour causes intermediate jobs to be run, but only once
		 * in the worst case.
		 *
		 * When running jobs, the inequality used is greater but not
		 * equal to t1, and less then or equal to t2.
		 */
		if (stat(G.crontab_dir_name, &sbuf) != 0)
			sbuf.st_mtime = 0; /* force update (once) if dir was deleted */
		if (G.crontab_dir_mtime != sbuf.st_mtime) {
			G.crontab_dir_mtime = sbuf.st_mtime;
			rescan = 1;
		}
		if (--rescan == 0) {
			rescan = 60;
			rescan_crontab_dir();
		}
		process_cron_update_file();
		if (DebugOpt)
			crondlog(LVL5 "wakeup dt=%ld", dt);
		if (dt < -60 * 60 || dt > 60 * 60) {
			crondlog(WARN9 "time disparity of %ld minutes detected", dt / 60);
			/* and we do not run any jobs in this case */
		} else if (dt > 0) {
			/* Usual case: time advances forward, as expected */
			flag_starting_jobs(t1, t2);
			start_jobs();
			if (check_completions() > 0) {
				/* some jobs are still running */
				sleep_time = 10;
			} else {
				sleep_time = 60;
			}
		}
		/* else: time jumped back, do not run any jobs */
	} /* for (;;) */

	return 0; /* not reached */
}
=======
	line->cl_Pid = pid;
#endif
}
>>>>>>> ripe-atlas-fw-4550:miscutils/perd.c
