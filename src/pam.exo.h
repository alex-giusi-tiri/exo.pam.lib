#ifndef pam_exo_h
#define pam_exo_h

#define _GNU_SOURCE

#include <stdbool.h>

#ifdef HAVE_CONFIG_H
	#include <config.h>
//#else
	//#error You must use autotools to build this!
#endif

//#include <nss.h>
#include <syslog.h>
//#include <stdio.h>

// Some syslog shortcuts
//#ifdef DEBUG
	#define PAM_DEBUG(msg, ...) syslog(LOG_DEBUG, (msg), ## __VA_ARGS__)
//#else
	//#define DBGLOG(msg, ...)
	//#define DBGLOG(msg, ...) syslog(LOG_DEBUG, (msg), ## __VA_ARGS__)
//#endif

//#define LOG_ERROR(msg, ...) syslog(LOG_ERR, (msg), ## __VA_ARGS__)

// Options
#define PAM_OPT_DEBUG            0x01
#define PAM_OPT_NO_WARN          0x02
#define PAM_OPT_USE_FIRST_PASS   0x04
#define	PAM_OPT_TRY_FIRST_PASS   0x08
#define PAM_OPT_USE_MAPPED_PASS  0x10
#define PAM_OPT_ECHO_PASS        0x20

// Perform request from server.
const bool/* success*/ srv_req (char **/* returned value*/, const char */* URI of request*/, const char */* type of request*/, const char */* item*/, const char */* content*/, const char */* extra*/);
//const bool/* success*/ srv_req_set (const char */* URI of request*/, const char */* user name*/, const char */* item name*/, const char */* content of request*/);

#define PASSWORD_PROMPT                 "Password: "
#define PASSWORD_PROMPT_NEW             "New Password: "
#define PASSWORD_PROMPT_CONFIRMATION    "New Password Confirmation: "
#define SERVER_URI                      "tcp://0.0.0.0:2231"

#endif
