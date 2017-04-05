#ifndef pam_pass_h
#define pam_pass_h

#include <stdbool.h>
#include <syslog.h>
#include <security/pam_modules.h>

const int pam_conv_pass (const pam_handle_t *, const char *, const int);
const int pam_get_pass (const pam_handle_t *, char **, const char *, const int);
const int pam_get_confirm_pass (const pam_handle_t *, char **, const char *, const char *, const int);
//const int pam_std_option (int *, const char *);
//const char * pam_get_service (pam_handle_t *);

#endif
