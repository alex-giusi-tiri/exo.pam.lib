#ifndef pam_std_option_h
#define pam_std_option_h

//#include <security/pam_modules.h>
//#include <string.h>
//#include "pam.exo.h"

/*
 * If the given name is a standard option, set the corresponding flag in
 * the options word and return 0.  Else return -1.
 */

const int pam_std_option (int *, const char *);

#endif
