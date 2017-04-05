#include <security/pam_modules.h>
#include <string.h>
#include "pam.exo.h"
#include "pam_std_option.h"

/*
 * If the given name is a standard option, set the corresponding flag in
 * the options word and return 0.  Else return -1.
 */
const int pam_std_option (int * options, const char * name)
{
    struct opttab {
        const char *name;
        int value;
    };
    static struct opttab std_options[] = {
        { "debug",          PAM_OPT_DEBUG },
        { "no_warn",        PAM_OPT_NO_WARN },
        { "use_first_pass", PAM_OPT_USE_FIRST_PASS },
        { "try_first_pass", PAM_OPT_TRY_FIRST_PASS },
        { "use_mapped_pass",PAM_OPT_USE_MAPPED_PASS },
        { "echo_pass",      PAM_OPT_ECHO_PASS },
        { NULL,         0 }
    };
    struct opttab *p;

    for (p = std_options;  p->name != NULL;  p++) {
        if (strcmp(name, p->name) == 0) {
            *options |= p->value;
            return 0;
        }
    }
    return -1;
}
