/*
 * Sample application to test the module
 */

/* $Id: test.c,v 1.2 2003/06/22 18:51:39 ek Exp $ */
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main (int argc, char * argv [])
{
    pam_handle_t * pamh;
    int retval;
    char * user;

		pamh = NULL;
		user = "nobody";
		
    if(argc < 2) {
        fprintf (stderr, "  Usage:\n  '%s' <service name> [user name]\n", argv [0]);
        return 1;
    }

    if(argc >= 3) {
        user = argv[2];
    }

    retval = pam_start(argv[1], user, &conv, &pamh);

    if(retval == PAM_SUCCESS)
        printf("PAM started.\n");

    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if(retval == PAM_SUCCESS)
        printf("Authentication succeeded, checking access.\n");
    else 
        printf("Authentication failed: %s\n", pam_strerror(pamh, retval));

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    if(retval == PAM_SUCCESS)
        printf("Access permitted.\n");
    else 
        printf("Access denied: %s\n", pam_strerror(pamh, retval));

    /* lets try print password */
    printf("Changing authentication token...\n");
    retval = pam_chauthtok(pamh, 0); 
    if(retval != PAM_SUCCESS) {
        printf("Failed: %s\n", pam_strerror(pamh, retval));
    } else {
        printf("Token changed.\n");
    }

    /* This is where we have been authorized or not. */
    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        return 1;
    }

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}
