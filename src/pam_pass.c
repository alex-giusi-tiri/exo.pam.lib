#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include "pam.exo.h"
#include "pam_pass.h"

const int pam_conv_pass (const pam_handle_t * pamh, const char * prompt, const int options)
{
	PAM_DEBUG ("pam::exo::pam_conv_pass()::...");
	
	int retval;
	const void *item;
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgs[1];
	struct pam_response *resp;

	if ((retval = pam_get_item(pamh, PAM_CONV, &item)) !=
			PAM_SUCCESS)
			return retval;
	conv = (const struct pam_conv *)item;
	msg.msg_style = options & PAM_OPT_ECHO_PASS ?
			PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt;
	msgs[0] = &msg;
	if ((retval = conv->conv(1, msgs, &resp, conv->appdata_ptr)) !=
			PAM_SUCCESS)
			return retval;
	if ((retval = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp)) !=
			PAM_SUCCESS)
			return retval;
	
	memset (resp[0].resp, 0, strlen(resp[0].resp));
	
	free(resp[0].resp);
	free(resp);
	
	PAM_DEBUG ("pam::exo::pam_conv_pass()::return");
	
	return PAM_SUCCESS;
}

const int pam_get_pass (const pam_handle_t * pamh, char ** passp, const char * prompt, const int options)
{
	PAM_DEBUG ("pam::exo::pam_get_pass()::...");
	
	int rc;
	void * item;
		
	item = NULL;
	
	/*
		* Grab the already-entered password if we might want to use it.
		*/
	/*
	if (options & (PAM_OPT_TRY_FIRST_PASS | PAM_OPT_USE_FIRST_PASS)) {
			if ((retval = pam_get_item(pamh, PAM_AUTHTOK, &item)) !=
					PAM_SUCCESS)
					return retval;
	}
	*/
	
	if (item == NULL)
	// The user has not entered a password yet.
	{
		//if (options & PAM_OPT_USE_FIRST_PASS)
		//	return PAM_AUTH_ERR;
		
		// Use the conversation function to get a password.
		rc = pam_conv_pass (pamh, prompt, options);
		if (rc != PAM_SUCCESS)
			return rc;
		
		// Get the password (set by the conversation function).
		rc = pam_get_item (pamh, PAM_AUTHTOK, &item);
		if (rc != PAM_SUCCESS)
			return rc;
	}
	
	*passp = (const char *) item;
	
	PAM_DEBUG ("pam::exo::pam_get_pass()::return");
	return PAM_SUCCESS;
}

const int pam_get_confirm_pass (const pam_handle_t * pamh, char ** passp, const char * prompt1, const char * prompt2, const int options)
{
	PAM_DEBUG ("pam::exo::pam_get_confirm_pass()::...");
    int retval, i;
    void *item = NULL;
    const struct pam_conv *conv;
    struct pam_message msgs[2];
    const struct pam_message *pmsgs[2];
    struct pam_response *resp;

    if ((retval = pam_get_item(pamh, PAM_CONV, &item)) != PAM_SUCCESS)
        return retval;

    conv = (const struct pam_conv *)item;
    for(i = 0; i < 2; i++)
        msgs[i].msg_style = options & PAM_OPT_ECHO_PASS ? 
            PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
    msgs[0].msg = prompt1;
    msgs[1].msg = prompt2;
    pmsgs[0] = &msgs[0];
    pmsgs[1] = &msgs[1];
    
    if((retval = conv->conv(2, pmsgs, &resp, conv->appdata_ptr)) != PAM_SUCCESS)
        return retval;

    if(!resp)
        return PAM_AUTHTOK_RECOVER_ERR;
    if(strcmp(resp[0].resp, resp[1].resp) != 0)
        return PAM_AUTHTOK_RECOVER_ERR;

    retval = pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
    memset(resp[0].resp, 0, strlen(resp[0].resp));
    memset(resp[1].resp, 0, strlen(resp[1].resp));
    free(resp[0].resp);
    free(resp[1].resp);
    free(resp);

    if(retval == PAM_SUCCESS) {
        item = NULL;
        retval = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&item);
        *passp = item;
    }

	PAM_DEBUG ("pam::exo::pam_get_confirm_pass()::return");
    return retval;
}
