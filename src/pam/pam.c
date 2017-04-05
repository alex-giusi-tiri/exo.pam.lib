#include "../pam.exo.h"
#include "../pam_pass.h"
#include "../pam_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
//#include <crypt.h>
#include <security/pam_modules.h>

#include <zmq.h>
#include <zmq/zhelpers.h>


// Expected hook.
// public: just succeed.
PAM_EXTERN int pam_sm_setcred (pam_handle_t * pamh, int flag, int argc, const char ** argv)
{
	return PAM_SUCCESS;
}

// Expected hook.
// PAM authorization check.
// public: check if account has expired, or needs new password
PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t * pamh, int flag, int argc, const char ** argv)
{
	// We do not need to do anything here.
	//printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

// PAM authentication check.
// This is where custom stuff happens.
PAM_EXTERN int pam_sm_authenticate (pam_handle_t * pamh, int flag, int argc, const char ** argv)
{
	PAM_DEBUG ("pam::exo::pam_sm_authenticate()::beginning");
	
	//void * context;
	//void * socket;
	const char * user;
	char * password_provided;
	char * password_retrieved;
	//char * success;
	int rc;	// return code
	
	//user = "test1";
	//password_provided = "test_pw";
	//success = NULL;
	//context = zmq_ctx_new ();
	//socket = zmq_socket (context, ZMQ_DEALER);
	
	PAM_DEBUG ("pam::exo::pam_sm_authenticate()::get::user");
	
	// Get the user name.
	rc = pam_get_user (pamh, &user, NULL);
	if (rc != PAM_SUCCESS)
		return rc;
	
	// Get the password from the user.
	rc = pam_get_pass (pamh, &password_provided, PASSWORD_PROMPT, 0);
	if (rc != PAM_SUCCESS)
		return rc;
	
	// Get the password from the server.
	if (!srv_req (&password_retrieved, SERVER_URI, "get", "password", user, NULL))
	{
		return PAM_AUTH_ERR;
	}
	
	if (strcmp (password_provided, password_retrieved) != 0)
	{
		PAM_DEBUG ("(%s) user [%s] authentication failed::incorrect password", pam_get_service (pamh), user);
		
		free (password_retrieved);
		
		return PAM_AUTH_ERR;
	}
	
	free (password_retrieved);
	
	PAM_DEBUG ("(%s) user [%s] authenticated", pam_get_service (pamh), user);
	
	return PAM_SUCCESS;
}

/*
	Change the password of the user.
	This function is first called with PAM_PRELIM_CHECK set in the flags
	and then without the flag.
	In the first pass, it is determined whether we can contact the LDAP server
	and the provided old password is valid.
	In the second pass we get the new password and actually modify the password.
*/
PAM_EXTERN int pam_sm_chauthtok (pam_handle_t * pamh, int flag, int argc, const char ** argv)
{
	PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::beginning");
	
	char * user;
	char * password_provided;
	char * password_retrieved;
	char * password_new;
	//char * password_confirmation;
	//char * success;
	int rc;	// return code
	
	
	// Get the user name.
	rc = pam_get_user (pamh, &user, NULL);
	if (rc != PAM_SUCCESS)
	{
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not get user name");
		
		return rc;
	}
	
	// Now, set the new password.
	
	if (flag & PAM_PRELIM_CHECK)
	{
		// at this point, this is the first time we get called
		
		// Ask for the new password.
		rc = pam_get_pass (pamh, &password_provided, "Old Password: ", 0);
		
		if (rc == PAM_SUCCESS)
		{
			if (!srv_req (&password_retrieved, SERVER_URI, "get", "password", user, NULL))
			{
				return PAM_AUTH_ERR;
			}
			
			//rc = auth_verify_password (user, pass, options);
			
			if (strcmp (password_provided, password_retrieved) == 0)
			{
				rc = pam_set_item (pamh, PAM_OLDAUTHTOK, (const void *) password_retrieved);
				
				if (rc != PAM_SUCCESS)
				{
					PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::failed to set PAM_OLDAUTHTOK");
					
					free (password_retrieved);
				}
				//free_module_options(options);
				return rc;
			}
			else
			{
				PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::password verification failed for user [%s]", user);
				
				free (password_retrieved);
				
				return rc;
			}
		}
		else
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not retrieve password from user [%s]", user);
			
			return PAM_AUTH_ERR;
		}
	}
	else if (flag & PAM_UPDATE_AUTHTOK)
	{
		password_new = NULL;
		//password_confirmation = NULL;
		
		rc = pam_get_item (pamh, PAM_OLDAUTHTOK, (const void **) &password_provided);
		if (rc != PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not retrieve old token");
			//free_module_options (options);
			return rc;
		}
		
		if (!srv_req (&password_retrieved, SERVER_URI, "get", "password", user, NULL))
			return PAM_AUTH_ERR;
		
		//rc = auth_verify_password (user, pass, options);
		if (strcmp (password_provided, password_retrieved) != 0)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::(%s) user [%s] not authenticated.", pam_get_service (pamh), user);
			
			//free_module_options(options);
			free (password_retrieved);
			
			return rc;
		}
		
		// get and confirm the new password
		rc = pam_get_confirm_pass (pamh, &password_new, PASSWORD_PROMPT_NEW, PASSWORD_PROMPT_CONFIRMATION, 0);
		if (rc != PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not retrieve new authentication tokens");
			
			//free_module_options(options);
			free (password_retrieved);
			
			return rc;
		}
		
		// save the new password for subsequently stacked modules
		rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *) password_new);
		if(rc != PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not set PAM_AUTHTOK");
			
			//free_module_options(options);
			free (password_retrieved);
			
			return rc;
		}
		
		// update the database
		if (!srv_req (NULL, SERVER_URI, "set", "password", user, password_new))
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not set new password");
			
			free (password_retrieved);
			
			return PAM_AUTH_ERR;
		}
		
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::new password has been set");
		
		//free (success);
	}
	
	
	free (password_retrieved);
	
	
	PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::complete");
	
	return PAM_SUCCESS;
}
