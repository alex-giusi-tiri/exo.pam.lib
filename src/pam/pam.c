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
		PAM_DEBUG ("pam::exo::pam_sm_authenticate()::(%s) user [%s] authentication failed::incorrect password", pam_get_service (pamh), user);
		//PAM_DEBUG ("pam::exo::pam_sm_authenticate()::user [%s] authentication failed::incorrect password", user);
		
		free (password_retrieved);
		
		return PAM_AUTH_ERR;
	}
	
	free (password_retrieved);
	
	PAM_DEBUG ("pam::exo::pam_sm_authenticate()::(%s) user [%s] authenticated", pam_get_service (pamh), user);
	//PAM_DEBUG ("pam::exo::pam_sm_authenticate()::(%s) user [%s] authenticated", pam_get_service (pamh), user);
	
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
	PAM_DEBUG ("pam::exo::pam_sm_chauthtok()...");
	
	char * user;
	char * password_provided;
	char * password_retrieved;
	char * password_new;
	//char * password_confirmation;
	//char * success;
	int rc;	// return code
	
	
	// Get the user name.
	PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_user()...");
	rc = pam_get_user (pamh, &user, NULL);
	if (rc != PAM_SUCCESS)
	{
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_user()::failure");
		
		return rc;
	}
	PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_user()::success");
	
	// Now, set the new password.
	
	if (flag & PAM_PRELIM_CHECK)
	{
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::if(flag & PAM_PRELIM_CHECK)");
		
		// at this point, this is the first time we get called
		
		// Ask for the new password.
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_pass()...");
		rc = pam_get_pass (pamh, &password_provided, "Old Password: ", 0);
		
		if (rc == PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_pass()::success");
			
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()...");
			if (!srv_req (&password_retrieved, SERVER_URI, "get", "password", user, NULL))
			{
				PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()::failure");
				return PAM_AUTH_ERR;
			}
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()::success");
			
			//rc = auth_verify_password (user, pass, options);
			
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::if::strcmp(pw,pw)...");
			if (strcmp (password_provided, password_retrieved) == 0)
			{
				PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::strcmp(pw,pw)==0");
				
				PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_set_item()...");
				rc = pam_set_item (pamh, PAM_OLDAUTHTOK, (const void *) password_retrieved);
				
				if (rc != PAM_SUCCESS)
				{
					PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_set_item()::failure");
					//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::failed to set PAM_OLDAUTHTOK");
					
					free (password_retrieved);
				}
				PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_set_item()::success");
				//free_module_options(options);
				return rc;
			}
			else
			{
				PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::strcmp(pw,pw)!=0");
				//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::password verification failed for user [%s]", user);
				
				free (password_retrieved);
				
				return PAM_AUTH_ERR;
			}
		}
		else
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_pass()::failure");
			//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not retrieve password from user [%s]", user);
			
			return PAM_AUTH_ERR;
		}
	}
	else if (flag & PAM_UPDATE_AUTHTOK)
	{
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::else if(flag & PAM_UPDATE_AUTHTOK)");
		
		password_new = NULL;
		//password_confirmation = NULL;
		
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_item()...");
		rc = pam_get_item (pamh, PAM_OLDAUTHTOK, (const void **) &password_provided);
		if (rc != PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_item():failure");
			//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not retrieve old token");
			//free_module_options (options);
			return rc;
		}
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_item()::success");
		
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()...");
		if (!srv_req (&password_retrieved, SERVER_URI, "get", "password", user, NULL))
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()::failure");
			return PAM_AUTH_ERR;
		}
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()::success");
		
		//rc = auth_verify_password (user, pass, options);
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::if::strcmp(pw,pw)...");
		if (strcmp (password_provided, password_retrieved) != 0)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::if::strcmp(pw,pw)!=0");
			//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::(%s) user [%s] not authenticated.", pam_get_service (pamh), user);
			
			//free_module_options(options);
			free (password_retrieved);
			
			return rc;
		}
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::if::strcmp(pw,pw)==0");
		
		// get and confirm the new password
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_confirm_pass()...");
		rc = pam_get_confirm_pass (pamh, &password_new, PASSWORD_PROMPT_NEW, PASSWORD_PROMPT_CONFIRMATION, 0);
		if (rc != PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_confirm_pass()::failure");
			//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not retrieve new authentication tokens");
			
			//free_module_options(options);
			free (password_retrieved);
			
			return rc;
		}
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_get_confirm_pass()::success");
		
		// save the new password for subsequently stacked modules
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_set_item()...");
		rc = pam_set_item(pamh, PAM_AUTHTOK, (const void *) password_new);
		if (rc != PAM_SUCCESS)
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_set_item()::failure");
			//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not set PAM_AUTHTOK");
			
			//free_module_options(options);
			free (password_retrieved);
			
			return rc;
		}
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::pam_set_item()::success");
		
		// update the database
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()...");
		if (!srv_req (NULL, SERVER_URI, "set", "password", user, password_new))
		{
			PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()::failure");
			//PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::could not set new password");
			
			free (password_retrieved);
			
			return PAM_AUTH_ERR;
		}
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::srv_req()::success");
		
		PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::new password has been set");
		
		//free (success);
	}
	
	
	free (password_retrieved);
	
	
	PAM_DEBUG ("pam::exo::pam_sm_chauthtok()::done");
	
	return PAM_SUCCESS;
}
