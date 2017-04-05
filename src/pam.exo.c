#include <stdlib.h>
#include <string.h>
#include <security/pam_modules.h>
#include <zmq.h>
#include <zmq/zhelpers.h>
#include "pam.exo.h"

const bool srv_req (char ** value, const char * uri, const char * type, const char * item, const char * content, const char * extra)
{
	PAM_DEBUG ("pam::exo::srv_req([%s], [%s], [%s], [%s], [%s])::call::beginning", uri, type, item, content, extra);
	
	void * context;
	void * socket;
	//const char * user;
	//char * password_provided;
	//char * password_retrieved;
	char * success;
	//int rc;	// return code
	
	//user = "test1";
	//password_provided = "test_pw";
	success = NULL;
	context = zmq_ctx_new ();
	socket = zmq_socket (context, ZMQ_DEALER);
	
	
	PAM_DEBUG ("pam::exo::srv_req()::socket.connect()");
	//if (zmq_connect (socket, "tcp://0.0.0.0:2231") != 0)
	if (zmq_connect (socket, uri) != 0)
	{
		PAM_DEBUG ("pam::exo::srv_req()::socket.connect()::failure");
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::socket.connect()::success");
	
	//zclock_sleep (200);
	
	
	// Send the request ("ask for the password by user name") (in parts):
	PAM_DEBUG ("pam::exo::srv_req()::tx(type)");
	if (s_sendmore (socket, type) < strlen (type))
	{
		PAM_DEBUG ("pam::exo::srv_req()::tx(type)::failure");
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::tx(type)::success");
	
	PAM_DEBUG ("pam::exo::srv_req()::tx(item)");
	if (s_sendmore (socket, item) < strlen (item))
	{
		PAM_DEBUG ("pam::exo::srv_req()::tx(item)::failure");
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::tx(item)::success");
	
	if (extra == NULL)
	{
		PAM_DEBUG ("pam::exo::srv_req()::tx(content)");
		if (s_send (socket, content) < strlen (content))
		{
			PAM_DEBUG ("pam::exo::srv_req()::tx(content)::failure");
			
			zmq_close (socket);
			zmq_ctx_destroy (context);
			
			return false;
		}
		PAM_DEBUG ("pam::exo::srv_req()::tx(content)::success");
	}
	else
	{
		PAM_DEBUG ("pam::exo::srv_req()::tx(content)");
		if (s_sendmore (socket, content) < strlen (content))
		{
			PAM_DEBUG ("pam::exo::srv_req()::tx(content)::failure");
			
			zmq_close (socket);
			zmq_ctx_destroy (context);
			
			return false;
		}
		PAM_DEBUG ("pam::exo::srv_req()::tx(content)::success");
		
		PAM_DEBUG ("pam::exo::srv_req()::tx(extra)");
		if (s_send (socket, extra) < strlen (extra))
		{
			PAM_DEBUG ("pam::exo::srv_req()::tx(extra)::failure");
			
			zmq_close (socket);
			zmq_ctx_destroy (context);
			
			return false;
		}
		PAM_DEBUG ("pam::exo::srv_req()::tx(extra)::success");
	}
	
	// Get the success status:
	PAM_DEBUG ("pam::exo::srv_req()::rx(success)::...");
	success = s_recv (socket);
	PAM_DEBUG ("pam::exo::srv_req()::rx(success)::complete");
	
	PAM_DEBUG ("pam::exo::srv_req()::(success?!=true)\n");
	if (strcmp (success, "1") != 0)
	{
		PAM_DEBUG ("pam::exo::srv_req()::(success!=1)\n");
		
		free (success);
		//free (password);
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::(success==1)\n");
	free (success);
	
	// Get the requested value.
	PAM_DEBUG ("pam::exo::srv_req()::rx(value)::...");
	if (value != NULL)
		*value = s_recv (socket);
	PAM_DEBUG ("pam::exo::srv_req()::rx(value)::ok");
	
	
	zmq_close (socket);
	zmq_ctx_destroy (context);
	
	
	PAM_DEBUG ("pam::exo::srv_req([%s], [%s], [%s], [%s], [%s])::call::ending", uri, type, item, content, extra);
	
	return true;
}
