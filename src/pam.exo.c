#include <stdlib.h>
//#include <stdbool.h>
#include <string.h>
#include <security/pam_modules.h>
#include <zmq.h>
#include <zmq/zhelpers.h>
#include "pam.exo.h"

const bool srv_req (char ** value, const char * uri, const char * type, const char * item, const char * content, const char * extra)
{
	if (extra == NULL)
		PAM_DEBUG ("pam::exo::srv_req([%s], [%s], [%s], [%s])::call::beginning", uri, type, item, content);
	else
		PAM_DEBUG ("pam::exo::srv_req([%s], [%s], [%s], [%s], [%s])::call::beginning", uri, type, item, content, extra);
	
	void * context;
	void * socket;
	//const char * user;
	//char * password_provided;
	//char * password_retrieved;
	char * success;
	//int rc;	// return code
	int64_t more;
	size_t more_size;
	// In milliseconds.
	int linger;
	size_t linger_size;
	int timeout;
	size_t timeout_size;
	//user = "test1";
	//password_provided = "test_pw";
	success = NULL;
	more_size = sizeof more;
	linger_size = sizeof linger;
	timeout_size = sizeof timeout;
	// 5 seconds
	linger = 0;
	timeout = 5000;
	context = zmq_ctx_new ();
	socket = zmq_socket (context, ZMQ_DEALER);
	
	
	PAM_DEBUG ("pam::exo::srv_req()::socket.setopt(linger, [%i])", linger);
	if (zmq_setsockopt (socket, ZMQ_LINGER, &linger, linger_size) != 0)
	{
		PAM_DEBUG ("pam::exo::srv_req()::socket.setopt(linger, [%i])::failure", linger);
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::socket.setopt(linger, [%i])::success", linger);
	
	PAM_DEBUG ("pam::exo::srv_req()::socket.setopt(timeout, [%i])", timeout);
	if (zmq_setsockopt (socket, ZMQ_RCVTIMEO, &timeout, timeout_size) != 0)
	{
		PAM_DEBUG ("pam::exo::srv_req()::socket.setopt(timeout, [%i])::failure", timeout);
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::socket.setopt(timeout, [%i])::success", timeout);
	
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
	PAM_DEBUG ("pam::exo::srv_req()::rx(success)");
	success = s_recv (socket);
	PAM_DEBUG ("pam::exo::srv_req()::rx(success)::complete");
	
	PAM_DEBUG ("pam::exo::srv_req()::(success?==NULL)");
	if (success == NULL)
	{
		PAM_DEBUG ("pam::exo::srv_req()::(success==NULL)");
	}
	else
	{
		PAM_DEBUG ("pam::exo::srv_req()::(success!=NULL)");
	}
	
	PAM_DEBUG ("pam::exo::srv_req()::(success?!=1)");
	if (success == NULL || strcmp (success, "1") != 0)
	{
		PAM_DEBUG ("pam::exo::srv_req()::(success!=1)");
		
		PAM_DEBUG ("pam::exo::srv_req()::(success!=1)::free(success)");
		free (success);
		//free (password);
		
		PAM_DEBUG ("pam::exo::srv_req()::(success!=1)::zmq_close(socket)");
		zmq_close (socket);
		PAM_DEBUG ("pam::exo::srv_req()::(success!=1)::zmq_ctx_destroy(context)");
		zmq_ctx_destroy (context);
		
		PAM_DEBUG ("pam::exo::srv_req()::(success!=1)::return false");
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::(success==1)");
	free (success);
	
	PAM_DEBUG ("pam::exo::srv_req()::zmq_getsockopt(more)");
	if (zmq_getsockopt (socket, ZMQ_RCVMORE, &more, &more_size) != 0)
	{
		PAM_DEBUG ("pam::exo::srv_req()::zmq_getsockopt(more)::failure");
		
		//free (success);
		//free (password);
		
		zmq_close (socket);
		zmq_ctx_destroy (context);
		
		return false;
	}
	PAM_DEBUG ("pam::exo::srv_req()::zmq_getsockopt(more)::success");
	
	PAM_DEBUG ("pam::exo::srv_req()::(?!more)\n");
	if (more && value != NULL)
	{
		//PAM_DEBUG ("pam::exo::srv_req()::srv_rx(*value)::...");
		PAM_DEBUG ("pam::exo::srv_req()::s_recv(*value)");
		
		// Get the requested value.
		*value = s_recv (socket);
		
		PAM_DEBUG ("pam::exo::srv_req()::s_recv(*value)::ok");
	}
	PAM_DEBUG ("pam::exo::srv_req()::(!more)::false");
	
	/*
	// Get the requested value.
	PAM_DEBUG ("pam::exo::srv_req()::rx(value)::...");
	if (value != NULL)
		*value = srv_rx (socket);
	PAM_DEBUG ("pam::exo::srv_req()::rx(value)::ok");
	*/
	
	zmq_close (socket);
	zmq_ctx_destroy (context);
	
	if (extra == NULL)
		PAM_DEBUG ("pam::exo::srv_req([%s], [%s], [%s], [%s], NULL)::call::ending", uri, type, item, content);
	else
		PAM_DEBUG ("pam::exo::srv_req([%s], [%s], [%s], [%s], [%s])::call::ending", uri, type, item, content, extra);
	
	return true;
}

/*
const char * srv_rx (void * socket)
{
	zmq_msg_t msg;
	char * tmp;
	
	if (zmq_msg_init (&msg) != 0)
		return NULL;
	
	if (zmq_recv (socket, &msg, 0, ZMQ_NOBLOCK) != 0)
		return NULL;
	
	tmp = strdup ((const char *) zmq_msg_data (&msg));
	zmq_msg_close (&msg);
	return tmp;
}
*/
