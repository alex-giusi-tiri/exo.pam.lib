/*
	Copyright (C) 2000 Leon Breedt
	Copyright (C) 2002 David D. W. Downey
*/

#include <security/pam_modules.h>
#include <stddef.h>
#include "pam_service.h"

const char * pam_get_service (const pam_handle_t * pamh)
{
	const char * service;

	service = NULL;
	
	if (pam_get_item (pamh, PAM_SERVICE, (void *) &service) != PAM_SUCCESS)
		return NULL;
	
	return service;
}
