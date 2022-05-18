#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	char* mac = "14:07:1D:04:28:3D"; //enter mac address of device
	char cmd[100] = "";
	
	/*snprintf(cmd, sizeof(cmd), "bluetoothctl -- info %s | grep -q 'Connected: yes'", mac);
	int x = system(cmd);
	if (x != 0){
		snprintf(cmd, sizeof(cmd), "bluetoothctl disconnect %s", mac);
		system(cmd);
		return PAM_SUCCESS;
	}*/
	
	snprintf(cmd, sizeof(cmd), "rfkill unblock bluetooth && timeout 5 bluetoothctl -- connect %s > /dev/null 2>&1", mac);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "bluetoothctl -- info %s | grep -q 'Connected: yes'", mac);
	int x = system(cmd);
	if (x != 0){
		return PAM_IGNORE;
	}
	snprintf(cmd, sizeof(cmd), "bluetoothctl disconnect %s > /dev/null 2>&1", mac);
	system(cmd);
	return PAM_SUCCESS;
	//return PAM_IGNORE;
}

