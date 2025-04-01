#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_PATH "/etc/bluetooth_auth.db"
#define SCAN_DURATION 45  // seconds to wait during scan

// Helper function: Check if a given MAC exists in our database file.
int is_mac_authorized(const char *mac, pam_handle_t *pamh) {
    FILE *db = fopen(DB_PATH, "r");
    if (!db) {
        pam_syslog(pamh, LOG_ERR, "Could not open database file: %s", DB_PATH);
        return 0;
    }
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), db)) {
        // Remove trailing newline
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, mac) == 0) {
            found = 1;
            break;
        }
    }
    fclose(db);
    return found;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    // Unblock Bluetooth using rfkill.
    int rfkill_ret = system("rfkill unblock bluetooth");
    if (rfkill_ret != 0) {
        pam_syslog(pamh, LOG_ERR, "rfkill unblock bluetooth command failed");
        return PAM_AUTH_ERR;
    }

    FILE *fp;
    char output_line[512];

    // Start a bluetooth scan and list discovered devices.
    // The command will turn on scanning in the background, wait for SCAN_DURATION seconds, then list devices.
    char command[512];
    snprintf(command, sizeof(command),
             "bluetoothctl scan on & sleep %d; bluetoothctl devices", SCAN_DURATION);

    fp = popen(command, "r");
    if (fp == NULL) {
        pam_syslog(pamh, LOG_ERR, "Failed to run bluetoothctl command");
        return PAM_AUTH_ERR;
    }

    int auth_success = 0;
    while (fgets(output_line, sizeof(output_line), fp) != NULL) {
        // Expected output format: "Device XX:XX:XX:XX:XX:XX <DeviceName>"
        char *token = strtok(output_line, " ");
        if (token && strcmp(token, "Device") == 0) {
            char *mac = strtok(NULL, " ");
            if (mac) {
                pam_syslog(pamh, LOG_DEBUG, "Found device with MAC: %s", mac);
                if (is_mac_authorized(mac, pamh)) {
                    pam_syslog(pamh, LOG_INFO, "Authorized bluetooth device found: %s", mac);
                    auth_success = 1;
                    break;
                }
            }
        }
    }
    pclose(fp);

    if (auth_success) {
        return PAM_SUCCESS;
    } else {
        pam_syslog(pamh, LOG_INFO, "No authorized bluetooth device found");
        return PAM_AUTH_ERR;
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {
    // This module does not manipulate credentials.
    return PAM_SUCCESS;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_bluetooth_auth");
#endif
