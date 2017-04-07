#define _GNU_SOURCE

#include <arpa/inet.h>
#include <fnmatch.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define MAX_HOST_NAME_LEN 256

static int succeed_if(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *rhost, r_name[MAX_HOST_NAME_LEN], m_name[MAX_HOST_NAME_LEN], *pos, *end;
    const char *arg;
    struct sockaddr_in r_ipv4, m_ipv4;
    struct sockaddr_in6 r_ipv6, m_ipv6;
    struct addrinfo *address, *addresses;
    int quiet = 0, match, ret, netmask, negate, ai, i;
    unsigned int mask;
    unsigned char mask6[16];
    int r_ipv4_valid = 0, r_ipv6_valid = 0, r_name_valid = 0;

    for(i=0; i<argc; i++) {
        if(strcmp(argv[i], "quiet") == 0)
            quiet = 1;
    }

    /*
     * Step one: collecting info
     *
     * PAM_RHOST is fetched from the application. If it's a valid ip address, a
     * hostname lookup will be done. If it's not a valid IP address, we assume
     * it's a hostname and the ip will be looked up.
     */

    ret = pam_get_item(pamh, PAM_RHOST, (const void**)&rhost);
    if(ret != PAM_SUCCESS)
        return PAM_SYSTEM_ERR;

    if((inet_pton(AF_INET, rhost, &r_ipv4.sin_addr.s_addr) == 1)) {
        r_ipv4_valid = 1;
        if(getnameinfo((const struct sockaddr *)&r_ipv4, sizeof(&r_ipv4), rhost, MAX_HOST_NAME_LEN, NULL, 0, 0) == 0)
            r_name_valid = 1;
    }
    else if(inet_pton(AF_INET6, rhost, &r_ipv6.sin6_addr.s6_addr) == 1) {
        r_ipv6_valid = 1;
        if(getnameinfo((const struct sockaddr *)&r_ipv6, sizeof(&r_ipv6), rhost, MAX_HOST_NAME_LEN, NULL, 0, 0) == 0)
            r_name_valid = 1;
    }
    else {
        strncpy(r_name, rhost, MAX_HOST_NAME_LEN-1);
        r_name[MAX_HOST_NAME_LEN-1] = '\0';
        r_name_valid = 1;
        if(getaddrinfo(r_name, NULL, NULL, &addresses) == 0) {
            address = addresses;
            while(address) {
                if(address->ai_family == AF_INET && !r_ipv4_valid) {
                    r_ipv4.sin_addr.s_addr = ((struct sockaddr_in*)(address->ai_addr))->sin_addr.s_addr;
                    r_ipv4_valid = 1;
                }
                if(address->ai_family == AF_INET6 && !r_ipv6_valid) {
                    memcpy(&(r_ipv6.sin6_addr), &((struct sockaddr_in6*)(address->ai_addr))->sin6_addr, sizeof(r_ipv6.sin6_addr));
                    r_ipv6_valid = 1;
                }
                address = address->ai_next;
            }
            freeaddrinfo(addresses);
        }
    }

    /*
     * Step two: matching
     * Arguments to this module can be of the form ipv4-address[/netmask],
     * ipv6-address[/netmask] or hostname*wildcard*
     *
     * ipv4 arguments will only be checked against rhosts with a valid ipv4
     * address, similar for ipv6 arguments. Hostname arguments will only be
     * checked if a host has a valid hostname.
     *
     * Arguments can be prefixed with a ! to negate their meaning.
     */
    for(ai=0; ai<argc; ai++) {
        arg = argv[ai];
        netmask = -1;
        if(strcmp(arg, "quiet") == 0)
            continue;
        if(arg[0] == '!') {
            strncpy(m_name, arg+1, MAX_HOST_NAME_LEN-1);
            negate = 1;
        }
        else {
            strncpy(m_name, arg, MAX_HOST_NAME_LEN-1);
            negate = 0;
        }
        m_name[MAX_HOST_NAME_LEN-1] = '\0';
        netmask = -1;
        if((pos = strrchr(m_name, '/')) && *(pos+1)) {
            netmask = strtol(pos+1, &end, 10);
            if(end)
                *pos = '\0';
        }
        if(inet_pton(AF_INET, m_name, &(m_ipv4.sin_addr.s_addr)) == 1) {
            if(r_ipv4_valid) {
                mask = 0;
                if(netmask < 0)
                    netmask = 32;
                if(netmask > 32) {
                    pam_syslog(pamh, LOG_ERR, "Invalid netmask in %s", arg);
                    continue;
                }
                for(i=0; i<netmask; i++) {
                    mask |= 1<<(31-i);
                }
                mask = htonl(mask);
                if(((r_ipv4.sin_addr.s_addr & mask) == (m_ipv4.sin_addr.s_addr & mask)) == !negate) {
                    if(!quiet)
                        pam_syslog(pamh, LOG_INFO, "%s matches %s", rhost, arg);
                    return PAM_SUCCESS;
                }
                if(!quiet)
                    pam_syslog(pamh, LOG_INFO, "%s does not match %s", rhost, arg);
            }
        }
        else if(inet_pton(AF_INET6, m_name, &m_ipv6.sin6_addr) == 1) {
            if(r_ipv6_valid) {
                if(netmask < 0)
                    netmask = 128;
                if(netmask > 128) {
                    pam_syslog(pamh, LOG_ERR, "Invalid netmask in %s", arg);
                    continue;
                }
                memset(mask6, 0, 16);
                for(i=0; i<netmask; i++) {
                    mask6[i/8] |= 1<<(7-(i%8));
                }
                match = 1;
                for(i=0; i<16; i++) {
                    if((r_ipv6.sin6_addr.s6_addr[i] & mask6[i]) != (m_ipv6.sin6_addr.s6_addr[i] & mask6[i])) {
                        match = 0;
                        break;
                    }
                }
                if(match != negate) {
                    if(!quiet)
                        pam_syslog(pamh, LOG_INFO, "%s matches %s", rhost, arg);
                    return PAM_SUCCESS;
                }
                if(!quiet)
                    pam_syslog(pamh, LOG_INFO, "%s does not match %s", rhost, arg);
            }
        }
        else {
            if(r_name_valid) {
                ret = fnmatch(m_name, r_name, FNM_CASEFOLD|FNM_EXTMATCH);
                if(ret != 0 && ret != FNM_NOMATCH) {
                    pam_syslog(pamh, LOG_INFO, "Error while matching %s against %s", r_name, m_name);
                    return PAM_SYSTEM_ERR;
                }
                if(ret == negate) {
                    if(!quiet)
                        pam_syslog(pamh, LOG_INFO, "%s matches %s", r_name, arg);
                    return PAM_SUCCESS;
                }
                if(!quiet)
                    pam_syslog(pamh, LOG_INFO, "%s does not match %s", r_name, arg);
            }
        }
    }
    if(!quiet)
        pam_syslog(pamh, LOG_INFO, "No match found for %s", rhost);
    return PAM_AUTH_ERR;
}

/* The actual pam functions are merely wrappers around succeed_if */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return succeed_if(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return succeed_if(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return succeed_if(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return succeed_if(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return succeed_if(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return succeed_if(pamh, flags, argc, argv);
}
