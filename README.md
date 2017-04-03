pam_succeed_if_rhost - test rhost network membership
====================================================
With this module you can manipulate the pam stack based on where the user is
coming from. For example, you can require that users coming from an external
network provide a second factor for authentication.

Example 1: must come from a special host
----------------------------------------
```
auth    requisite   pam_succeed_if_rhost.so 192.168.12.0/28 gatekeeper*.company.com
auth    required    pam_unix.so
```

Example 2: no system authentication for non-local users
-------------------------------------------------------
```
auth    [success=ok,default=1]      pam_succeed_if_rhost.so 10.0.0.0/8
auth    required                    pam_unix.so
auth    required                    pam_ldap.so
```

Example 3: Two-factor authentication required unless you're on a special network
--------------------------------------------------------------------------------
```
auth    required                    pam_sss.so
auth    [success=ok,default=1]      pam_succeed_if_rhost.so !172.16.3.0/24
auth    required                    pam_radius_auth.so prompt=TokenCode force_prompt
```

Arguments to the model can be of 4 forms:

* `quiet`, to make the module not log all match attempts
* `10.0.0.0/8`, to match an ipv4 address with optional netmask
* `fe80::/10`, to match an ipv6 address with optional netmask
* `hostname*.company.com`, to match a hostname with wildcards

Match arguments can be prefixed with a `!` to negate the match. You can specify
multiple networks, or a combination of hostnames and networks. A match will
succeed if any argument matches.
