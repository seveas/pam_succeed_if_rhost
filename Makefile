all: pam_succeed_if_rhost.so

clean:
	rm -f pam_succeed_if_rhost.so

pam_succeed_if_rhost.so: pam_succeed_if_rhost.c
	$(CC) -Wall -Werror -shared -fPIC -o $@ $^

.PHONY: all clean dist
