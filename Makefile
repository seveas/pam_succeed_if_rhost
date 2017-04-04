VERSION  = 0.1
NAME     = pam_succeed_if_rhost
SOURCES  = $(NAME).c
SOURCES += Makefile
SOURCES += README.md
SOURCES += LICENSE

all: $(NAME).so

clean:
	rm -f $(NAME).so
	rm -f $(NAME)-$(VERSION).tar.gz

$(NAME).so: $(NAME).c
	$(CC) -Wall -Werror -shared -fPIC -o $@ $^

dist: $(NAME)-$(VERSION).tar.gz

$(NAME)-$(VERSION).tar.gz: $(SOURCES)
	tar -zcvf $@ --transform=s,^,$(NAME)-$(VERSION)/, --sort=name $^

.PHONY: all clean dist
