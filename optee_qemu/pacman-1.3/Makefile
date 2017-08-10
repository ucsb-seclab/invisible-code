prefix=/tmp
bindir=$(prefix)/bin
datarootdir=$(prefix)/share

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

all:
	$(CC) pacman.c     -o pacman -static -DDATAROOTDIR=\"$(datarootdir)\" -I../ncurses-6.0/include -L../ncurses-6.0/lib $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lncurses
	$(CC) pacmanedit.c -o pacmanedit -DDATAROOTDIR=\"$(datarootdir)\" -I../ncurses-6.0/include -L../ncurses-6.0/lib $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lncurses

install:    all
	mkdir -p $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(datarootdir)/pacman
	cp -fR Levels/ $(DESTDIR)$(datarootdir)/pacman/
	-chown root:games $(DESTDIR)$(bindir)/pacman
	-chown root:games $(DESTDIR)$(datarootdir)/pacman -R
	chmod 750 $(DESTDIR)$(bindir)/pacman
	chmod 750 $(DESTDIR)$(bindir)/pacmanedit
	chmod 750 $(DESTDIR)$(datarootdir)/pacman/ -R

uninstall:
	rm -f $(DESTDIR)$(bindir)/pacman
	rm -f $(DESTDIR)$(bindir)/pacmanedit
	rm -f $(DESTDIR)$(datarootdir)/pacman/Levels/level0[1-9].dat
	rm -f $(DESTDIR)$(datarootdir)/pacman/Levels/README
	rm -f $(DESTDIR)$(datarootdir)/pacman/Levels/template.dat
	if [ -e $(DESTDIR)$(datarootdir)/pacman/Levels/ ] ; then rmdir $(DESTDIR)$(datarootdir)/pacman/Levels/ ; fi
	if [ -e $(DESTDIR)$(datarootdir)/pacman/ ] ; then rmdir $(DESTDIR)$(datarootdir)/pacman/ ; fi

clean:	uninstall
	rm -f pacman
	rm -f pacmanedit
