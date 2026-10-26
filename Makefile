PREFIX?=/usr/local
TARGET?=release

.PHONY: all
all:
	cargo build --profile $(TARGET)

.PHONY: install
install:
	install -D -m755 ./target/$(TARGET)/userdomain-daemon             "$(PREFIX)/bin/userdomain-daemon"
	install -D -m755 ./target/$(TARGET)/userdomain                    "$(PREFIX)/bin/userdomain"
	install -D -m755 ./target/$(TARGET)/libnss_userdomain.so          "$(PREFIX)/lib/libnss_userdomain.so.2"
	install -D -m644 ./data/lib/systemd/system/userdomain.service     "$(PREFIX)/lib/systemd/system/userdomain.service"
	install -D -m644 ./data/lib/sysusers.d/userdomain-daemon.conf     "$(PREFIX)/lib/sysusers.d/userdomain-daemon.conf"
	install -D -m644 ./data/share/dbus-1/system.d/org.UserDomain.conf "$(PREFIX)/share/dbus-1/system.d/org.UserDomain.conf"
	@if [ $(PREFIX) = /usr/local ] && ! [ -e /etc/dbus-1/system.d/org.UserDomain.conf ]; then \
		echo -e "\033[0;33mWarn:\033[0m"; \
		echo -e "\033[0;33mWarn:\033[0m DBus policy configuration have be installed to $(PREFIX)/share/dbus-1/system.d/org.UserDomain.conf."; \
		echo -e "\033[0;33mWarn:\033[0m By default DBus will only look into /usr and /etc but not /usr/local for policy configuration."; \
		echo -e "\033[0;33mWarn:\033[0m You may want to create the following symbolic link:"; \
		echo -e "\033[0;33mWarn:\033[0m     /etc/dbus-1/system.d/org.UserDomain.conf -> $(PREFIX)/share/dbus-1/system.d/org.UserDomain.conf"; \
		echo -e "\033[0;33mWarn:\033[0m This can be done by symlinking entire directory:"; \
		echo -e "\033[0;33mWarn:\033[0m     ln -sf $(PREFIX)/share/dbus-1 /etc/dbus-1"; \
		echo -e "\033[0;33mWarn:\033[0m Alternatively symlink only the required files if you have existing configuration in /etc/dbus-1/system.d:"; \
		echo -e "\033[0;33mWarn:\033[0m     ln -sf $(PREFIX)/share/dbus-1/system.d/org.UserDomain.conf /etc/dbus-1/system.d/org.UserDomain.conf"; \
		echo -e "\033[0;33mWarn:\033[0m"; \
	fi
	echo -e "\033[0;32mInfo:\033[0m"; \
	echo -e "\033[0;32mInfo:\033[0m Installation Completed."; \
	echo -e "\033[0;32mInfo:\033[0m"; \
	echo -e "\033[0;32mInfo:\033[0m It is a good time to configure nsswitch.conf(5) if you have not already."; \
	echo -e "\033[0;32mInfo:\033[0m See README.md for more details."; \
	echo -e "\033[0;32mInfo:\033[0m"; \

.PHONY: uninstall
uninstall:
	-rm -f "$(PREFIX)/bin/userdomain-daemon"
	-rm -f "$(PREFIX)/bin/userdomain"
	-rm -f "$(PREFIX)/lib/libnss_userdomain.so.2"
	-rm -f "$(PREFIX)/lib/systemd/system/userdomain.service"
	-rm -f "$(PREFIX)/lib/sysusers.d/userdomain-daemon.conf"
	-rm -f "$(PREFIX)/share/dbus-1/system.d/org.UserDomain.conf"
