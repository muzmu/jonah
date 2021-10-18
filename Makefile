
install: jonah.service
	@cp jonah.service /etc/systemd/system/jonah.service
	@sudo systemctl daemon-reload
	@echo "daemonizing jonah..."
	@sudo systemctl enable jonah.service
	@sudo systemctl start jonah.service
	@sudo systemctl status jonah.service

uninstall:
	@sudo systemctl stop jonah.service
	@sudo rm -rf /etc/systemd/system/jonah.service

clean:
	rm -f jonah.o jonah jonah.log

