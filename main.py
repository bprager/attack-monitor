#!/usr/bin/env python3
import attack_monitor as monitor
import logging

DATABASE = "./attack.db"
REFRESH = 2
FORMAT = "%(asctime)s - %(funcName)s, %(line)s, %(levelname)s: %(message)s"

# create logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
# create file handler and set level to debug
sh = logging.StreamHandler()
sh.setLevel(logging.INFO)
log.addHandler(sh)
fh = logging.FileHandler("attack_monitor.log")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter(FORMAT))
log.addHandler(fh)


def main():
    am = monitor.AttackMonitor(db=DATABASE, refresh=REFRESH)
    log.debug(" calling run")
    am.run()


if __name__ == "__main__":
    main()
