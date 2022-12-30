#!/usr/bin/env python3
import attack_monitor as monitor

DATABASE = "./attack.db"
REFRESH = 3


def main():
    am = monitor.AttackMonitor(db=DATABASE, refresh=REFRESH)
    am.run()


if __name__ == "__main__":
    main()
