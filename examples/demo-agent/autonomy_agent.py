"""
Demo agent showing autonomy patterns.
This file is designed to be *scanned* (statically) by agent-scan.

It does not run background tasks by default; functions are not called.
"""

import threading


def thread_example():
    t = threading.Thread(target=lambda: None)
    t.start()
    return t


def timer_example():
    t = threading.Timer(5.0, lambda: None)
    t.start()
    return t


def schedule_example():
    import schedule
    schedule.every(10).minutes.do(lambda: None)


def asyncio_example():
    import asyncio
    asyncio.create_task(do_work())


def do_work():
    return None


if __name__ == "__main__":
    print("This demo file is meant for static scanning only.")
