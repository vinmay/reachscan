from agent_scan.detectors.autonomy import scan_file

def test_thread_start():
    src = 'import threading\nt = threading.Thread(target=lambda: None)\nt.start()'
    findings = scan_file("demo.py", src)
    assert any(f.capability == "AUTONOMY" for f in findings)


def test_asyncio_create_task():
    src = 'import asyncio\nasyncio.create_task(do_work())'
    findings = scan_file("demo.py", src)
    assert any("asyncio.create_task" in f.evidence or f.capability == "AUTONOMY" for f in findings)


def test_schedule_every():
    src = 'import schedule\nschedule.every(10).minutes.do(lambda: None)'
    findings = scan_file("demo.py", src)
    assert any("schedule.every" in f.evidence or f.capability == "AUTONOMY" for f in findings)
