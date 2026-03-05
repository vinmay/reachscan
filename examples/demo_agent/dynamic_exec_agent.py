"""
Demo agent showing dynamic execution patterns.
This file is designed to be *scanned* (statically) by reachscan.

It does not execute any dynamic code by default; functions are not called.
"""

# Built-in dynamic execution

def eval_example():
    return eval("1 + 1")


def exec_example():
    exec("x = 42")
    return locals().get("x")


def compile_example():
    code = compile("2 + 2", "<string>", "eval")
    return eval(code)


# Dynamic import patterns

def importlib_example():
    import importlib
    return importlib.import_module("json")


def runpy_example():
    import runpy
    return runpy.run_module("json")


if __name__ == "__main__":
    print("This demo file is meant for static scanning only.")
