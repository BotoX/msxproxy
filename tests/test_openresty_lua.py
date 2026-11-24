"""Pytest wrappers that execute OpenResty Lua unit & E2E suites with LuaJIT."""
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("script_name", ["test_openresty.lua", "test_openresty_e2e.lua"])
def test_openresty_lua_suite(script_name):
    luajit = shutil.which("luajit")
    if not luajit:
        pytest.skip("luajit not installed")

    script = Path(__file__).resolve().parent / script_name
    res = subprocess.run([luajit, str(script)], capture_output=True, text=True)
    assert res.returncode == 0, f"{script_name} failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
