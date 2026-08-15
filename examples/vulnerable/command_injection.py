"""Deliberately vulnerable example: OS command injection (CWE-78)."""
import os
import subprocess


def ping_host(host: str) -> str:
    """Ping a user-supplied host — vulnerable to command injection."""
    # vulnforge-static: command-injection
    return os.system("ping -c 4 " + host)


def convert_file(filename: str) -> str:
    """Shell out to ImageMagick with shell=True — vulnerable."""
    # vulnforge-static: command-injection
    return subprocess.getoutput("convert " + filename + " out.png")
