import subprocess
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "anchor"


def test_debug_openssl_on_runner():
    v = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    t = subprocess.run(["openssl", "ts", "-reply", "-in", str(FIX / "digicert.tsr"), "-text"],
                       capture_output=True, text=True)
    r = subprocess.run(["openssl", "ts", "-verify", "-in", str(FIX / "digicert.tsr"), "-digest",
                        "4c3da67688a064a39d3ce310a3d9d3ea0a54e1161b734e204d140766f9f7b6e2", "-sha256",
                        "-CAfile", str(FIX / "digicert-trusted-root-g4.pem"), "-attime", "1794198293"],
                       capture_output=True, text=True)
    raise AssertionError(f"DEBUG {v!r} REPLY rc={t.returncode} {t.stdout[-400:]!r} {t.stderr[-300:]!r} "
                         f"VERIFY rc={r.returncode} out={r.stdout!r} err={r.stderr!r}")
