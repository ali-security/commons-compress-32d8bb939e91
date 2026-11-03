# Print every skipped test with its reason, then the aggregated surefire totals.
# Surefire only prints a per-class "Skipped: N" count; this names each skipped test.
import glob
import re
import xml.etree.ElementTree as ET


def source_context(cls, name):
    """The @Ignore annotation / assume call around the test method, from source: a bare
    @Ignore has no message and a Hamcrest assume only says "got: <false>, expected: is <true>"."""
    src = "src/test/java/" + cls.replace(".", "/") + ".java"
    try:
        lines = open(src).read().splitlines()
    except IOError:
        return ""
    for i, line in enumerate(lines):
        if re.search(r"void\s+" + re.escape(name.split("[")[0]) + r"\s*\(", line):
            return " | ".join(x.strip() for x in lines[max(0, i - 3):i + 6] if x.strip())
    return ""


tot = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
skipped = []
for f in sorted(glob.glob("target/surefire-reports/TEST-*.xml")):
    r = ET.parse(f).getroot()
    for k in tot:
        tot[k] += int(r.get(k, 0))
    for tc in r.iter("testcase"):
        s = tc.find("skipped")
        if s is not None:
            skipped.append((tc.get("classname"), tc.get("name"), s.get("message") or ""))

print("=== Skipped tests and reasons ===")
for cls, name, msg in skipped:
    ctx = source_context(cls, name)
    reason = " || ".join(x for x in (msg, "source: " + ctx if ctx else "") if x)
    print("SKIPPED %s.%s -- %s" % (cls, name, reason or "(no message)"))
print(
    "=== TEST SUMMARY: Tests run: %(tests)d, Failures: %(failures)d, "
    "Errors: %(errors)d, Skipped: %(skipped)d ===" % tot
)
