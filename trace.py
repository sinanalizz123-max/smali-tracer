#!/data/data/com.termux/files/usr/bin/python3
"""smali-tracer: inject Log.d entry tracing into smali methods (no Frida needed).

Inserts, right after the .locals/.registers line of each target method, code that
logs the method name plus every argument (null-safe via String.valueOf, arrays
via Arrays.toString). Uses v0/v1, which are dead at method entry, so NO .locals
bump is needed (bumping shifts p-register mapping and breaks existing code).

Usage:
    python3 trace.py <smali-file> <MethodName> <TAG>
    # or batch:
    python3 trace.py --config trace.conf <smali-root>

trace.conf lines: <relative-smali-path> <MethodName> <TAG>
Only the FIRST matching method per file is patched (extend as needed).
"""
import re
import sys


def split_params(descriptor):
    """Split '(...)R' param section into type chars, e.g. 'J', 'F', '[I'."""
    inner = descriptor[1:descriptor.index(")")]
    parts = []
    i = 0
    while i < len(inner):
        if inner[i] == "[":
            j = i
            while inner[j] == "[":
                j += 1
            if inner[j] == "L":
                k = inner.index(";", j)
                parts.append(inner[i:k + 1])
                i = k + 1
            else:
                parts.append(inner[i:j + 1])
                i = j + 1
        elif inner[i] == "L":
            k = inner.index(";", i)
            parts.append(inner[i:k + 1])
            i = k + 1
        else:
            parts.append(inner[i])
            i += 1
    return parts


def log_for_type(typ):
    """Return (invoke-target, extra-setup) for one argument already in a reg."""
    if typ in ("I", "Z", "B", "C", "S"):
        return "Ljava/lang/String;->valueOf(I)Ljava/lang/String;", None
    if typ == "J":
        return "Ljava/lang/String;->valueOf(J)Ljava/lang/String;", None
    if typ in ("F", "D"):
        return "Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % typ, None
    if typ == "Ljava/lang/String;":
        return None, None  # direct
    if typ in ("[I", "[B", "[Z]", "[J", "[F", "[D", "[C", "[S"):
        base = typ[1]
        return ("Ljava/util/Arrays;->toString([%s)Ljava/lang/String;" % base), "null-guard"
    return "Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;", None


def patch_method(path, method_name, tag):
    src = open(path).read()
    lines = src.split("\n")
    out = []
    i = 0
    patched = False
    while i < len(lines):
        out.append(lines[i])
        m = re.match(r"\.method .* %s\(([^)]*)\)" % re.escape(method_name), lines[i])
        if m and not patched:
            desc = "(" + m.group(1) + ")"
            params = split_params(desc + "V")
            # find .locals/.registers line
            j = i + 1
            while j < len(lines) and not re.match(r"\s*\.(locals|registers)", lines[j]):
                out.append(lines[j])
                j += 1
            if j >= len(lines):
                raise SystemExit("no locals line in %s" % method_name)
            out.append(lines[j])  # keep .locals/.registers unchanged
            # need param reg mapping: p0..pn; use move/from16-free low regs? use v0/v1 dead at entry
            code = []
            code.append('    const-string v0, "%s"' % tag)
            code.append('    const-string v1, "call %s"' % method_name)
            code.append("    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I")
            preg = 1  # p0 is this for instance methods; static starts at p0=args
            # detect static
            is_static = " static " in lines[i]
            r = 0 if is_static else 1
            for t in params:
                wide = t in ("J", "D")
                ref = "p%d" % r
                is_obj = t.startswith("[") or t.startswith("L")
                if wide:
                    code.append("    move-wide/from16 v1, %s" % ref)
                elif is_obj:
                    code.append("    move-object/from16 v1, %s" % ref)
                else:
                    code.append("    move/from16 v1, %s" % ref)
                conv, extra = log_for_type(t)
                if extra == "null-guard":
                    code.append("    if-eqz v1, :trace_%s_null" % method_name)
                if conv is None:
                    code.append("    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I")
                else:
                    code.append("    invoke-static {v1}, L%s" % conv)
                    code.append("    move-result-object v1")
                    code.append("    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I")
                if extra == "null-guard":
                    code.append("    :trace_%s_null" % method_name)
                r += 2 if wide else 1
            out.extend(code)
            i = j + 1
            patched = True
            continue
        i += 1
    if not patched:
        raise SystemExit("method %s not found in %s" % (method_name, path))
    open(path, "w").write("\n".join(out))
    print("patched %s :: %s" % (path, method_name))


def main():
    if len(sys.argv) == 4 and not sys.argv[1].startswith("-"):
        patch_method(sys.argv[1], sys.argv[2], sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == "--config":
        for line in open(sys.argv[2]):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            f, m, t = line.split()
            patch_method(f, m, t)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
