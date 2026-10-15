# smali-tracer

Entry-tracing injector for smali methods — runtime insight without Frida.

Inserts `Log.d` calls at the start of target methods logging the method name
plus every argument (primitives via `String.valueOf`, arrays via
`Arrays.toString` with null guards, objects via null-safe `String.valueOf`).
Output appears in logcat under your tag; read it with `adb logcat` or any
on-device shell.

## Why this exists

Dynamic instrumentation (Frida) is unavailable on some targets. This covers
the most common need — "what arguments does this method actually receive?" —
with a static patch + rebuild instead of a runtime agent.

## Usage

```bash
# single method (first match only)
python3 trace.py path/to/Class.smali methodName LOGTAG

# batch from config (one "<smali> <Method> <TAG>" per line)
python3 trace.py --config trace.conf
```

Then assemble (`smali`), merge into the app dex (e.g. dexlib2 `DexPool`),
repack, sign, install, and watch logcat:

```bash
adb logcat | grep LOGTAG
```

## Rules the injector follows (learned the hard way)

- Never bumps `.locals`/`.registers` (that shifts `p`-register mapping and
  breaks existing instructions). It reuses `v0`/`v1`, which are dead at method
  entry, and the original code redefines them.
- Every parameter access uses `/from16` move forms, so high registers in big
  methods work with short-form invokes afterward.
- Array args get a null guard; everything else goes through null-safe
  `String.valueOf`.

## Limits (v1)

- Entry logging only (no exit/return tracing).
- Only the first matching method per file.
- Object args log as `Class@hash` unless they implement `toString`.
- You still need an assemble + repack + sign pipeline for your target.
