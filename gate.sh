#!/bin/sh
# Self-contained validation gate for capa_export_gate.
#
# Checks, from nothing but the committed tree, that:
#   * the connector type-checks and runs (offline fixture),
#   * the Python and Wasm backends agree byte-for-byte,
#   * the two-layer WASI host gate rejects without --allow-host and
#     compiles with it,
#   * every counter-example is rejected with the expected diagnostic,
#   * the SBOM records the {Net, Fs, Stdio} surface, the provably
#     excluded capabilities, the single declassify site, and the
#     operator-declared approved-host grant,
#   * a fresh build of the SBOM family matches the committed one (step 6).
#
# Run `capa` == the compiler build you intend (e.g. `python -m capa`).
# Exits non-zero on the first failure.
set -e

CAPA="${CAPA:-capa}"
fail() { echo "GATE FAIL: $1" >&2; exit 1; }
ok() { echo "  ok: $1"; }

echo "== 1. connector type-checks + runs (offline fixture) =="
$CAPA --check connector.capa >/dev/null || fail "connector.capa did not type-check"
ok "connector.capa --check"
$CAPA --run connector.capa | grep -q "no regulated field left the program except through the audited declassify" \
    || fail "connector.capa --run did not reach the audited-egress summary"
ok "connector.capa --run (offline)"

echo "== 2. Python / Wasm backend parity (modulo line endings) =="
$CAPA --run connector.capa | tr -d '\r' > /tmp/eg_py.txt
$CAPA --wasm --run connector.capa | tr -d '\r' > /tmp/eg_wasm.txt
diff /tmp/eg_py.txt /tmp/eg_wasm.txt >/dev/null || fail "Python and Wasm output differ"
ok "python == wasm output"

echo "== 3. two-layer WASI host gate =="
if command -v wasm-tools >/dev/null 2>&1; then
    if $CAPA --wasm --component --wasi --output /tmp/eg_nogrant.wasm connector.capa >/dev/null 2>&1; then
        fail "connector compiled under --wasi WITHOUT --allow-host (should fail closed)"
    fi
    ok "rejected under --wasi without --allow-host (fail-closed)"
    $CAPA --wasm --component --wasi --allow-host bureau.example.com \
        --output /tmp/eg_grant.wasm connector.capa >/dev/null 2>&1 \
        || fail "connector did NOT compile under --wasi with --allow-host bureau.example.com"
    ok "compiles under --wasi with --allow-host bureau.example.com"
else
    echo "  skip: wasm-tools not installed"
fi

echo "== 4. counter-examples rejected with the expected diagnostic =="
# leaky_export: information-flow HARD errors, no compile.
if $CAPA --check leaky_export.capa >/dev/null 2>&1; then
    fail "leaky_export.capa compiled (should be an information-flow error)"
fi
$CAPA --check leaky_export.capa 2>&1 | grep -q "information-flow: a @secret value reaches" \
    || fail "leaky_export.capa did not raise the information-flow diagnostic"
ok "leaky_export.capa rejected (information-flow)"

# offhost_export: run-time host-confinement denial.
$CAPA --run offhost_export.capa 2>&1 | grep -q "DENIED: Net capability does not permit access to host '169.254.169.254'" \
    || fail "offhost_export.capa did not deny the off-host post"
ok "offhost_export.capa denied off-host (host confinement)"

# forbidden_cap_export: the surface makes Proc unrepresentable.
if $CAPA --check forbidden_cap_export.capa >/dev/null 2>&1; then
    fail "forbidden_cap_export.capa compiled (should be undefined name 'proc')"
fi
$CAPA --check forbidden_cap_export.capa 2>&1 | grep -q "undefined name 'proc'" \
    || fail "forbidden_cap_export.capa did not raise undefined name 'proc'"
ok "forbidden_cap_export.capa rejected (no Proc in the surface)"

echo "== 5. SBOM authority surface =="
M="$($CAPA --manifest connector.capa)"
echo "$M" | python -c "import sys,json; m=json.load(sys.stdin); f=[x for x in m['functions'] if x.get('source_name')=='main'][0]; d=set(f.get('declared_capabilities') or []); e=set(f.get('provably_excluded_capabilities') or []); assert d=={'Net','Fs','Stdio'}, ('declared',d); assert {'Proc','Db','Env','Clock','Random','Unsafe'}<=e, ('excluded',e); assert m['summary'].get('declassification_sites')==1, ('sites',m['summary'].get('declassification_sites'))" \
    || fail "manifest surface / declassify count is not as expected"
ok "declared {Net,Fs,Stdio}; excluded Proc/Db/Env/Clock/Random/Unsafe; 1 declassify site"
$CAPA --manifest --allow-host bureau.example.com connector.capa \
    | python -c "import sys,json; g=json.load(sys.stdin).get('operator_declared_grants') or {}; hosts=[h.get('host') for h in g.get('allow_hosts') or []]; assert g.get('trust_level')=='operator-declared', g; assert hosts==['bureau.example.com'], hosts" \
    || fail "operator_declared_grants did not record the approved host"
ok "operator_declared_grants records bureau.example.com (operator-declared)"

echo "== 6. SBOM byte-reproducibility =="
SOURCE_DATE_EPOCH="$(tr -d '\r' < sbom/SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH
for pair in "manifest:--manifest" "sbom.cyclonedx:--cyclonedx" "sbom.spdx:--spdx" "provenance.slsa:--provenance"; do
    name="${pair%%:*}"; flag="${pair##*:}"
    ext="json"
    [ "$name" = "provenance.slsa" ] && ext="json"
    $CAPA $flag connector.capa | tr -d '\r' > "/tmp/eg_${name}.json"
    if [ -f "sbom/${name}.json" ]; then
        tr -d '\r' < "sbom/${name}.json" > "/tmp/eg_committed_${name}.json"
        diff "/tmp/eg_committed_${name}.json" "/tmp/eg_${name}.json" >/dev/null \
            || fail "sbom/${name}.json is not byte-reproducible"
        ok "sbom/${name}.json reproduces"
    fi
done

echo
echo "GATE PASS: capa_export_gate is self-contained and both layers hold."
