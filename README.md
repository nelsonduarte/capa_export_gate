# Export Gate

A connector that exports **regulated payroll records** from an internal
system to an **approved external processing bureau** (a SaaS), and
**checks that the regulated data leaves the program through one audited
`declassify` and that its egress is narrowed to one approved host**. The
evidence is not a policy document or a code-review sign-off. It comes
from the [Capa](https://github.com/nelsonduarte) toolchain: the
information-flow analysis, under `@strict_ifc` on the egress, refuses a
flow it detects from a regulated field to an unaudited sink; its
capability SBOM records the capabilities each function holds; the
attenuated `Net` refuses a request to another host at runtime; and its
WASI backend refuses to build a component with a dynamic URL unless the
operator declares the host with `--allow-host`.

## The problem

Payroll outsourcing is routine and unavoidably high-stakes. To let an
external bureau run payroll you must hand it exactly the data that makes
exfiltration catastrophic: employees' names, national ids (NIF), IBANs
and gross salaries. The obligation, under GDPR (Art. 5, 28, 32), is to
show two things at once: that this regulated data goes to the **approved
processor and nowhere else** (not a log, not the console, not a second
host), and that it does so **only under the data processing agreement
(DPA)** that authorises it.

Today that assurance is built from process: data-flow diagrams, DPIAs,
code reviews, egress-filtering appliances, DLP that pattern-matches after
the fact. A single refactor can tee the payload into a debug log or point
the uploader at an attacker's host, and nothing in the build notices.

Export Gate shows a different model. "The regulated data leaves through
the audited bureau egress, and that egress is narrowed to the approved
host" is **checked at compile time, at build time and at runtime**: a
flow the analysis detects in the `@strict_ifc` egress stops the build, a
`--wasi` build without the operator's `--allow-host` is refused, and the
attenuated `Net` refuses another host.

## The checks, in two independent layers

The headline decomposes into two layers, each checked by a different part
of the toolchain.

### Layer 1 - flow confinement (information-flow control, `@secret`)

The four regulated fields are `@secret`. The single egress function opts
into `@strict_ifc`, so **a secret-to-sink flow the analysis detects
without an audited `declassify` is a hard compile error**. The payload is
`@secret` (it embeds the regulated fields), and it reaches `Net.post`
through the one `declassify`, whose reason names the DPA:

```capa
@strict_ifc()
pub fun export_to_bureau(net: Net, approved_host: String, records: List<PayrollRecord>) -> Result<String, ExportError>
    let bureau = net.restrict_to(approved_host)              // layer 2
    let url = "https://${approved_host}/v1/payroll/export"
    let secret_payload = build_payload(records)              // @secret
    let authorised_payload = declassify(                     // the ONE bridge
        secret_payload,
        reason: "DPA-2026-0417, Art. 28 GDPR processor agreement with the approved payroll bureau: ..."
    )
    return match bureau.post(url, authorised_payload)
        Ok(resp) -> Ok(resp)
        Err(e)   -> Err(Egress("${e}"))
```

`leaky_export.capa` is the counter-example that makes this concrete. It
tries to tee regulated fields into a log file and the console without the
`declassify`, and the compiler refuses it:

```
$ python -m capa --check leaky_export.capa
leaky_export.capa:30:37: error: information-flow: a @secret value reaches Fs.write
  (argument 2), a public sink that sends data out of the program. Route it through
  declassify(value, reason: "...") if this disclosure is intended.
leaky_export.capa:38:19: error: information-flow: a @secret value reaches Stdio.println
  (argument 1), a public sink ...
leaky_export.capa:45:37: error: information-flow: a @secret value reaches Fs.write
  (argument 2), a public sink ...
leaky_export.capa: 3 errors            # exit code 1
```

### Layer 2 - host confinement (`Net` attenuation + WASI grant)

The egress holds a `Net` it immediately narrows with
`restrict_to(approved_host)`. At run time that attenuation refuses any
other host before a byte hits the socket. The approved endpoint is
**operator-configured, not a literal in the source** (it is read from
`config/bureau_host.txt`), so under `--wasi` the URL is dynamic and the
backend **fails closed**: it refuses to build a component that reaches an
operator-chosen host unless the operator declares that exact host with
`--allow-host`.

```
# Without the grant: the WASI backend will not build a network reach it
# cannot bound. Deny-by-default.
$ python -m capa --wasm --component --wasi connector.capa
capa: --wasm: Net in WASI mode requires every URL passed to get/post to be a string
  literal so the allowed-host ceiling can be materialised; this program passes a dynamic
  URL ... Run with --allow-host <host> to grant the component network authority to reach
  that host ...                                                     # exit code 1

# With the operator-declared grant: it compiles, with that host recorded
# as the operator's grant.
$ python -m capa --wasm --component --wasi --allow-host bureau.example.com connector.capa
capa: --wasm: wrote component (43339 bytes) to ...
```

`offhost_export.capa` is the counter-example. It declassifies the payload
correctly (so it is **not** an information-flow leak) but aims it at the
cloud-metadata endpoint `169.254.169.254`, the classic SSRF /
exfiltration target. The `restrict_to` gate denies it at run time, on
both backends:

```
$ python -m capa --run offhost_export.capa
DENIED: Net capability does not permit access to host '169.254.169.254':
  current restrictions: ['bureau.example.com']
```

And an operator who tried to approve that host would be warned:

```
$ python -m capa --wasm --component --wasi --allow-host 169.254.169.254 connector.capa
capa: WARNING: --allow-host 169.254.169.254 grants a link-local address; this is
  usually an SSRF risk
```

### The two layers compose

Layer 1 checks that the secret leaves through **one** audited point.
Layer 2 narrows that point to **one** approved host. Neither alone is the
headline; together they are the evidence for it: *the regulated payroll
data is sent to the approved bureau, under the named DPA*. Neither layer
is a proof that it reaches nowhere else.

## Capability discipline: what the connector holds

`main` acquires three capabilities. The compiler checks it and the SBOM
records it:

```
$ python -m capa --manifest connector.capa \
    | jq '.functions[] | select(.source_name=="main")
          | {declared: .declared_capabilities, excluded: .provably_excluded_capabilities}'
{
  "declared": ["Net", "Fs", "Stdio"],
  "excluded": ["Clock", "Db", "Env", "Proc", "Random", "Unsafe"]
}
```

With no `Proc` anywhere in the surface, "this connector cannot shell out
to `curl` to exfiltrate the payload" is a checked fact.
`forbidden_cap_export.capa` is the counter-example: it tries exactly that,
with no `Proc` in scope, and the compiler refuses it.

```
$ python -m capa --check forbidden_cap_export.capa
forbidden_cap_export.capa:31:12: error: undefined name 'proc'
forbidden_cap_export.capa: 1 error            # exit code 1
```

The single legitimate secret-to-public crossing is named in the manifest:

```
$ python -m capa --manifest connector.capa | jq '.summary.declassification_sites'
1
```

One site, not zero (the payload must cross to reach the bureau), not many.

## The operator-declared grant in the SBOM

`--allow-host` is recorded as **operator-declared** (Level 2) authority,
kept distinct from the compiler-derived capability surface:

```
$ python -m capa --manifest --allow-host bureau.example.com connector.capa \
    | jq '.operator_declared_grants'
{
  "trust_level": "operator-declared",
  "note": "Authority declared by the operator at build/run time ... DISTINCT from the
           compiler-derived, program-proven capability surface ...",
  "preopens": [],
  "allow_hosts": [ { "kind": "net", "host": "bureau.example.com" } ]
}
```

An SBOM consumer therefore sees three things it can act on: the derived
surface (`{Net, Fs, Stdio}`), the compiler's derived exclusion set, and the
one host the operator approved, labelled as their decision, not the
compiler's.

## Layout

| Path | Role |
| --- | --- |
| `domain.capa` | the typed data model; the `@secret` annotations that are the policy |
| `ingest.capa` | inline CSV parse + validation into `PayrollRecord`s (no capability) |
| `payload.capa` | build the `@secret` export payload from the records (no capability) |
| `config.capa` | read the operator-configured approved host (Fs read-only) |
| `egress.capa` | the single audited `declassify` + `Net`-restricted egress (`@strict_ifc`) |
| `connector.capa` | the orchestrator: read (Fs ro) -> parse -> payload -> egress (Net) |
| `leaky_export.capa` | counter-example (layer 1): the flow leak the compiler rejects |
| `offhost_export.capa` | counter-example (layer 2): the off-host the gate denies |
| `forbidden_cap_export.capa` | counter-example: subprocess exfiltration the surface forbids |
| `data/payroll.csv` | sample batch (8 records, entirely fictitious) |
| `config/bureau_host.txt` | the operator-configured approved bureau host |
| `sbom/` | sample generated manifest + SBOMs + provenance |
| `generate.sh` | regenerate the SBOM family, with timestamps pinned |
| `gate.sh` | the self-contained validation gate (all of the above, checked) |

## Run it

All commands use the local Capa compiler; substitute `python -m capa` for
`capa` if the installed `capa` is not the build you intend.

```sh
# Type-check + information-flow check (clean: no finding)
capa --check connector.capa

# Run the connector against the committed fixture.
capa --run connector.capa

# See both counter-examples the compiler rejects, and the run-time denial
capa --check leaky_export.capa            # 3 information-flow errors, exit 1
capa --run   offhost_export.capa          # DENIED: off-host refused
capa --check forbidden_cap_export.capa    # undefined name 'proc', exit 1

# The two-layer WASI host gate
capa --wasm --component --wasi connector.capa                               # rejected
capa --wasm --component --wasi --allow-host bureau.example.com connector.capa  # compiles

# Regenerate the SBOM family (timestamps pinned)
./generate.sh

# The full self-contained gate
./gate.sh
```

### The network call is an offline fixture

The checks are **compile-time** (information-flow), **build-time** (the
WASI host gate) and **runtime** (the attenuated `Net`); no live bureau is
required to demonstrate them. The
committed `config/bureau_host.txt` names `bureau.example.com` (RFC 2606
documentation domain), so `capa --run connector.capa` builds the payload,
crosses the single audited `declassify`, attempts the POST, and reports
the expected offline outcome. In production the operator points the config
at the real approved host and grants it with `--allow-host`. The DNS/
connect failure in the fixture is not a leak and not a host breach: the
checks live in the toolchain, not in a running server.

### Same source, both backends

The connector runs unchanged on the Wasm backend; the console output is
byte-identical to the Python backend (modulo line-ending style).

```sh
capa --wasm --run connector.capa            # identical output
```

## Dependencies

None fetched at build time: the CSV parsing is inline and holds no
capability, so the
demo is fully self-contained and `gate.sh` runs from nothing but the
committed tree. A verified `capa_csv` git dependency, as in
[capa_dataguard](../capa_dataguard), is the drop-in alternative; it is
capability-free and would not widen the `{Net, Fs, Stdio}` surface.

## Licence

MIT. See `LICENSE`. The sample batch is entirely fictitious.
