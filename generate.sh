#!/bin/sh
# Regenerate the capa_export_gate SBOM family:
#
#   sbom/manifest.json           the capability manifest (surface + declassify site)
#   sbom/manifest.grants.json    the manifest WITH the operator-declared --allow-host grant
#   sbom/sbom.cyclonedx.json     CycloneDX 1.5 SBOM with the manifest embedded
#   sbom/sbom.spdx.json          SPDX 2.3 SBOM companion
#   sbom/provenance.slsa.json    SLSA build provenance over the source
#
# The SBOM family is EMITTED BY THE COMPILER from connector.capa. Together
# with the information-flow analysis it is the machine-readable evidence:
# the program states the claim, the compiler checks it (flow confinement +
# the capability surface + the operator-declared Net grant).
#
# Determinism comes from SOURCE_DATE_EPOCH (reproducible-builds.org): the
# compiler stamps the SBOM build time from this fixed instant. The
# compiler's tests pin byte-identical output for repeated runs; a
# rebuild-and-diff is a check to run, not a guarantee. Bump it by writing a new UTC epoch to
# sbom/SOURCE_DATE_EPOCH and rerunning this script.
#
# Run every invocation through the local Capa compiler (`capa` == the
# build you intend, e.g. `python -m capa`).
set -e

SOURCE_DATE_EPOCH="$(tr -d '\r' < sbom/SOURCE_DATE_EPOCH)"
export SOURCE_DATE_EPOCH

mkdir -p sbom

# The compiler-derived surface (no operator grant): Net + Fs + Stdio used,
# Proc/Db/Env/Clock/Random/Unsafe listed as excluded, one declassify site.
capa --manifest   connector.capa > sbom/manifest.json
capa --cyclonedx  connector.capa > sbom/sbom.cyclonedx.json
capa --spdx       connector.capa > sbom/sbom.spdx.json
capa --provenance connector.capa > sbom/provenance.slsa.json

# The same manifest WITH the operator-declared approved-host grant, so the
# operator_declared_grants block records the approved bureau host at
# trust_level "operator-declared", distinct from the compiler-derived
# surface above.
capa --manifest --allow-host bureau.example.com connector.capa > sbom/manifest.grants.json

echo "regenerated sbom/ (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
