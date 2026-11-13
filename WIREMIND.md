# wiremind fork of trivy-operator

The `wiremind` branch carries fixes to alternate report storage on top of an upstream release. `main` mirrors upstream and is not used.

## Why

By default trivy-operator stores every report as a custom resource. On large clusters the VulnerabilityReports become the main load the operator puts on etcd, and the kube-apiserver re-reads them on every cache consistency check.

Alternate report storage (`alternateReportStorage.enabled`) writes the reports as JSON files on a PersistentVolume instead. As released upstream it is not usable for us:

- the metrics collector only reads the custom resources, so every `trivy_*` report metric is empty;
- a rescan never rewrites an existing file, so reports stay frozen at their first scan;
- files are named `<kind>-<name>-<container>.json`, so same-named workloads in different namespaces overwrite each other;
- the decision to scan still looks for custom resources, which this mode never creates: every workload event rescans, the report TTL is never applied, and files of deleted workloads are never removed.

## What this branch changes

On top of upstream `v0.36.1`:

- upstream pull request `#2856`, cherry-picked: metrics are read from the report files;
- upstream pull request `#3104`, cherry-picked: a rescan rewrites the report file;
- report files are named `<namespace>_<kind>_<name>_<container>.json` and written through a temporary file and a rename;
- with alternate storage, a workload is not rescanned while each container has a report file with the current spec hash younger than `scannerReportTTL`, and it is requeued when the oldest one expires;
- with alternate storage, report files are deleted at start and every hour when their workload no longer exists, when they are older than the TTL, or when their name does not match their content;
- the upstream workflows are replaced by `.github/workflows/wiremind.yaml`.

Without alternate storage the operator behaves as upstream.

## Releases

Pull requests target `wiremind`. Tagging a commit of `wiremind` with `v<upstream version>-wiremind.<n>` runs the unit tests and pushes `ghcr.io/wiremind/trivy-operator:<tag>` for linux/amd64. Use the upstream Helm chart with `image.registry: ghcr.io`, `image.repository: wiremind/trivy-operator` and that tag.

The volume is ReadWriteOnce, so run a single replica (`operator.replicas: 1`, the chart default).

## Following upstream

For a new upstream release, rebase `wiremind` onto its tag, drop what upstream now ships, and tag `v<new version>-wiremind.1`.

Drop the fork once upstream ships equivalent fixes for all the points above.
