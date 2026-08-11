# Make Kubernetes compatibility a tested product contract

Each Positron release supports all upstream-maintained Kubernetes minors at
release time, records exact tested patches, and integration-tests `amd64` and
`arm64` across upstream Kubernetes, EKS, GKE, AKS, OpenShift, and k3s. The
operator uses stable APIs without optional feature gates;
`apiextensions.k8s.io/v1` CRDs use structural schemas, CEL, status
subresources, printer columns, and pruning, beginning at `v1beta1` with
coexistence, conversion, and storage-version migration required before
retiring future versions. Reconciliation is idempotent, watch-driven, bounded,
jittered, and server-side-applied with explicit ownership; two operator
replicas use a stable Lease. Cluster-wide and scoped multi-namespace installs
use least-privilege RBAC, bounded finalizers default to retaining data, and
webhooks are avoided unless representation conversion requires them. Pods
satisfy the Restricted Pod Security Standard. Integration tests cover
installation, drift, operator failover, API outage, eviction, node drain,
storage detach and reattach, Key Provider outage, backup and restore,
certificate rotation, operator and operand upgrades, CRD migration, retained
uninstall, and restricted-namespace execution.
