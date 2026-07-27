# Required repository policy

The desired machine-readable policy is
[repository-policy.json](repository-policy.json). GitHub repository settings,
not this file, provide remote enforcement.

After the workflow exists on GitHub and its first trusted check has completed,
an administrator must apply a branch ruleset that:

- requires pull requests and the merge queue for `main`;
- requires the exact `Engineering quality / PR gates` check from GitHub
  Actions on the current base and `merge_group` revision;
- requires current CODEOWNER approval and one approval from someone other than
  the latest pusher;
- dismisses stale approvals and requires all review threads resolved;
- requires linear history and signed commits;
- blocks direct pushes, force pushes, deletion, and administrator bypass; and
- protects rulesets, workflows, CODEOWNERS, engineering policy, gate
  registries, and the quality runner through the same review path.

The repository policy must be verified through GitHub after application.
Checked-in desired state alone must never be reported as active protection.
