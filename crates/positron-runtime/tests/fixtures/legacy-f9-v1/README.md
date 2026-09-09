# Released f9 V1 ordinary-data fixture

This 53-file, 17,684-byte fixture was generated from the exact released
checkout `f9ab271bae4fde03fee173380e01eb8d41b2db65` by its
`services::tests::schema_maintenance::cross_version_legacy_v1_fixture_persists_ordinary_log`
test. That test uses f9 production initialization, claims the generated
test credentials, persists `legacy-f9-before-v2` through f9's ordinary log
service, and restores the original encrypted bootstrap claim before capture.

The fixture contains generated test-only cryptographic material and encrypted
test credentials. The successor test copies it into a fresh owner-only
temporary root, claims the credentials there, migrates V1 to V2, reopens, and
queries the f9-persisted record. It never embeds or prints raw credentials and
requires neither a checkout of f9 nor network access.
