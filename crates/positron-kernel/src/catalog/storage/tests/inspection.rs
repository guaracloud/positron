use super::*;

#[test]
fn read_only_inspection_opens_only_an_existing_complete_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let root = TemporaryRoot::new()?;
    let volume = PrimaryDataVolume::acquire(root.path(), MountQualification::LocalHost)?;
    let storage = CatalogStorage::open(&volume)?;
    drop(storage);
    drop(volume);
    std::fs::remove_file(root.path().join(".positron-volume.lock"))?;

    let inspected = CatalogStorage::inspect(&File::open(root.path())?)?;
    drop(inspected);
    assert!(!root.path().join(".positron-volume.lock").exists());

    std::fs::remove_dir(root.path().join("catalog/staging"))?;
    let incomplete = CatalogStorage::inspect(&File::open(root.path())?);
    assert!(matches!(
        incomplete,
        Err(failure) if failure.code() == CatalogFailureCode::IntegrityCorruption
    ));
    assert!(!root.path().join("catalog/staging").exists());
    Ok(())
}
