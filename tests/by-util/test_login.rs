use assert_cmd::Command;

#[test]
fn test_not_root() {
    Command::cargo_bin("shadow")
        .expect("found binary")
        .arg("login")
        .assert()
        .code(1)
        .stderr(predicates::str::contains("must be suid to work properly"));
}
