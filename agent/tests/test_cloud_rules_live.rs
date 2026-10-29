//! Against a running vandam-cloud (ignored by default): `VANDAM_CLOUD_URL=http://127.0.0.1:8090
//! VANDAM_ISSUER_KEY=<its public key> cargo test -p vandam-agent --test test_cloud_rules_live --
//! --ignored`. Fetches the published bundle with the agent's own client, checks it against the
//! repo's rules folder it was made from, and loads it into a ConfigManager.

use vandam::cloud_rules::{fetch, CloudRules, Fetched};
use vandam::rules::{source, ConfigManager};

#[tokio::test]
#[ignore]
async fn the_published_rules_arrive_verified_and_load() {
    let cloud = CloudRules::configured().expect("VANDAM_CLOUD_URL and VANDAM_ISSUER_KEY");
    let Fetched::New { rules, json } = fetch(&cloud, None).await.expect("fetch") else { panic!("expected a bundle") };
    let from_cloud = source::parse_bundle(&json).unwrap();
    let repo = source::Source::Dir(source::REPO_RULES.into());
    for name in ["linux_web_signatures.json", "exec_control_lists.json", "policies/ssh.json"] {
        assert_eq!(from_cloud.json(name), repo.json(name), "{} differs from the repo", name);
    }
    assert!(matches!(fetch(&cloud, Some(rules)).await.expect("refetch"), Fetched::Current));

    source::set(from_cloud);
    let config = ConfigManager::load_defaults();
    assert!(!config.sensitive_files().is_empty());
    assert!(!config.db_signatures().is_empty());
    println!("rules {} loaded from {}", rules, cloud.base);
}
