extern crate cargo_lock;

use cargo_lock::Lockfile;
use rustsec::database::Database;
use rustsec::Advisory;

fn main() {
    let lockfile = Lockfile::load("Cargo.lock").unwrap();
    let database = Database::fetch().unwrap();

    for package in lockfile.packages() {
        let advisories = database.find_by_package(
            &package.name,
            Some(&package.version.to_string()),
            None,
            None,
            None,
        );

        if advisories.is_empty() {
            println!("No vulnerabilities found for package '{}'", package.name);
        } else {
            println!("Found {} vulnerabilities for package '{}':", advisories.len(), package.name);
            for advisory in advisories {
                print_advisory(&advisory);
            }
        }
    }
}

fn print_advisory(advisory: &Advisory) {
    println!("\nAdvisory ID: {}", advisory.id);
    println!("Title: {}", advisory.title);
    println!("URL: {}", advisory.url);
    println!("Severity: {}", advisory.severity);
    println!("Description: {}", advisory.description);
    println!("Versions: {:?}", advisory.versions);
}
