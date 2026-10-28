//! EPSS, KEV, and CVSS enrichment.
//!
//! [`merge_advisories`] combines OSV advisories that alias each other for one
//! package, then attaches the highest CVSS, the maximum EPSS, and any KEV hit.
//! Scoring comes later. This module does not call the network; callers pass
//! the EPSS and KEV maps they already loaded.

pub mod cvss;
pub mod epss;
pub mod kev;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::cache::EpssEntry;
use crate::model::{Advisory, Severity};

use self::cvss::{assess, severity_fallback, CvssAssessment};
use self::kev::KevRecord;

/// EPSS numbers for one merged advisory.
///
/// `score` is the maximum probability and `percentile` is the maximum
/// percentile. They can come from different CVEs. Both are 0 when the advisory
/// has no CVE or none of the CVEs are in the EPSS map (PRD AC3.4).
#[derive(Debug, Clone, PartialEq)]
pub struct EpssEnrichment {
    /// Maximum EPSS probability, or 0.
    pub score: f64,
    /// Maximum EPSS percentile, or 0.
    pub percentile: f64,
    /// Score date of the CVE that supplied [`Self::score`], when any row matched.
    pub date: Option<String>,
}

/// One advisory after alias merging and enrichment.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrichedAdvisory {
    /// Primary id. A `GHSA-` id wins, then any non-CVE OSV id, then a CVE.
    pub id: String,
    /// Every other id and alias in the group, sorted.
    pub aliases: Vec<String>,
    /// CVE ids from the primary id and the aliases, uppercased and sorted.
    pub cves: Vec<String>,
    /// Summary of the primary advisory.
    pub summary: String,
    /// Reference URLs from every advisory in the group, sorted and unique.
    pub references: Vec<String>,
    /// Fixed versions from every advisory in the group, sorted and unique.
    pub fixed_versions: Vec<String>,
    /// Highest CVSS, or the severity fallback, or `None`.
    pub cvss: Option<CvssAssessment>,
    /// Maximum EPSS across `cves`.
    pub epss: EpssEnrichment,
    /// True when any CVE is in the KEV catalog.
    pub kev: bool,
    /// The KEV row that made [`Self::kev`] true.
    pub kev_record: Option<KevRecord>,
}

/// Merge `advisories` that belong to one package and enrich them.
///
/// Two advisories are the same vulnerability when their id/alias sets
/// intersect (each lists the other, they share a CVE, or the ids are equal).
/// Groups keep input order. Inside a group the earliest id of the best rank
/// becomes [`EnrichedAdvisory::id`].
pub fn merge_advisories(
    advisories: &[Advisory],
    epss: &BTreeMap<String, EpssEntry>,
    kev: &BTreeMap<String, KevRecord>,
) -> Vec<EnrichedAdvisory> {
    components(advisories)
        .into_iter()
        .map(|group| enrich_group(advisories, &group, epss, kev))
        .collect()
}

fn enrich_group(
    advisories: &[Advisory],
    group: &[usize],
    epss: &BTreeMap<String, EpssEntry>,
    kev: &BTreeMap<String, KevRecord>,
) -> EnrichedAdvisory {
    let primary = primary_index(advisories, group);
    let primary_adv = &advisories[primary];

    let mut names = BTreeSet::new();
    let mut references = BTreeSet::new();
    let mut fixed_versions = BTreeSet::new();
    let mut severities: Vec<Severity> = Vec::new();
    let mut fallback_label: Option<String> = None;
    let mut fallback_score: Option<f64> = None;

    for &index in group {
        let advisory = &advisories[index];
        names.insert(advisory.id.clone());
        names.extend(advisory.aliases.iter().cloned());
        references.extend(advisory.references.iter().cloned());
        fixed_versions.extend(advisory.fixed_versions.iter().cloned());
        severities.extend(advisory.severity.iter().cloned());
        if let Some(label) = &advisory.database_specific_severity {
            if let Some(score) = severity_fallback(label) {
                let replace = match fallback_score {
                    Some(current) => score.total_cmp(&current) == Ordering::Greater,
                    None => true,
                };
                if replace {
                    fallback_score = Some(score);
                    fallback_label = Some(label.clone());
                }
            }
        }
    }
    names.remove(&primary_adv.id);

    let cves: Vec<String> = names
        .iter()
        .chain(std::iter::once(&primary_adv.id))
        .filter(|id| is_cve(id))
        .map(|id| id.to_ascii_uppercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let cvss = assess(&severities, fallback_label.as_deref());
    let epss_enrichment = max_epss(&cves, epss);
    let kev_record = best_kev(&cves, kev).cloned();

    EnrichedAdvisory {
        id: primary_adv.id.clone(),
        aliases: names.into_iter().collect(),
        cves,
        summary: primary_adv.summary.clone(),
        references: references.into_iter().collect(),
        fixed_versions: fixed_versions.into_iter().collect(),
        cvss,
        kev: kev_record.is_some(),
        kev_record,
        epss: epss_enrichment,
    }
}

fn primary_index(advisories: &[Advisory], group: &[usize]) -> usize {
    let mut best = group[0];
    for &index in &group[1..] {
        if id_rank(&advisories[index].id) < id_rank(&advisories[best].id) {
            best = index;
        }
    }
    best
}

/// Lower is a better primary id: GHSA, then any non-CVE OSV id, then a CVE.
fn id_rank(id: &str) -> u8 {
    if id.starts_with("GHSA-") {
        0
    } else if is_cve(id) {
        2
    } else {
        1
    }
}

fn is_cve(id: &str) -> bool {
    id.len() >= 4 && id[..4].eq_ignore_ascii_case("CVE-")
}

fn max_epss(cves: &[String], epss: &BTreeMap<String, EpssEntry>) -> EpssEnrichment {
    let mut score: Option<f64> = None;
    let mut date: Option<String> = None;
    let mut percentile = 0.0;
    for cve in cves {
        let Some(entry) = lookup_epss(epss, cve) else {
            continue;
        };
        let replace = match score {
            Some(current) => entry.score.total_cmp(&current) == Ordering::Greater,
            None => true,
        };
        if replace {
            score = Some(entry.score);
            date = Some(entry.date.clone());
        }
        if entry.percentile.total_cmp(&percentile) == Ordering::Greater {
            percentile = entry.percentile;
        }
    }
    EpssEnrichment {
        score: score.unwrap_or(0.0),
        percentile: if score.is_some() { percentile } else { 0.0 },
        date,
    }
}

fn lookup_epss<'a>(epss: &'a BTreeMap<String, EpssEntry>, cve: &str) -> Option<&'a EpssEntry> {
    epss.get(cve)
        .or_else(|| epss.get(&cve.to_ascii_uppercase()))
}

fn best_kev<'a>(cves: &[String], kev: &'a BTreeMap<String, KevRecord>) -> Option<&'a KevRecord> {
    let mut chosen: Option<&KevRecord> = None;
    for cve in cves {
        let Some(record) = kev.get(cve).or_else(|| kev.get(&cve.to_ascii_uppercase())) else {
            continue;
        };
        chosen = Some(match chosen {
            None => record,
            Some(current) => prefer_kev(current, record),
        });
    }
    chosen
}

fn prefer_kev<'a>(current: &'a KevRecord, candidate: &'a KevRecord) -> &'a KevRecord {
    let current_known = current.known_ransomware_campaign_use == "Known";
    let candidate_known = candidate.known_ransomware_campaign_use == "Known";
    if candidate_known != current_known {
        if candidate_known {
            return candidate;
        }
        return current;
    }
    if candidate.cve_id < current.cve_id {
        candidate
    } else {
        current
    }
}

fn components(advisories: &[Advisory]) -> Vec<Vec<usize>> {
    let count = advisories.len();
    let mut parent: Vec<usize> = (0..count).collect();
    for left in 0..count {
        for right in (left + 1)..count {
            if related(&advisories[left], &advisories[right]) {
                union(&mut parent, left, right);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..count {
        groups
            .entry(find(&mut parent, index))
            .or_default()
            .push(index);
    }
    groups.into_values().collect()
}

fn related(left: &Advisory, right: &Advisory) -> bool {
    if left.id == right.id {
        return true;
    }
    if left.aliases.iter().any(|alias| alias == &right.id)
        || right.aliases.iter().any(|alias| alias == &left.id)
    {
        return true;
    }
    left.aliases
        .iter()
        .any(|alias| right.aliases.contains(alias))
}

fn find(parent: &mut [usize], mut index: usize) -> usize {
    let mut root = index;
    while parent[root] != root {
        root = parent[root];
    }
    while parent[index] != root {
        let next = parent[index];
        parent[index] = root;
        index = next;
    }
    root
}

fn union(parent: &mut [usize], left: usize, right: usize) {
    let mut left_root = find(parent, left);
    let mut right_root = find(parent, right);
    if left_root == right_root {
        return;
    }
    if left_root > right_root {
        std::mem::swap(&mut left_root, &mut right_root);
    }
    parent[right_root] = left_root;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn advisory(id: &str, aliases: &[&str]) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: aliases.iter().map(|alias| (*alias).to_string()).collect(),
            summary: format!("summary {id}"),
            severity: Vec::new(),
            database_specific_severity: None,
            references: Vec::new(),
            fixed_versions: Vec::new(),
            imports: Vec::new(),
        }
    }

    fn epss(cve: &str, score: f64, percentile: f64, date: &str) -> (String, EpssEntry) {
        (
            cve.to_string(),
            EpssEntry {
                cve: cve.to_string(),
                score,
                percentile,
                date: date.to_string(),
                fetched_at: 1,
            },
        )
    }

    fn kev(cve: &str, ransomware: &str) -> (String, KevRecord) {
        (
            cve.to_string(),
            KevRecord {
                cve_id: cve.to_string(),
                date_added: "2026-01-01".to_string(),
                due_date: "2026-01-15".to_string(),
                known_ransomware_campaign_use: ransomware.to_string(),
                vulnerability_name: format!("name {cve}"),
                required_action: "Apply updates".to_string(),
            },
        )
    }

    fn vector(score: &str) -> Severity {
        Severity {
            kind: "CVSS_V3".to_string(),
            score: score.to_string(),
        }
    }

    #[test]
    fn two_cves_take_max_epss_any_kev_and_highest_cvss() {
        let mut advisory = advisory("GHSA-1111-2222-3333", &["CVE-2020-0001", "CVE-2020-0002"]);
        advisory.summary = "two cves".to_string();
        advisory.severity = vec![
            vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
            vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        ];
        let epss = BTreeMap::from([
            epss("CVE-2020-0001", 0.25, 0.5, "2026-10-01"),
            epss("CVE-2020-0002", 0.5, 0.25, "2026-10-02"),
        ]);
        let kev = BTreeMap::from([kev("CVE-2020-0001", "Unknown")]);

        let merged = merge_advisories(&[advisory], &epss, &kev);
        assert_eq!(merged.len(), 1);
        let item = &merged[0];
        assert_eq!(item.id, "GHSA-1111-2222-3333");
        assert_eq!(
            item.cves,
            vec!["CVE-2020-0001".to_string(), "CVE-2020-0002".to_string()]
        );
        assert_eq!(item.epss.score, 0.5);
        assert_eq!(item.epss.percentile, 0.5);
        assert_eq!(item.epss.date.as_deref(), Some("2026-10-02"));
        assert!(item.kev);
        assert_eq!(
            item.kev_record.as_ref().map(|row| row.cve_id.as_str()),
            Some("CVE-2020-0001")
        );
        assert_eq!(item.cvss.as_ref().map(|cvss| cvss.base_score), Some(9.8));
    }

    #[test]
    fn advisory_without_a_cve_has_zero_epss_and_no_kev() {
        let mut advisory = advisory("GHSA-aaaa-bbbb-cccc", &[]);
        advisory.database_specific_severity = Some("MEDIUM".to_string());
        let epss = BTreeMap::from([epss("CVE-1999-0001", 0.5, 0.5, "2026-10-01")]);
        let kev = BTreeMap::from([kev("CVE-1999-0001", "Known")]);

        let merged = merge_advisories(&[advisory], &epss, &kev);
        assert_eq!(merged.len(), 1);
        let item = &merged[0];
        assert!(item.cves.is_empty());
        assert_eq!(item.epss.score, 0.0);
        assert_eq!(item.epss.percentile, 0.0);
        assert!(item.epss.date.is_none());
        assert!(!item.kev);
        assert!(item.kev_record.is_none());
        assert_eq!(item.cvss.as_ref().map(|cvss| cvss.base_score), Some(5.0));
        assert_eq!(
            item.cvss.as_ref().map(|cvss| cvss.source.as_str()),
            Some("database_specific")
        );
    }

    #[test]
    fn aliased_advisories_collapse_to_the_ghsa_id() {
        let mut ghsa = advisory("GHSA-cccc-dddd-eeee", &["CVE-2021-1111", "OSV-2021-1"]);
        ghsa.summary = "from ghsa".to_string();
        ghsa.fixed_versions = vec!["4.17.21".to_string()];
        ghsa.references = vec!["https://example.test/ghsa".to_string()];
        ghsa.severity = vec![vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")];

        let mut cve = advisory("CVE-2021-1111", &["GHSA-cccc-dddd-eeee"]);
        cve.summary = "from cve".to_string();
        cve.fixed_versions = vec!["4.17.20".to_string(), "4.17.21".to_string()];
        cve.references = vec!["https://example.test/cve".to_string()];
        cve.severity = vec![vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")];

        let mut other = advisory("GHSA-9999-8888-7777", &["CVE-2024-9999"]);
        other.summary = "unrelated".to_string();

        let epss = BTreeMap::from([epss("CVE-2021-1111", 0.25, 0.25, "2026-10-03")]);
        let kev = BTreeMap::new();

        let merged = merge_advisories(&[cve, ghsa, other], &epss, &kev);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "GHSA-cccc-dddd-eeee");
        assert_eq!(merged[0].summary, "from ghsa");
        assert_eq!(
            merged[0].aliases,
            vec!["CVE-2021-1111".to_string(), "OSV-2021-1".to_string(),]
        );
        assert_eq!(merged[0].cves, vec!["CVE-2021-1111".to_string()]);
        assert_eq!(
            merged[0].fixed_versions,
            vec!["4.17.20".to_string(), "4.17.21".to_string()]
        );
        assert_eq!(
            merged[0].references,
            vec![
                "https://example.test/cve".to_string(),
                "https://example.test/ghsa".to_string(),
            ]
        );
        assert_eq!(merged[0].epss.score, 0.25);
        assert!(!merged[0].kev);
        assert_eq!(
            merged[0].cvss.as_ref().map(|cvss| cvss.base_score),
            Some(9.8)
        );
        assert_eq!(merged[1].id, "GHSA-9999-8888-7777");
        assert_eq!(merged[1].cves, vec!["CVE-2024-9999".to_string()]);
        assert_eq!(merged[1].epss.score, 0.0);
    }

    #[test]
    fn known_ransomware_wins_when_two_cves_are_in_kev() {
        let advisory = advisory("GHSA-1212-3434-5656", &["CVE-2022-0002", "CVE-2022-0001"]);
        let kev = BTreeMap::from([
            kev("CVE-2022-0001", "Unknown"),
            kev("CVE-2022-0002", "Known"),
        ]);
        let merged = merge_advisories(&[advisory], &BTreeMap::new(), &kev);
        assert_eq!(
            merged[0].kev_record.as_ref().map(|row| row.cve_id.as_str()),
            Some("CVE-2022-0002")
        );
    }
}
