//! CVSS base scores from OSV severity vectors.
//!
//! v3.x and v4.0 vectors are scored with the RustSec `cvss` crate, whose
//! equations follow the FIRST specifications. When no vector parses, the
//! qualitative `database_specific.severity` label is mapped per PRD AC3.3.
//! Neither a vector nor a known label yields `None`.

use std::cmp::Ordering;
use std::str::FromStr;

use crate::model::Severity;

/// Where a CVSS number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CvssSource {
    /// Parsed from an OSV `severity[]` vector string.
    Osv,
    /// Mapped from `database_specific.severity`.
    DatabaseSpecific,
}

impl CvssSource {
    /// JSON / report token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Osv => "osv",
            Self::DatabaseSpecific => "database_specific",
        }
    }
}

/// One CVSS number for an advisory.
///
/// `version` and `vector` are absent when the number is a severity fallback.
#[derive(Debug, Clone, PartialEq)]
pub struct CvssAssessment {
    /// `"2.0"`, `"3.0"`, `"3.1"`, or `"4.0"` for a parsed vector.
    pub version: Option<String>,
    /// Original vector string.
    pub vector: Option<String>,
    /// Base score in `0.0..=10.0`.
    pub base_score: f64,
    /// Provenance of [`Self::base_score`].
    pub source: CvssSource,
}

/// Score `severities`, or fall back to `database_specific_severity`.
///
/// Several vectors keep the highest base score. Equal scores keep the earlier
/// entry. A vector that the crate rejects is ignored. The qualitative fallback
/// is used only when every vector is missing or unusable.
pub fn assess(
    severities: &[Severity],
    database_specific_severity: Option<&str>,
) -> Option<CvssAssessment> {
    let mut best: Option<CvssAssessment> = None;
    for item in severities {
        let Some(scored) = score_vector(&item.score) else {
            continue;
        };
        let replace = match &best {
            Some(current) => scored.base_score.total_cmp(&current.base_score) == Ordering::Greater,
            None => true,
        };
        if replace {
            best = Some(scored);
        }
    }
    if best.is_some() {
        return best;
    }
    let score = severity_fallback(database_specific_severity?)?;
    Some(CvssAssessment {
        version: None,
        vector: None,
        base_score: score,
        source: CvssSource::DatabaseSpecific,
    })
}

/// Base score of one vector string, or `None` when it does not parse.
pub fn score_vector(vector: &str) -> Option<CvssAssessment> {
    let vector = vector.trim();
    if vector.is_empty() {
        return None;
    }
    let parsed = cvss::Cvss::from_str(vector).ok()?;
    Some(CvssAssessment {
        version: Some(version_of(&parsed).to_string()),
        vector: Some(vector.to_string()),
        base_score: parsed.score(),
        source: CvssSource::Osv,
    })
}

/// PRD AC3.3 qualitative map. Unknown labels, including empty, are `None`.
pub fn severity_fallback(label: &str) -> Option<f64> {
    match label.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(9.5),
        "HIGH" => Some(7.5),
        "MODERATE" | "MEDIUM" => Some(5.0),
        "LOW" => Some(2.5),
        _ => None,
    }
}

fn version_of(parsed: &cvss::Cvss) -> &'static str {
    match parsed {
        cvss::Cvss::CvssV20(_) => "2.0",
        cvss::Cvss::CvssV30(_) => "3.0",
        cvss::Cvss::CvssV31(_) => "3.1",
        cvss::Cvss::CvssV40(_) => "4.0",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn severity(kind: &str, score: &str) -> Severity {
        Severity {
            kind: kind.to_string(),
            score: score.to_string(),
        }
    }

    /// Scores published by the FIRST CVSS v3.1 calculator.
    #[test]
    fn first_v3_vectors_match_the_official_calculator() {
        let cases = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.4),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ];
        for (vector, expected) in cases {
            let scored = score_vector(vector).expect(vector);
            assert_eq!(scored.base_score, expected, "{vector}");
            assert_eq!(scored.vector.as_deref(), Some(vector));
            assert_eq!(scored.source, CvssSource::Osv);
            assert!(scored.version.as_deref().unwrap().starts_with("3."));
        }
    }

    /// FIRST CVSS v4.0 calculator: this base vector scores 9.3.
    #[test]
    fn first_v4_vector_matches_the_official_calculator() {
        let vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        let scored = score_vector(vector).expect("v4");
        assert_eq!(scored.base_score, 9.3);
        assert_eq!(scored.version.as_deref(), Some("4.0"));
        assert_eq!(scored.source, CvssSource::Osv);
    }

    #[test]
    fn highest_vector_wins_over_a_lower_one_and_over_the_label() {
        let scored = assess(
            &[
                severity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
                severity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ],
            Some("LOW"),
        )
        .expect("vector");
        assert_eq!(scored.base_score, 9.8);
        assert_eq!(
            scored.vector.as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        assert_eq!(scored.source, CvssSource::Osv);
    }

    #[test]
    fn equal_scores_keep_the_earlier_vector() {
        let earlier = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
        let later = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H";
        let scored = assess(
            &[severity("CVSS_V3", earlier), severity("CVSS_V3", later)],
            None,
        )
        .expect("tie");
        assert_eq!(scored.base_score, 8.8);
        assert_eq!(scored.vector.as_deref(), Some(earlier));
    }

    #[test]
    fn severity_fallback_maps_the_prd_labels() {
        let cases = [
            ("CRITICAL", 9.5),
            ("high", 7.5),
            ("MODERATE", 5.0),
            ("medium", 5.0),
            (" Low ", 2.5),
        ];
        for (label, expected) in cases {
            let scored = assess(&[], Some(label)).expect(label);
            assert_eq!(scored.base_score, expected, "{label}");
            assert!(scored.version.is_none());
            assert!(scored.vector.is_none());
            assert_eq!(scored.source, CvssSource::DatabaseSpecific);
            assert_eq!(scored.source.as_str(), "database_specific");
        }
    }

    #[test]
    fn missing_or_unknown_severity_is_none() {
        assert!(assess(&[], None).is_none());
        assert!(assess(&[], Some("")).is_none());
        assert!(assess(&[], Some("NONE")).is_none());
        assert!(assess(&[], Some("informational")).is_none());
        assert!(score_vector("not-a-vector").is_none());
        assert!(assess(&[severity("CVSS_V3", "not-a-vector")], None).is_none());
    }

    #[test]
    fn unusable_vector_falls_back_to_the_label() {
        let scored = assess(&[severity("CVSS_V3", "7.5")], Some("HIGH")).expect("fallback");
        assert_eq!(scored.base_score, 7.5);
        assert_eq!(scored.source, CvssSource::DatabaseSpecific);
    }
}
