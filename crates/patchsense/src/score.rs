//! Priority score from PRD §9.
//!
//! Components are KEV, EPSS, CVSS, direct, and fix-available. The rounded
//! score is half-away-from-zero. When the weights do not add up to 100 the
//! raw total is scaled to 0–100 and a warning is returned.

use crate::config::{EpssMode, ScoreSection, Thresholds};
use crate::model::Tier;

/// One package/advisory pair before scoring.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreRequest {
    /// Package name, used as the last sort key.
    pub package_name: String,
    /// True when any alias CVE is in the KEV catalog.
    pub kev: bool,
    /// EPSS probability and percentile. `None` when there is no CVE or no row.
    pub epss: Option<EpssSample>,
    /// CVSS base score, 0–10. `None` contributes 0.
    pub cvss_base: Option<f64>,
    /// `Some(true)` direct, `Some(false)` transitive, `None` unknown.
    pub direct: Option<bool>,
    /// True when the installed version has a fixed release.
    pub fix_available: bool,
}

/// The two EPSS numbers the formula can use.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpssSample {
    /// Probability, 0–1.
    pub score: f64,
    /// Percentile, 0–1.
    pub percentile: f64,
}

/// Unnormalized component values. They sum to the pre-scale raw total.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreBreakdown {
    /// KEV component.
    pub kev: f64,
    /// EPSS component.
    pub epss: f64,
    /// CVSS component.
    pub cvss: f64,
    /// Direct-dependency component.
    pub direct: f64,
    /// Fix-available component.
    pub fix_available: f64,
    /// Sum of the configured weights.
    pub total_weight: f64,
}

/// A scored row, ready to sort.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoredFinding {
    /// Package name copied from the request.
    pub package_name: String,
    /// KEV flag copied from the request.
    pub kev: bool,
    /// Rounded score, 0–100.
    pub score: u32,
    /// Tier for `score`.
    pub tier: Tier,
    /// Component values before rounding.
    pub breakdown: ScoreBreakdown,
}

/// Score one request. The warning list is empty when the weights sum to 100.
pub fn score_request(request: &ScoreRequest, score: &ScoreSection) -> (ScoredFinding, Vec<String>) {
    let (mut findings, warnings) = score_findings(std::slice::from_ref(request), score);
    let finding = findings
        .pop()
        .expect("INVARIANT: one request produces one scored row");
    (finding, warnings)
}

/// Score every request and sort the result.
///
/// Order is score descending, then KEV true first, then package name, then
/// the original input order. A weight total other than 100 adds one warning.
pub fn score_findings(
    requests: &[ScoreRequest],
    score: &ScoreSection,
) -> (Vec<ScoredFinding>, Vec<String>) {
    let total = weight_total(score);
    let mut warnings = Vec::new();
    if (total - 100.0).abs() > 1e-9 {
        warnings.push(format!("score weights total {total}, normalized to 0-100"));
    }
    let mut ranked: Vec<(usize, ScoredFinding)> = requests
        .iter()
        .enumerate()
        .map(|(index, request)| (index, score_one(request, score, total)))
        .collect();
    ranked.sort_by(|left, right| {
        right
            .1
            .score
            .cmp(&left.1.score)
            .then_with(|| right.1.kev.cmp(&left.1.kev))
            .then_with(|| left.1.package_name.cmp(&right.1.package_name))
            .then_with(|| left.0.cmp(&right.0))
    });
    let findings = ranked.into_iter().map(|(_, finding)| finding).collect();
    (findings, warnings)
}

/// Round `raw / total * 100` and pick a tier.
///
/// `total` of 0 yields score 0. Rounding is half away from zero.
pub fn finalize(raw: f64, total_weight: f64, thresholds: &Thresholds) -> (u32, Tier) {
    let scaled = if total_weight.abs() < 1e-12 {
        0.0
    } else {
        raw / total_weight * 100.0
    };
    let clamped = scaled.clamp(0.0, 100.0);
    let score = clamped.round() as u32;
    (score, tier_for(score, thresholds))
}

fn score_one(request: &ScoreRequest, score: &ScoreSection, total: f64) -> ScoredFinding {
    let weights = &score.weights;
    let kev = if request.kev { weights.kev } else { 0.0 };
    let epss = weights.epss * epss_factor(request.epss, score);
    let cvss = match request.cvss_base {
        Some(base) => weights.cvss * (base / 10.0),
        None => 0.0,
    };
    let direct_fraction = match request.direct {
        Some(true) => 1.0,
        Some(false) => 0.0,
        None => score.unknown_direct.weight_fraction,
    };
    let direct = weights.direct * direct_fraction;
    let fix_available = if request.fix_available {
        weights.fix_available
    } else {
        0.0
    };
    let raw = kev + epss + cvss + direct + fix_available;
    let (rounded, tier) = finalize(raw, total, &score.thresholds);
    ScoredFinding {
        package_name: request.package_name.clone(),
        kev: request.kev,
        score: rounded,
        tier,
        breakdown: ScoreBreakdown {
            kev,
            epss,
            cvss,
            direct,
            fix_available,
            total_weight: total,
        },
    }
}

fn epss_factor(sample: Option<EpssSample>, score: &ScoreSection) -> f64 {
    let Some(sample) = sample else {
        return 0.0;
    };
    match score.epss.mode {
        EpssMode::Probability => {
            let saturation = score.epss.saturation;
            if saturation <= 0.0 {
                0.0
            } else {
                (sample.score / saturation).clamp(0.0, 1.0)
            }
        }
        EpssMode::Percentile => sample.percentile.clamp(0.0, 1.0),
    }
}

fn weight_total(score: &ScoreSection) -> f64 {
    let weights = &score.weights;
    weights.kev + weights.epss + weights.cvss + weights.direct + weights.fix_available
}

fn tier_for(score: u32, thresholds: &Thresholds) -> Tier {
    let score = f64::from(score);
    if score >= thresholds.critical {
        Tier::Critical
    } else if score >= thresholds.review {
        Tier::Review
    } else {
        Tier::Defer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EpssMode, ScoreSection};

    fn req(name: &str) -> ScoreRequest {
        ScoreRequest {
            package_name: name.to_string(),
            kev: false,
            epss: None,
            cvss_base: None,
            direct: Some(true),
            fix_available: true,
        }
    }

    fn one(request: ScoreRequest, score: &ScoreSection) -> ScoredFinding {
        let (mut findings, _) = score_findings(&[request], score);
        findings.pop().expect("one")
    }

    #[test]
    fn prd_cases_a_through_e() {
        let score = ScoreSection::default();

        let mut exploited = req("a");
        exploited.kev = true;
        exploited.epss = Some(EpssSample {
            score: 0.94,
            percentile: 0.99,
        });
        exploited.cvss_base = Some(9.8);
        let a = one(exploited, &score);
        assert_eq!(a.score, 100, "A breakdown {:?}", a.breakdown);
        assert_eq!(a.tier, Tier::Critical);

        let mut rare = req("b");
        rare.epss = Some(EpssSample {
            score: 0.0123,
            percentile: 0.5,
        });
        rare.cvss_base = Some(7.2);
        let b = one(rare, &score);
        assert_eq!(b.score, 37, "B breakdown {:?}", b.breakdown);
        assert_eq!(b.tier, Tier::Defer);
        assert!(
            (b.breakdown.cvss - 14.4).abs() < 1e-9,
            "{}",
            b.breakdown.cvss
        );
        assert!(
            (b.breakdown.epss - 3.075).abs() < 1e-6,
            "{}",
            b.breakdown.epss
        );

        let mut transitive = req("c");
        transitive.kev = true;
        transitive.epss = Some(EpssSample {
            score: 0.05,
            percentile: 0.2,
        });
        transitive.cvss_base = Some(8.1);
        transitive.direct = Some(false);
        transitive.fix_available = false;
        let c = one(transitive, &score);
        assert_eq!(c.score, 64, "C breakdown {:?}", c.breakdown);
        assert_eq!(c.tier, Tier::Review);

        let mut no_cve = req("d");
        no_cve.cvss_base = Some(5.0);
        let d = one(no_cve, &score);
        assert_eq!(d.score, 30, "D breakdown {:?}", d.breakdown);
        assert_eq!(d.tier, Tier::Defer);
        assert_eq!(d.breakdown.epss, 0.0);

        let mut edge = req("e");
        edge.kev = true;
        edge.epss = Some(EpssSample {
            score: 0.02,
            percentile: 0.1,
        });
        edge.cvss_base = Some(10.0);
        edge.fix_available = false;
        let e = one(edge, &score);
        assert_eq!(e.score, 70, "E breakdown {:?}", e.breakdown);
        assert_eq!(e.tier, Tier::Critical);
    }

    #[test]
    fn rounding_boundaries_use_half_away_from_zero() {
        let thresholds = Thresholds::default();
        let cases = [
            (69.5, 70, Tier::Critical),
            (70.0, 70, Tier::Critical),
            (69.4, 69, Tier::Review),
            (39.9, 40, Tier::Review),
            (40.0, 40, Tier::Review),
            (39.4, 39, Tier::Defer),
        ];
        for (raw, score, tier) in cases {
            assert_eq!(finalize(raw, 100.0, &thresholds), (score, tier), "{raw}");
        }
    }

    #[test]
    fn non_100_weights_are_normalized_with_a_warning() {
        let mut score = ScoreSection::default();
        score.weights.kev = 10.0;
        score.weights.epss = 0.0;
        score.weights.cvss = 0.0;
        score.weights.direct = 0.0;
        score.weights.fix_available = 0.0;
        let mut request = req("only-kev");
        request.kev = true;
        request.direct = Some(false);
        request.fix_available = false;
        let (findings, warnings) = score_findings(&[request], &score);
        assert_eq!(findings[0].score, 100);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("normalized"), "{}", warnings[0]);
    }

    #[test]
    fn unknown_direct_uses_the_configured_fraction() {
        let mut score = ScoreSection::default();
        score.unknown_direct.weight_fraction = 0.5;
        let mut request = req("unknown");
        request.direct = None;
        request.fix_available = false;
        request.cvss_base = None;
        let scored = one(request, &score);
        assert!((scored.breakdown.direct - 5.0).abs() < 1e-9);
    }

    #[test]
    fn percentile_mode_uses_the_percentile() {
        let mut score = ScoreSection::default();
        score.epss.mode = EpssMode::Percentile;
        let mut request = req("pct");
        request.epss = Some(EpssSample {
            score: 0.01,
            percentile: 0.40,
        });
        request.direct = Some(false);
        request.fix_available = false;
        let scored = one(request, &score);
        assert!((scored.breakdown.epss - 10.0).abs() < 1e-9);
    }

    #[test]
    fn sort_is_score_then_kev_then_name() {
        let score = ScoreSection::default();
        let mut high = req("z");
        high.kev = false;
        high.cvss_base = Some(10.0);
        high.epss = Some(EpssSample {
            score: 0.94,
            percentile: 1.0,
        });
        let mut kev_late = req("c");
        kev_late.kev = true;
        kev_late.cvss_base = Some(5.0);
        kev_late.fix_available = false;
        let mut kev_early = req("a");
        kev_early.kev = true;
        kev_early.cvss_base = Some(5.0);
        kev_early.fix_available = false;
        let mut plain = req("b");
        plain.cvss_base = Some(5.0);
        plain.fix_available = false;

        let (findings, warnings) = score_findings(&[plain, kev_late, high, kev_early], &score);
        assert!(warnings.is_empty());
        let names: Vec<_> = findings
            .iter()
            .map(|finding| finding.package_name.as_str())
            .collect();
        assert_eq!(names, vec!["z", "a", "c", "b"]);
        assert!(findings[1].kev && findings[2].kev);
        assert!(!findings[3].kev);
        assert_eq!(findings[1].score, findings[2].score);
    }
}
