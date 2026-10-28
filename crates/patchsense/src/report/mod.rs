//! Report renderers. The scan stores a [`crate::model::Report`]; these modules
//! turn it into the documents CI and reviewers consume.

pub mod gitlab;
pub mod json;
pub mod markdown;
pub mod sarif;

pub use gitlab::render_gitlab;
pub use json::render_json;
pub use markdown::render_markdown;
pub use sarif::render_sarif;
