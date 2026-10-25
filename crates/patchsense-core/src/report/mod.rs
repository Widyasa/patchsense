//! Report renderers. The scan stores a [`crate::model::Report`]; these modules
//! turn it into the documents CI and reviewers consume.

pub mod json;
pub mod sarif;

pub use json::render_json;
pub use sarif::render_sarif;
