//! Parser for Maven `pom.xml`.
//!
//! A POM is not a full lockfile. Declared `<dependencies>/<dependency>` entries
//! are direct packages named `groupId:artifactId`. Transitive artifacts are not
//! listed. `test` scope is dev. `import` scope is a BOM and is not a package.
//!
//! Versions may use `${property}` from the project's `<properties>`, plus
//! `${project.version}`, `${project.groupId}`, and `${project.artifactId}`
//! (and the `pom.*` aliases Maven accepts). Substitution runs at most eight
//! times. A version that still contains `${` is skipped with a warning: parent
//! BOMs and external `dependencyManagement` are not resolved.
//!
//! Dependencies inside `dependencyManagement`, `plugin`, `plugins`, or
//! `pluginManagement` are build metadata, not project dependencies.

use std::collections::BTreeMap;
use std::path::Path;

use quick_xml::escape::unescape;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::CoreError;
use crate::lockfile::LockfileParser;
use crate::model::{Ecosystem, Package, ParsedLockfile};

/// How many `${...}` passes to run before giving up.
const MAX_PROPERTY_PASSES: usize = 8;

/// Parser for `pom.xml`.
pub struct MavenParser;

impl LockfileParser for MavenParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Maven
    }

    fn matches(&self, path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("pom.xml"))
    }

    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
        parse_pom(path, content)
    }
}

#[derive(Default)]
struct Dependency {
    group_id: String,
    artifact_id: String,
    version: String,
    scope: String,
    line: u32,
}

struct PomReader<'a> {
    path: &'a Path,
    stack: Vec<String>,
    properties: BTreeMap<String, String>,
    project_group: String,
    project_artifact: String,
    project_version: String,
    dependency: Option<Dependency>,
    dependency_depth: usize,
    pending: Vec<Dependency>,
    text: String,
    capture: Capture,
    packages: Vec<Package>,
    warnings: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Capture {
    None,
    DependencyField(Field),
    ProjectField(Field),
    Property,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    GroupId,
    ArtifactId,
    Version,
    Scope,
}

fn parse_pom(path: &Path, content: &str) -> Result<ParsedLockfile, CoreError> {
    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);
    let mut state = PomReader {
        path,
        stack: Vec::new(),
        properties: BTreeMap::new(),
        project_group: String::new(),
        project_artifact: String::new(),
        project_version: String::new(),
        dependency: None,
        dependency_depth: 0,
        pending: Vec::new(),
        text: String::new(),
        capture: Capture::None,
        packages: Vec::new(),
        warnings: Vec::new(),
    };
    let mut buf = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buf).map_err(|err| {
            CoreError::parse(
                path,
                Some(line_at(content, reader.buffer_position())),
                err.to_string(),
            )
        })?;
        let position = reader.buffer_position();
        match event {
            Event::Start(element) => {
                let name = local_name(element.local_name().as_ref());
                state.begin_element(&name, line_at(content, position) as u32);
            }
            Event::Empty(element) => {
                let name = local_name(element.local_name().as_ref());
                state.begin_element(&name, line_at(content, position) as u32);
                state.end_element(&name);
            }
            Event::Text(text) => {
                if state.capture != Capture::None {
                    let decoded = unescape(text.as_ref()).map_err(|err| {
                        CoreError::parse(path, Some(line_at(content, position)), err.to_string())
                    })?;
                    state.text.push_str(&decoded);
                }
            }
            Event::CData(text) => {
                if state.capture != Capture::None {
                    state.text.push_str(text.as_ref());
                }
            }
            Event::End(element) => {
                let name = local_name(element.local_name().as_ref());
                state.end_element(&name);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if !state.stack.is_empty() {
        return Err(CoreError::parse(
            path,
            None,
            "pom.xml ended before all elements were closed",
        ));
    }
    // Properties and ${project.version} may appear after <dependencies>.
    state.resolve_pending();
    state
        .packages
        .sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    Ok(ParsedLockfile {
        ecosystem: Ecosystem::Maven,
        packages: state.packages,
        warnings: state.warnings,
    })
}

impl PomReader<'_> {
    fn begin_element(&mut self, name: &str, line: u32) {
        self.stack.push(name.to_string());
        if self.dependency.is_none() && is_project_dependency(&self.stack) {
            self.dependency = Some(Dependency {
                line,
                ..Dependency::default()
            });
            self.dependency_depth = self.stack.len();
            self.capture = Capture::None;
            self.text.clear();
            return;
        }
        self.capture = self.capture_for(name);
        if self.capture != Capture::None {
            self.text.clear();
        }
    }

    fn capture_for(&self, name: &str) -> Capture {
        if self
            .dependency
            .as_ref()
            .is_some_and(|_| self.stack.len() == self.dependency_depth + 1)
        {
            if let Some(field) = field_of(name) {
                return Capture::DependencyField(field);
            }
        }
        if is_project_coordinate(&self.stack) {
            if let Some(field) = field_of(name) {
                if field != Field::Scope {
                    return Capture::ProjectField(field);
                }
            }
        }
        if is_project_property(&self.stack) {
            return Capture::Property;
        }
        Capture::None
    }

    fn end_element(&mut self, name: &str) {
        let text = std::mem::take(&mut self.text);
        let capture = self.capture;
        self.capture = Capture::None;
        match capture {
            Capture::DependencyField(field) => {
                if let Some(dep) = self.dependency.as_mut() {
                    assign_field(dep, field, text.trim());
                }
            }
            Capture::ProjectField(field) => match field {
                Field::GroupId => self.project_group = text.trim().to_string(),
                Field::ArtifactId => self.project_artifact = text.trim().to_string(),
                Field::Version => self.project_version = text.trim().to_string(),
                Field::Scope => {}
            },
            Capture::Property => {
                let key = self.stack.last().cloned().unwrap_or_default();
                if !key.is_empty() {
                    self.properties.insert(key, text.trim().to_string());
                }
            }
            Capture::None => {}
        }
        let finishing = self.dependency.is_some()
            && self.stack.len() == self.dependency_depth
            && name == "dependency";
        if finishing {
            if let Some(dep) = self.dependency.take() {
                self.pending.push(dep);
            }
        }
        self.stack.pop();
    }

    fn resolve_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        for dep in pending {
            self.finish_dependency(dep);
        }
    }

    fn finish_dependency(&mut self, dep: Dependency) {
        let source = display_path(self.path);
        let group = if dep.group_id.is_empty() {
            self.project_group.clone()
        } else {
            dep.group_id.clone()
        };
        if group.is_empty() || dep.artifact_id.is_empty() {
            self.warnings.push(format!(
                "{source}:{}: skipped dependency with missing groupId or artifactId",
                dep.line
            ));
            return;
        }
        let coordinate = format!("{group}:{}", dep.artifact_id);
        if dep.scope.eq_ignore_ascii_case("import") {
            self.warnings.push(format!(
                "{source}:{}: skipped import-scoped BOM {coordinate}",
                dep.line
            ));
            return;
        }
        let resolved = resolve_version(&dep.version, self);
        if dep.version.trim().is_empty() || resolved.contains("${") {
            let shown = if dep.version.trim().is_empty() {
                "(missing)"
            } else {
                dep.version.trim()
            };
            self.warnings.push(format!(
                "{source}:{}: skipped {coordinate} version `{shown}` (parent BOM or dependencyManagement)",
                dep.line
            ));
            return;
        }
        self.packages.push(Package {
            ecosystem: Ecosystem::Maven,
            name: coordinate,
            version: resolved,
            direct: Some(true),
            dev: dep.scope.eq_ignore_ascii_case("test"),
            source_file: source,
            source_files: Vec::new(),
            line: Some(dep.line),
        });
    }
}

fn assign_field(dep: &mut Dependency, field: Field, text: &str) {
    match field {
        Field::GroupId => dep.group_id = text.to_string(),
        Field::ArtifactId => dep.artifact_id = text.to_string(),
        Field::Version => dep.version = text.to_string(),
        Field::Scope => dep.scope = text.to_string(),
    }
}

fn field_of(name: &str) -> Option<Field> {
    match name {
        "groupId" => Some(Field::GroupId),
        "artifactId" => Some(Field::ArtifactId),
        "version" => Some(Field::Version),
        "scope" => Some(Field::Scope),
        _ => None,
    }
}

fn is_project_dependency(stack: &[String]) -> bool {
    let Some(parent) = stack
        .len()
        .checked_sub(2)
        .map(|index| stack[index].as_str())
    else {
        return false;
    };
    stack.last().is_some_and(|name| name == "dependency")
        && parent == "dependencies"
        && !stack.iter().any(|name| {
            matches!(
                name.as_str(),
                "dependencyManagement" | "plugin" | "plugins" | "pluginManagement"
            )
        })
}

fn is_project_coordinate(stack: &[String]) -> bool {
    stack.len() == 2 && stack[0] == "project"
}

fn is_project_property(stack: &[String]) -> bool {
    stack.len() == 3 && stack[0] == "project" && stack[1] == "properties"
}

fn resolve_version(raw: &str, state: &PomReader<'_>) -> String {
    let mut props = state.properties.clone();
    if !state.project_version.is_empty() {
        props.insert("project.version".to_string(), state.project_version.clone());
        props.insert("pom.version".to_string(), state.project_version.clone());
    }
    if !state.project_group.is_empty() {
        props.insert("project.groupId".to_string(), state.project_group.clone());
        props.insert("pom.groupId".to_string(), state.project_group.clone());
    }
    if !state.project_artifact.is_empty() {
        props.insert(
            "project.artifactId".to_string(),
            state.project_artifact.clone(),
        );
        props.insert("pom.artifactId".to_string(), state.project_artifact.clone());
    }
    substitute(raw.trim(), &props)
}

fn substitute(input: &str, props: &BTreeMap<String, String>) -> String {
    let mut current = input.to_string();
    for _ in 0..MAX_PROPERTY_PASSES {
        if !current.contains("${") {
            break;
        }
        let mut next = String::with_capacity(current.len());
        let mut rest = current.as_str();
        let mut changed = false;
        while let Some(start) = rest.find("${") {
            next.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            if let Some(end) = after.find('}') {
                let key = &after[..end];
                if let Some(value) = props.get(key) {
                    next.push_str(value);
                    changed = true;
                } else {
                    next.push_str("${");
                    next.push_str(key);
                    next.push('}');
                }
                rest = &after[end + 1..];
            } else {
                next.push_str(&rest[start..]);
                rest = "";
                break;
            }
        }
        next.push_str(rest);
        if !changed {
            break;
        }
        current = next;
    }
    current
}

fn local_name(qname: &str) -> String {
    match qname.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => qname.to_string(),
    }
}

fn line_at(content: &str, byte_pos: u64) -> usize {
    let end = usize::try_from(byte_pos)
        .unwrap_or(content.len())
        .min(content.len());
    content[..end].bytes().filter(|byte| *byte == b'\n').count() + 1
}

fn display_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn parse_fixture(project: &str) -> ParsedLockfile {
        let relative = format!("tests/fixtures/maven/{project}/pom.xml");
        let full = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&relative);
        let content = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("read {}: {err}", full.display()));
        MavenParser
            .parse(Path::new(&relative), &content)
            .unwrap_or_else(|err| panic!("parse {project}: {err}"))
    }

    #[test]
    fn commons_lang_resolves_jmh_property_and_warns_on_junit() {
        let parsed = parse_fixture("commons-lang");
        let jmh = parsed
            .packages
            .iter()
            .find(|package| package.name == "org.openjdk.jmh:jmh-core")
            .expect("jmh-core");
        assert_eq!(jmh.version, "1.37");
        assert!(jmh.dev);
        assert_eq!(jmh.direct, Some(true));
        let hamcrest = parsed
            .packages
            .iter()
            .find(|package| package.name == "org.hamcrest:hamcrest")
            .expect("hamcrest");
        assert_eq!(hamcrest.version, "2.2");
        assert!(hamcrest.dev);
        assert!(
            !parsed
                .packages
                .iter()
                .any(|package| package.name.contains("maven-pmd-plugin")),
            "plugin coordinates must not become packages"
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.contains("org.junit.jupiter:junit-jupiter")),
            "{:?}",
            parsed.warnings
        );
        insta::assert_yaml_snapshot!("commons_lang_packages", parsed.packages);
        insta::assert_yaml_snapshot!("commons_lang_warnings", parsed.warnings);
    }

    #[test]
    fn jackson_core_ignores_bom_import_and_plugin_coordinates() {
        let parsed = parse_fixture("jackson-core");
        let fdp = parsed
            .packages
            .iter()
            .find(|package| package.name == "ch.randelshofer:fastdoubleparser")
            .expect("fastdoubleparser");
        assert_eq!(fdp.version, "0.9.0");
        assert!(!fdp.dev);
        assert_eq!(fdp.direct, Some(true));
        assert!(
            !parsed
                .packages
                .iter()
                .any(|package| package.name == "org.junit:junit-bom"),
            "dependencyManagement import is not a package"
        );
        for name in [
            "org.junit.vintage:junit-vintage-engine",
            "org.junit.jupiter:junit-jupiter",
            "org.assertj:assertj-core",
        ] {
            assert!(
                parsed.warnings.iter().any(|warning| warning.contains(name)),
                "{name} missing from {:?}",
                parsed.warnings
            );
        }
        insta::assert_yaml_snapshot!("jackson_packages", parsed.packages);
        insta::assert_yaml_snapshot!("jackson_warnings", parsed.warnings);
    }

    #[test]
    fn project_version_and_nested_properties_resolve() {
        let pom = r#"
            <project>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.2.3</version>
              <properties>
                <rev>9</rev>
                <lib.version>1.${rev}.0</lib.version>
              </properties>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.junit</groupId>
                    <artifactId>junit-bom</artifactId>
                    <version>5.9.3</version>
                    <scope>import</scope>
                  </dependency>
                </dependencies>
              </dependencyManagement>
              <dependencies>
                <dependency>
                  <artifactId>same-group</artifactId>
                  <version>${project.version}</version>
                </dependency>
                <dependency>
                  <groupId>com.example</groupId>
                  <artifactId>nested</artifactId>
                  <version>${lib.version}</version>
                  <scope>test</scope>
                </dependency>
              </dependencies>
            </project>
        "#;
        let parsed = MavenParser.parse(Path::new("pom.xml"), pom).expect("parse");
        let same = parsed
            .packages
            .iter()
            .find(|package| package.name == "com.example:same-group")
            .expect("same-group");
        assert_eq!(same.version, "1.2.3");
        assert!(!same.dev);
        let nested = parsed
            .packages
            .iter()
            .find(|package| package.name == "com.example:nested")
            .expect("nested");
        assert_eq!(nested.version, "1.9.0");
        assert!(nested.dev);
        assert!(parsed
            .packages
            .iter()
            .all(|package| package.name != "org.junit:junit-bom"));
    }

    #[test]
    fn broken_xml_names_the_file() {
        let err = MavenParser
            .parse(Path::new("pom.xml"), "<project><dependencies></project>")
            .expect_err("broken");
        let message = err.to_string();
        assert!(message.contains("pom.xml"), "{message}");
    }
}
