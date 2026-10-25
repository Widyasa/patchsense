# jackson-core `pom.xml`

- Repository: https://github.com/FasterXML/jackson-core
- Tag: `jackson-core-2.16.0`
- Commit: `2af46f18403d962d18121918c822d13224a3943c` (2023-11-15)
- File: `pom.xml`
- License: Apache-2.0
- Retrieved: 2026-10-25

Trimmed. The original POM keeps a large `<build>` (shade relocations, animal-sniffer, site). This copy keeps the parent `jackson-base` 2.16.0, module coordinates `com.fasterxml.jackson.core:jackson-core` 2.16.0, four properties, the `junit-bom` 5.9.3 `import` inside `dependencyManagement`, the gradle-module-metadata plugin's `removedDependencies` entry for `fastdoubleparser` (no version), and the `<dependencies>` block: `ch.randelshofer:fastdoubleparser` 0.9.0 plus three test artifacts with no version. Those versionless test artifacts are managed by the parent BOM and must be warnings, not packages.
