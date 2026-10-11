//! mendr: find known vulnerabilities in project dependencies and fix them the
//! way a developer would. See PLAN.md for the design.

mod cache;
mod config;
mod ecosystem;
mod http;
mod model;
mod osv;
mod plan;
mod progress;
mod report;
mod rules;
mod safety;
mod verify;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, ValueEnum};

use crate::config::{Config, Overrides, ProjectConfig};
use crate::ecosystem::Ecosystem;
use crate::osv::Osv;
use crate::report::{Mode, ProjectReport, Report};

/// Find known vulnerabilities (via OSV) and fix them with the smallest change
/// that builds and passes tests. Never modifies the project unless --write.
///
/// Exit codes: 0 = no unresolved vulnerabilities, 1 = unresolved
/// vulnerabilities remain, 2 = error.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Config file (default: ./mendr.toml if present).
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Only plan fixes; do not build or test anything (no safety checks).
    #[arg(long)]
    plan_only: bool,

    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    format: Format,

    /// Write the report to FILE instead of stdout.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Use OSV records from DIR (one JSON record per *.json file) instead of
    /// the live osv.dev API.
    #[arg(long, value_name = "DIR")]
    osv_snapshot: Option<PathBuf>,

    /// Allow major version bumps (overrides [policy] allow-major).
    #[arg(long)]
    allow_major: bool,

    /// Run builds even when the safety checks find secrets reachable from
    /// this environment (overrides [safety] allow-unsandboxed).
    #[arg(long)]
    allow_unsandboxed: bool,

    /// Minimum age of any version mendr picks, e.g. "7d", "12h", "0" (off).
    /// Default: [policy] min-release-age, else 7d.
    #[arg(long, value_name = "DUR")]
    min_release_age: Option<String>,

    /// Copy verified manifest/lockfile changes back into the project.
    #[arg(long, conflicts_with = "plan_only")]
    write: bool,

    /// Print only warnings and errors on stderr (no progress).
    #[arg(long, short)]
    quiet: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Json,
    Markdown,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            progress::error(format!("{e:#}"));
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> Result<u8> {
    progress::init(cli.quiet);
    cache::prune();
    let started = Instant::now();
    let cwd = std::env::current_dir().context("reading current directory")?;
    let mut config = Config::load(cli.config.as_deref(), &cwd)?;
    config.apply_overrides(&Overrides {
        allow_major: cli.allow_major,
        allow_unsandboxed: cli.allow_unsandboxed,
        min_release_age: cli.min_release_age.clone(),
    })?;
    config.validate(&ecosystem::names())?;

    if !cli.plan_only {
        safety::enforce(&config.safety)?;
    }

    let mut osv = match &cli.osv_snapshot {
        Some(dir) => Osv::snapshot(&cwd.join(dir))?,
        None => Osv::live(),
    };
    let now = jiff::Timestamp::now();
    let today = rules::today(now);
    for rule in config
        .ignores
        .iter()
        .filter(|r| rules::ignore_expired(r, today))
    {
        progress::warn(format!(
            "[[ignore]] entry for {} expired on {}; the advisory is reported again \
             (renew or remove the entry)",
            rule.id,
            rule.expires.expect("expired rules have a date")
        ));
    }
    let mode = if cli.plan_only {
        Mode::Plan
    } else {
        Mode::Full
    };

    let mut projects = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for project in &config.projects {
        let mut pr = ProjectReport::new(&project.path, &config.base_dir);
        if let Err(e) = run_project(cli, &config, project, &mut osv, now, &mut seen_ids, &mut pr) {
            progress::error(format!("project {}: {e:#}", pr.path));
            pr.error = Some(format!("{e:#}"));
        }
        projects.push(pr);
    }
    osv::warn_unmatched_ignores(&config.ignores, &seen_ids, today);

    let report = Report::new(mode, projects);
    let took = progress::elapsed(started);
    match summarize(&report) {
        Some(summary) => progress::line("Finished", format!("{summary} ({took})")),
        None => progress::line("Finished", format!("in {took}")),
    }
    let text = match cli.format {
        Format::Json => report.to_json(),
        Format::Markdown => report.to_markdown(),
    };
    match &cli.output {
        Some(path) => std::fs::write(cwd.join(path), text)
            .with_context(|| format!("writing {}", path.display()))?,
        None => print!("{text}"),
    }
    Ok(report.exit_code() as u8)
}

fn ecosystem_for(project: &ProjectConfig) -> Result<Box<dyn Ecosystem>> {
    match &project.ecosystem {
        Some(name) => ecosystem::by_name(name).ok_or_else(|| anyhow!("unknown ecosystem `{name}`")),
        None => ecosystem::detect_ecosystem(&project.path).ok_or_else(|| {
            anyhow!(
                "no supported project with a lockfile found in {} (supported: {})",
                project.path.display(),
                ecosystem::names().join(", ")
            )
        }),
    }
}

fn run_project(
    cli: &Cli,
    config: &Config,
    project: &ProjectConfig,
    osv: &mut Osv,
    now: jiff::Timestamp,
    seen_ids: &mut BTreeSet<String>,
    report: &mut ProjectReport,
) -> Result<()> {
    if !project.path.is_dir() {
        anyhow::bail!("{} is not a directory", project.path.display());
    }
    let eco = ecosystem_for(project)?;
    report.ecosystem = Some(eco.name().to_string());
    progress::line(
        "Scanning",
        format!("{} ({})", display_path(&project.path), eco.name()),
    );

    let step = progress::begin("Resolving", "dependency graph");
    let graph = eco
        .resolve_graph(&project.path)
        .context("resolving dependency graph")?;
    let packages = osv::package_names(&graph);
    step.done(
        "Resolved",
        progress::count(
            graph.nodes.len().saturating_sub(graph.roots.len()),
            "dependency",
            "dependencies",
        ),
    );

    let step = progress::begin(
        "Checking",
        format!(
            "{} against OSV",
            progress::count(packages.len(), "package", "packages")
        ),
    );
    let advisories = osv
        .advisories(eco.as_ref(), &packages)
        .context("looking up advisories")?;
    osv::remember_ids(seen_ids, &advisories);
    step.done(
        "Checked",
        format!(
            "{} against OSV",
            progress::count(packages.len(), "package", "packages")
        ),
    );

    let step = progress::begin("Planning", "fixes");
    let mut project_plan = plan::plan(&plan::PlanInput {
        eco: eco.as_ref(),
        graph: &graph,
        advisories: &advisories,
        policy: &config.policy,
        ignores: &config.ignores,
        now,
    });
    if project_plan.findings.is_empty() {
        drop(step);
        progress::line("Found", "no known vulnerabilities");
    } else {
        step.done(
            "Planned",
            format!(
                "{} for {}",
                progress::count(project_plan.changes.len(), "change", "changes"),
                progress::count(project_plan.findings.len(), "finding", "findings")
            ),
        );
    }

    if !cli.plan_only && !project_plan.changes.is_empty() {
        let ctx = verify::VerifyContext {
            eco: eco.as_ref(),
            project,
            commands: project.commands(eco.default_commands(&project.path)),
            timeout: project.timeout,
            policy: &config.policy,
            ignores: &config.ignores,
            now,
        };
        let verified = verify::verify(&ctx, osv, &mut project_plan)?;
        if cli.write {
            for file in verify::write_back(&ctx, &verified)? {
                progress::line("Updated", display_path(&file));
            }
        }
    }

    report.findings = project_plan.findings;
    report.changes = project_plan.changes;
    Ok(())
}

/// `path` relative to the current directory when it is inside it.
fn display_path(path: &Path) -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    match path.strip_prefix(&cwd) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
        Ok(rel) => rel.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// `3 findings: 2 fixed, 1 skipped` for the final progress line; `None`
/// when there is nothing to say (already reported per project).
fn summarize(report: &Report) -> Option<String> {
    let s = &report.summary;
    let mut parts: Vec<String> = [
        (s.fixed, "fixed"),
        (s.planned, "planned"),
        (s.skipped, "skipped"),
        (s.failed, "failed"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if s.errors > 0 {
        parts.push(progress::count(s.errors, "project error", "project errors"));
    }
    match (s.findings, parts.is_empty()) {
        (0, true) => None,
        (0, false) => Some(parts.join(", ")),
        (n, _) => Some(format!(
            "{}: {}",
            progress::count(n, "finding", "findings"),
            parts.join(", ")
        )),
    }
}
