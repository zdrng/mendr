//! mendr: find known vulnerabilities in project dependencies and fix them the
//! way a developer would. See PLAN.md for the design.

mod cache;
mod config;
mod ecosystem;
mod http;
mod model;
mod osv;
mod plan;
mod report;
mod rules;
mod safety;
mod verify;

use std::path::PathBuf;
use std::process::ExitCode;

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

    /// Only plan fixes; do not build or test anything.
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

    /// Allow major version bumps.
    #[arg(long)]
    allow_major: bool,

    /// Run builds even when secrets are reachable from this environment.
    #[arg(long)]
    allow_unsandboxed: bool,

    /// Minimum age of any version mendr picks, e.g. "7d", "12h", "0".
    #[arg(long, value_name = "DUR")]
    min_release_age: Option<String>,

    /// Copy verified manifest/lockfile changes back into the project.
    #[arg(long, conflicts_with = "plan_only")]
    write: bool,
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
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: &Cli) -> Result<u8> {
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
    let mode = if cli.plan_only {
        Mode::Plan
    } else {
        Mode::Full
    };

    let mut projects = Vec::new();
    for project in &config.projects {
        let mut pr = ProjectReport::new(&project.path, &config.base_dir);
        if let Err(e) = run_project(cli, &config, project, &mut osv, now, &mut pr) {
            eprintln!("error: project {}: {e:#}", pr.path);
            pr.error = Some(format!("{e:#}"));
        }
        projects.push(pr);
    }

    let report = Report::new(mode, projects);
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
            let known = ecosystem::names();
            anyhow!(
                "no supported project found in {} (supported: {})",
                project.path.display(),
                if known.is_empty() {
                    "none yet".to_string()
                } else {
                    known.join(", ")
                }
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
    report: &mut ProjectReport,
) -> Result<()> {
    if !project.path.is_dir() {
        anyhow::bail!("{} is not a directory", project.path.display());
    }
    let eco = ecosystem_for(project)?;
    report.ecosystem = Some(eco.name().to_string());
    eprintln!("mendr: {} ({})", project.path.display(), eco.name());

    let graph = eco
        .resolve_graph(&project.path)
        .context("resolving dependency graph")?;
    let advisories = osv
        .advisories(eco.as_ref(), &osv::package_names(&graph))
        .context("looking up advisories")?;
    let mut project_plan = plan::plan(&plan::PlanInput {
        eco: eco.as_ref(),
        graph: &graph,
        advisories: &advisories,
        policy: &config.policy,
        ignores: &config.ignores,
        now,
    });

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
                eprintln!("mendr: updated {}", file.display());
            }
        }
    }

    report.findings = project_plan.findings;
    report.changes = project_plan.changes;
    Ok(())
}
