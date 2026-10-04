//! `kasumictl --profile <profile.json>` data commands: everyday reads and writes
//! from a shell, using the same query language and client as applications.
//!
//! Rows and groups print as one compact JSON object per line, so output pipes
//! into `jq`. JSON arguments are inline text, `@path` to read a file, or `-`
//! for standard input; numbers keep their exact decimal text.
use anyhow::{Context, Result, bail, ensure};
use kasumi_client::Kasumi;
use kasumi_types::{Filter, MutationBatch, Paging, Precondition, QueryRequest, Sort, TextSearch};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::io::{Read, Write};

pub const USAGE: &str = "\
kasumictl --profile <profile.json> <command>
  get <collection> <id>
  query <collection> [<filter>] [--sort <field>]... [--select <field>]... [--limit <n>]
        [--search <index> <text>] [--allow-scan] [--seek] [--all]
  query --json <query> [--all]
  put <collection> <id> <body> [--if absent|any|<version>] [--key <idempotency-key>]
  patch <collection> <id> <merge-patch> [--if any|<version>] [--key <idempotency-key>]
  delete <collection> <id> [--if any|<version>] [--key <idempotency-key>]
  mutate <batch>
  collections
JSON arguments are inline, @path to read a file, or - for standard input.
Sort fields are JSON Pointers; prefix with - to sort descending (e.g. -/amount).";

/// Reads larger than one request are refused before parsing.
const MAX_ARGUMENT_BYTES: u64 = crate::api::MAX_REQUEST_BYTES as u64;

#[derive(Debug, Clone, PartialEq)]
pub enum DataCommand {
    Get { collection: String, id: String },
    Query { query: Box<QueryRequest>, all: bool },
    Write(MutationBatch),
    Collections,
}

/// Parse everything after `--profile <path>`.
pub fn parse(arguments: &[String]) -> Result<DataCommand> {
    let Some((command, rest)) = arguments.split_first() else {
        bail!("missing command\n{USAGE}");
    };
    match command.as_str() {
        "get" => {
            let [collection, id] = rest else {
                bail!("get takes <collection> <id>");
            };
            Ok(DataCommand::Get {
                collection: collection.clone(),
                id: id.clone(),
            })
        }
        "query" => parse_query(rest),
        "put" | "patch" | "delete" => parse_write(command, rest),
        "mutate" => {
            let [batch] = rest else {
                bail!("mutate takes one <batch> JSON argument");
            };
            Ok(DataCommand::Write(
                json_argument(batch).context("invalid mutation batch")?,
            ))
        }
        "collections" => {
            ensure!(rest.is_empty(), "collections takes no arguments");
            Ok(DataCommand::Collections)
        }
        other => bail!("unknown data command `{other}`\n{USAGE}"),
    }
}

fn parse_query(rest: &[String]) -> Result<DataCommand> {
    if let [flag, rest @ ..] = rest
        && flag == "--json"
    {
        let Some((query, options)) = rest.split_first() else {
            bail!("query --json takes <query> [--all]");
        };
        ensure!(
            options.is_empty() || options == ["--all"],
            "query --json takes <query> [--all]"
        );
        let query: QueryRequest = json_argument(query).context("invalid query")?;
        return Ok(DataCommand::Query {
            query: Box::new(query),
            all: !options.is_empty(),
        });
    }
    let Some((collection, mut rest)) = rest.split_first() else {
        bail!("query takes <collection> or --json <query>");
    };
    ensure!(
        !collection.starts_with("--"),
        "query takes <collection> or --json <query>"
    );
    let mut query = QueryRequest::new(collection.clone());
    let mut all = false;
    if let Some((filter, tail)) = rest.split_first()
        && !filter.starts_with("--")
    {
        let filter: Filter = json_argument(filter).context("invalid filter")?;
        query = query.filter(filter);
        rest = tail;
    }
    while let Some((flag, tail)) = rest.split_first() {
        let mut value = |name: &str| -> Result<&String> {
            let (value, tail) = tail
                .split_first()
                .with_context(|| format!("{name} needs a value"))?;
            rest = tail;
            Ok(value)
        };
        match flag.as_str() {
            "--sort" => {
                let field = value("--sort")?;
                query.sort.push(
                    serde_json::from_value::<Sort>(Value::String(field.clone()))
                        .context("invalid sort key")?,
                );
            }
            "--select" => {
                let field = value("--select")?.clone();
                query.select.push(field);
            }
            "--limit" => {
                let limit = value("--limit")?;
                query.limit = Some(limit.parse().context("--limit needs a number")?);
            }
            "--search" => {
                let index = value("--search")?.clone();
                let text = {
                    let (text, tail) = rest
                        .split_first()
                        .context("--search needs <index> <text>")?;
                    rest = tail;
                    text.clone()
                };
                query.search = Some(TextSearch::new(index, text));
            }
            "--allow-scan" => {
                query.allow_scan = true;
                rest = tail;
            }
            "--seek" => {
                query.paging = Paging::Seek;
                rest = tail;
            }
            "--all" => {
                all = true;
                rest = tail;
            }
            other => bail!("unknown query option `{other}`"),
        }
    }
    Ok(DataCommand::Query {
        query: Box::new(query),
        all,
    })
}

fn parse_write(command: &str, rest: &[String]) -> Result<DataCommand> {
    let positional = if command == "delete" { 2 } else { 3 };
    ensure!(
        rest.len() >= positional,
        "{command} takes <collection> <id>{}",
        if command == "delete" { "" } else { " <json>" }
    );
    let (arguments, mut options) = rest.split_at(positional);
    let mut expected = Precondition::Any;
    let mut key = None;
    while let Some((flag, tail)) = options.split_first() {
        let (value, tail) = tail
            .split_first()
            .with_context(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--if" => {
                expected = match value.as_str() {
                    "any" => Precondition::Any,
                    "absent" if command == "put" => Precondition::Absent,
                    version => Precondition::Version(version.parse().with_context(|| {
                        format!(
                            "--if takes any, a version number{}",
                            if command == "put" { " or absent" } else { "" }
                        )
                    })?),
                }
            }
            "--key" => key = Some(value.clone()),
            other => bail!("unknown {command} option `{other}`"),
        }
        options = tail;
    }
    let (collection, id) = (arguments[0].clone(), arguments[1].clone());
    let mutation = match command {
        "put" => kasumi_types::Mutation::put(
            collection,
            id,
            json_argument::<Value>(&arguments[2])?,
            expected,
        ),
        "patch" => kasumi_types::Mutation::patch(
            collection,
            id,
            json_argument::<Value>(&arguments[2])?,
            expected,
        ),
        _ => kasumi_types::Mutation::delete(collection, id, expected),
    };
    let batch = match key {
        Some(key) => MutationBatch::with_key(key),
        None => MutationBatch::new(),
    };
    Ok(DataCommand::Write(batch.push(mutation)))
}

/// Inline JSON, `@path`, or `-` for standard input, parsed with exact numbers.
fn json_argument<T: DeserializeOwned>(argument: &str) -> Result<T> {
    let text = if argument == "-" {
        let mut text = String::new();
        std::io::stdin()
            .take(MAX_ARGUMENT_BYTES + 1)
            .read_to_string(&mut text)?;
        text
    } else if let Some(path) = argument.strip_prefix('@') {
        let file = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
        let mut text = String::new();
        file.take(MAX_ARGUMENT_BYTES + 1)
            .read_to_string(&mut text)?;
        text
    } else {
        argument.to_owned()
    };
    ensure!(
        text.len() as u64 <= MAX_ARGUMENT_BYTES,
        "JSON argument exceeds the request limit"
    );
    serde_json::from_str(&text).context("invalid JSON argument")
}

/// Run one command, printing results to `out`. A missing document is an error,
/// so scripts can test the exit status.
pub async fn execute(command: DataCommand, db: &Kasumi, out: &mut impl Write) -> Result<()> {
    match command {
        DataCommand::Get { collection, id } => {
            let document = db
                .get(&collection, &id)
                .await?
                .with_context(|| format!("document {collection}/{id} not found"))?;
            writeln!(out, "{}", serde_json::to_string(&document)?)?;
        }
        DataCommand::Query { query, all } => {
            let mut page = db.query(&query).await?;
            loop {
                for row in page.rows() {
                    writeln!(out, "{}", serde_json::to_string(row)?)?;
                }
                for group in page.aggregates() {
                    writeln!(out, "{}", serde_json::to_string(group)?)?;
                }
                if !page.has_more() {
                    break;
                }
                if !all {
                    eprintln!("more rows are available; pass --all to read every page");
                    break;
                }
                page = db
                    .next_page(&page)
                    .await?
                    .context("query cursor ended early")?;
            }
        }
        DataCommand::Write(batch) => {
            let receipt = db.mutate(&batch).await.with_context(|| {
                format!(
                    "mutation with idempotency key `{}` failed; if its outcome is uncertain, retry the identical batch with this key",
                    batch.idempotency_key
                )
            })?;
            writeln!(out, "{}", serde_json::to_string(&receipt)?)?;
        }
        DataCommand::Collections => {
            let definitions = db.collections().await?;
            for definition in definitions {
                writeln!(out, "{}", serde_json::to_string(&definition)?)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn query_flags_build_the_same_request_as_the_builder() {
        let DataCommand::Query { query, all } = parse(&[
            "query".into(),
            "invoices".into(),
            r#"{"/status":"open","/amount":{"gte":10}}"#.into(),
            "--sort".into(),
            "-/amount".into(),
            "--select".into(),
            "/amount".into(),
            "--limit".into(),
            "20".into(),
            "--search".into(),
            "body".into(),
            "tokyo tower".into(),
            "--allow-scan".into(),
            "--all".into(),
        ])
        .unwrap() else {
            panic!("query command")
        };
        assert!(all);
        assert_eq!(
            *query,
            QueryRequest::new("invoices")
                .filter(Filter::new().eq("/status", "open").gte("/amount", 10))
                .sort_desc("/amount")
                .select(["/amount"])
                .limit(20)
                .search(TextSearch::new("body", "tokyo tower"))
                .allow_scan()
        );
        let DataCommand::Query { query, .. } = parse(&args(
            r#"query events {"/tenant":"acme"} --sort /at --seek"#,
        ))
        .unwrap() else {
            panic!("query command")
        };
        assert_eq!(query.paging, Paging::Seek);
        let DataCommand::Query { query, all } =
            parse(&args(r#"query --json {"collection":"docs","limit":5}"#)).unwrap()
        else {
            panic!("query command")
        };
        assert_eq!((*query, all), (QueryRequest::new("docs").limit(5), false));
        let DataCommand::Query { query, all } = parse(&args(
            r#"query --json {"collection":"docs","limit":5} --all"#,
        ))
        .unwrap() else {
            panic!("query command")
        };
        assert_eq!((*query, all), (QueryRequest::new("docs").limit(5), true));
    }

    #[test]
    fn writes_carry_preconditions_keys_and_exact_numbers() {
        let DataCommand::Write(batch) = parse(&args(
            r#"put docs a {"amount":9007199254740993.123456789} --if absent --key order-7"#,
        ))
        .unwrap() else {
            panic!("write command")
        };
        assert_eq!(batch.idempotency_key, "order-7");
        assert_eq!(
            serde_json::to_string(&batch.operations).unwrap(),
            r#"[{"op":"put","collection":"docs","id":"a","body":{"amount":9007199254740993.123456789},"expected":"absent"}]"#
        );
        let DataCommand::Write(batch) =
            parse(&args(r#"patch docs a {"note":null} --if 4"#)).unwrap()
        else {
            panic!("write command")
        };
        assert_eq!(
            batch.operations,
            [kasumi_types::Mutation::patch(
                "docs",
                "a",
                json!({"note": null}),
                Precondition::Version(4)
            )]
        );
        let DataCommand::Write(batch) = parse(&args("delete docs a")).unwrap() else {
            panic!("write command")
        };
        assert_eq!(
            batch.operations,
            [kasumi_types::Mutation::delete(
                "docs",
                "a",
                Precondition::Any
            )]
        );
    }

    #[test]
    fn mistakes_are_reported_before_connecting() {
        for (command, message) in [
            ("", "missing command"),
            ("fetch docs a", "unknown data command"),
            ("get docs", "get takes"),
            ("query docs --sort amount", "invalid sort key"),
            ("query docs {\"status\":\"open\"}", "invalid filter"),
            ("query docs --limit many", "--limit needs a number"),
            ("query docs --frobnicate", "unknown query option"),
            ("query --json", "query --json takes"),
            ("query --json {} --sort /n", "query --json takes"),
            ("query --all", "query takes"),
            (r#"query docs {"/n":1,"/n":2}"#, "duplicate filter field"),
            (
                r#"query --json {"collection":"docs","collection":"other"}"#,
                "duplicate field",
            ),
            (
                r#"query --json {"collection":"docs","aggregate":{"n":{"count":"*"},"n":{"sum":"/n"}}}"#,
                "duplicate aggregate",
            ),
            (
                r#"mutate {"idempotency_key":"a","idempotency_key":"b","operations":[]}"#,
                "duplicate field",
            ),
            ("put docs a", "put takes"),
            ("put docs a {} --if later", "--if takes"),
            ("patch docs a {} --if absent", "--if takes"),
            ("put docs a {broken", "invalid JSON argument"),
            ("collections extra", "takes no arguments"),
        ] {
            let arguments = if command.is_empty() {
                vec![]
            } else {
                args(command)
            };
            let error = format!("{:#}", parse(&arguments).unwrap_err());
            assert!(error.contains(message), "{command}: {error}");
        }
    }
}
