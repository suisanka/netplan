//! Interactive CLI shell using the same typed daemon requests as one-shot commands.

use clap::{CommandFactory, Parser};
use netplan::Client;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::output::OutputFormat;
use crate::{Commands, run_command};

#[derive(Debug, Parser)]
#[command(name = "netplan", disable_help_subcommand = true)]
struct InteractiveArgs {
    /// Print the complete machine-readable response as JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Commands,
}

pub(crate) async fn serve(
    client: Client,
    no_autostart: bool,
    default_output: OutputFormat,
) -> Result<(), String> {
    let mut input = BufReader::new(tokio::io::stdin()).lines();
    let mut output = tokio::io::stdout();
    output
        .write_all(b"PE Netplan interactive mode. Type 'help' or 'exit'.\n")
        .await
        .map_err(|error| error.to_string())?;
    loop {
        output
            .write_all(b"netplan> ")
            .await
            .map_err(|error| error.to_string())?;
        output.flush().await.map_err(|error| error.to_string())?;
        let Some(line) = input.next_line().await.map_err(|error| error.to_string())? else {
            break;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(line.to_ascii_lowercase().as_str(), "exit" | "quit") {
            break;
        }
        if line.eq_ignore_ascii_case("help") {
            let help = InteractiveArgs::command().render_long_help().to_string();
            output
                .write_all(help.as_bytes())
                .await
                .map_err(|error| error.to_string())?;
            output
                .write_all(b"\n")
                .await
                .map_err(|error| error.to_string())?;
            continue;
        }
        let words = match split_command_line(line) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("netplan: {error}");
                continue;
            }
        };
        let arguments = std::iter::once("netplan".to_owned()).chain(words);
        let parsed = match InteractiveArgs::try_parse_from(arguments) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprint!("{error}");
                continue;
            }
        };
        if matches!(parsed.command, Commands::Interactive | Commands::Rpc) {
            eprintln!("netplan: nested interactive and rpc modes are not supported");
            continue;
        }
        let output = if parsed.json {
            OutputFormat::Json
        } else {
            default_output
        };
        if let Err(error) = run_command(&client, parsed.command, no_autostart, output).await {
            eprintln!("{}", crate::output::render_error(&error, output));
        }
    }
    Ok(())
}

fn split_command_line(line: &str) -> Result<Vec<String>, String> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let line = line.strip_prefix('\u{feff}').unwrap_or(line);
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = Quote::None;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Quote::None, '\'') => quote = Quote::Single,
            (Quote::None, '"') => quote = Quote::Double,
            (Quote::Single, '\'') | (Quote::Double, '"') => quote = Quote::None,
            (Quote::None, character) if character.is_whitespace() => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            (Quote::Single, character) => word.push(character),
            (current, '\\') => match characters.peek().copied() {
                Some(next)
                    if next == '\\'
                        || (current == Quote::Double && next == '"')
                        || (current == Quote::None
                            && (next == '\'' || next == '"' || next.is_whitespace())) =>
                {
                    word.push(next);
                    characters.next();
                }
                _ => word.push('\\'),
            },
            (_, character) => word.push(character),
        }
    }
    if quote != Quote::None {
        return Err("unterminated quoted argument".into());
    }
    if !word.is_empty() {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_preserves_windows_paths_and_quoted_spaces() {
        assert_eq!(
            split_command_line(r#"validate "C:\Program Files\netplan\lab.yaml" --format yaml"#),
            Ok(vec![
                "validate".into(),
                r"C:\Program Files\netplan\lab.yaml".into(),
                "--format".into(),
                "yaml".into()
            ])
        );
        assert_eq!(
            split_command_line(r"validate C:\netplan\lab.yaml"),
            Ok(vec!["validate".into(), r"C:\netplan\lab.yaml".into()])
        );
    }

    #[test]
    fn tokenizer_rejects_unterminated_quotes() {
        assert_eq!(
            split_command_line("validate \"missing.yaml"),
            Err("unterminated quoted argument".into())
        );
    }

    #[test]
    fn tokenizer_accepts_a_powershell_utf8_bom_on_the_first_command() {
        assert_eq!(
            split_command_line("\u{feff}status"),
            Ok(vec!["status".into()])
        );
    }

    #[test]
    fn json_can_be_selected_for_one_interactive_command() {
        let parsed = InteractiveArgs::try_parse_from(["netplan", "status", "--json"]);
        assert!(matches!(
            parsed,
            Ok(InteractiveArgs {
                json: true,
                command: Commands::Status
            })
        ));
    }
}
