//! Command-line option parsing.

use std::fmt;
use std::net::IpAddr;

use clap::builder::{Styles, styling};
use clap::{ArgAction, CommandFactory, Parser, ValueEnum};
use clap_complete::{Generator, Shell};
use log::*;

use dns::record::RecordType;
use dns::{Labels, QClass};

use crate::connect::TransportType;
use crate::output::{OutputFormat, TextFormat, UseColours};
use crate::requests::{Inputs, ProtocolTweaks, RequestGenerator, UseEDNS};
use crate::resolve::ResolverType;
use crate::txid::TxidGenerator;

const STYLES: Styles = Styles::styled()
    .header(styling::AnsiColor::Yellow.on_default().underline())
    .usage(styling::AnsiColor::Yellow.on_default().underline())
    .literal(styling::AnsiColor::Green.on_default())
    .placeholder(styling::AnsiColor::Cyan.on_default());

const TEMPLATE: &str = "\x1b[1mdog\x1b[0m \x1b[1;32m●\x1b[0m command-line DNS client

{usage-heading} {usage}

\x1b[4;33mExamples:\x1b[0m
  \x1b[32mdog\x1b[0m \x1b[36mexample.net\x1b[0m                          Query a domain using default settings
  \x1b[32mdog\x1b[0m \x1b[36mexample.net MX\x1b[0m                       ...looking up MX records instead
  \x1b[32mdog\x1b[0m \x1b[36mexample.net MX @1.1.1.1\x1b[0m              ...using a specific nameserver instead
  \x1b[32mdog\x1b[0m \x1b[36mexample.net MX @1.1.1.1\x1b[0m \x1b[32m-T\x1b[0m          ...using TCP rather than UDP
  \x1b[32mdog\x1b[0m \x1b[32m-q\x1b[0m \x1b[36mexample.net\x1b[0m \x1b[32m-t\x1b[0m \x1b[36mMX\x1b[0m \x1b[32m-n\x1b[0m \x1b[36m1.1.1.1\x1b[0m \x1b[32m-T\x1b[0m   As above, but using explicit arguments
  \x1b[32mdog\x1b[0m \x1b[32m-x\x1b[0m \x1b[36m8.8.8.8\x1b[0m                           Reverse lookup for an IP address

{all-args}";

/// A command-line DNS client.
#[derive(Parser, Debug)]
#[command(name = "dog", version, about, styles = STYLES, help_template = TEMPLATE)]
#[allow(clippy::struct_excessive_bools)]
pub struct Args {
    /// Host names or domain names to query, nameservers (@), types, or classes
    #[arg(value_name = "ARGUMENTS")]
    pub arguments: Vec<String>,

    // === Query options ===
    /// Host name or domain name to query
    #[arg(
        short = 'q',
        long = "query",
        value_name = "HOST",
        help_heading = "Query options"
    )]
    pub queries: Vec<String>,

    /// Type of the DNS record being queried (A, MX, NS...)
    #[arg(
        short = 't',
        long = "type",
        value_name = "TYPE",
        help_heading = "Query options"
    )]
    pub types: Vec<String>,

    /// Address of the nameserver to send packets to
    #[arg(
        short = 'n',
        long = "nameserver",
        value_name = "ADDR",
        help_heading = "Query options"
    )]
    pub nameservers: Vec<String>,

    /// Network class of the DNS record being queried (IN, CH, HS)
    #[arg(long = "class", value_name = "CLASS", value_parser = parse_class, help_heading = "Query options")]
    pub classes: Vec<QClass>,

    /// Perform a reverse DNS lookup for an IP address
    #[arg(
        short = 'x',
        long = "reverse",
        value_name = "ADDR",
        help_heading = "Query options"
    )]
    pub reverse: Vec<String>,

    // === Sending options ===
    /// Whether to OPT in to EDNS (disable, hide, show)
    #[arg(
        long = "edns",
        value_name = "SETTING",
        value_enum,
        help_heading = "Sending options",
        hide_possible_values = true
    )]
    pub edns: Option<EdnsSetting>,

    /// Set the transaction ID to a specific value
    #[arg(long = "txid", value_name = "NUMBER", value_parser = parse_txid, help_heading = "Sending options")]
    pub txid: Option<u16>,

    /// Set uncommon protocol-level tweaks
    #[arg(short = 'Z', value_name = "TWEAKS", action = ArgAction::Append, help_heading = "Sending options")]
    pub tweaks: Vec<String>,

    // === Protocol options ===
    /// Use the DNS protocol over UDP
    #[arg(short = 'U', long = "udp", help_heading = "Protocol options")]
    pub udp: bool,

    /// Use the DNS protocol over TCP
    #[arg(short = 'T', long = "tcp", help_heading = "Protocol options")]
    pub tcp: bool,

    /// Use the DNS-over-TLS protocol
    #[arg(short = 'S', long = "tls", help_heading = "Protocol options")]
    pub tls: bool,

    /// Use the DNS-over-HTTPS protocol
    #[arg(short = 'H', long = "https", help_heading = "Protocol options")]
    pub https: bool,

    // === Output options ===
    /// Short mode: display nothing but the first result
    #[arg(short = '1', long = "short", help_heading = "Output options")]
    pub short: bool,

    /// Display the output as JSON
    #[arg(short = 'J', long = "json", help_heading = "Output options")]
    pub json: bool,

    /// When to colorise the output (always, automatic, never)
    #[arg(
        long = "color",
        visible_alias = "colour",
        value_name = "WHEN",
        value_enum,
        help_heading = "Output options",
        hide_possible_values = true
    )]
    pub color: Option<ColorSetting>,

    /// Do not format durations, display them as seconds
    #[arg(long = "seconds", help_heading = "Output options")]
    pub seconds: bool,

    /// Print how long the response took to arrive
    #[arg(long = "time", help_heading = "Output options")]
    pub time: bool,

    // === Completion generation ===
    /// Generate shell completions
    #[arg(long = "completions", value_name = "SHELL", value_enum, hide = true)]
    pub completions: Option<Shell>,
}

/// EDNS setting values
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EdnsSetting {
    /// Do not send an OPT query
    Disable,
    /// Send an OPT query, but hide the result
    Hide,
    /// Send an OPT query and show the result
    Show,
}

/// Color setting values
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ColorSetting {
    /// Always use colors
    Always,
    /// Use colors when printing to a terminal
    #[default]
    Automatic,
    /// Never use colors
    Never,
}

/// The command-line options used when running dog.
#[derive(PartialEq, Debug)]
pub struct Options {
    /// The requests to make and how they should be generated.
    pub requests: RequestGenerator,

    /// Whether to display the time taken after every query.
    pub measure_time: bool,

    /// How to format the output data.
    pub format: OutputFormat,
}

impl Options {
    /// Parses and interprets a set of options from the user's command-line arguments.
    pub fn parse() -> OptionsResult {
        let args = match Args::try_parse() {
            Ok(args) => args,
            Err(e) => {
                // Let clap print the error/help/version message
                e.exit();
            }
        };

        // Handle completion generation
        if let Some(shell) = args.completions {
            print_completions(shell);
            return OptionsResult::Exit(0);
        }

        Self::from_args(args)
    }

    /// Convert parsed Args into Options
    fn from_args(args: Args) -> OptionsResult {
        let use_colours = match args.color {
            Some(ColorSetting::Always) => UseColours::Always,
            Some(ColorSetting::Never) => UseColours::Never,
            Some(ColorSetting::Automatic) | None => UseColours::Automatic,
        };

        match Self::deduce(args) {
            Ok(opts) => {
                if opts.requests.inputs.domains.is_empty() {
                    OptionsResult::Help(use_colours)
                } else {
                    OptionsResult::Ok(opts)
                }
            }
            Err(e) => OptionsResult::InvalidOptions(e),
        }
    }

    fn deduce(args: Args) -> Result<Self, OptionsError> {
        let measure_time = args.time;
        let format = OutputFormat::deduce(&args);
        let requests = RequestGenerator::deduce(args)?;

        Ok(Self {
            requests,
            measure_time,
            format,
        })
    }
}

impl RequestGenerator {
    fn deduce(args: Args) -> Result<Self, OptionsError> {
        let edns = UseEDNS::deduce(&args);
        let txid_generator = TxidGenerator::deduce(&args);
        let protocol_tweaks = ProtocolTweaks::deduce(&args)?;
        let inputs = Inputs::deduce(args)?;

        Ok(Self {
            inputs,
            txid_generator,
            edns,
            protocol_tweaks,
        })
    }
}

impl Inputs {
    fn deduce(args: Args) -> Result<Self, OptionsError> {
        let mut inputs = Self::default();

        // Load transport types
        if args.https {
            inputs.transport_types.push(TransportType::HTTPS);
        }
        if args.tls {
            inputs.transport_types.push(TransportType::TLS);
        }
        if args.tcp {
            inputs.transport_types.push(TransportType::TCP);
        }
        if args.udp {
            inputs.transport_types.push(TransportType::UDP);
        }

        // Load named arguments
        for domain in &args.queries {
            inputs.add_domain(domain)?;
        }

        for record_name in &args.types {
            if record_name.eq_ignore_ascii_case("OPT") {
                return Err(OptionsError::QueryTypeOPT);
            } else if let Some(record_type) = RecordType::from_type_name(record_name) {
                inputs.add_type(record_type);
            } else if let Ok(type_number) = record_name.parse::<u16>() {
                inputs.record_types.push(RecordType::from(type_number));
            } else {
                return Err(OptionsError::InvalidQueryType(record_name.clone()));
            }
        }

        for ns in &args.nameservers {
            inputs.add_nameserver(ns);
        }

        inputs.classes.extend(args.classes);

        // Handle reverse lookups (-x)
        for ip in &args.reverse {
            let ptr_name =
                ip_to_reverse_name(ip).ok_or(OptionsError::InvalidIPAddress(ip.clone()))?;
            inputs.add_domain(&ptr_name)?;
            inputs.add_type(RecordType::PTR);
        }

        // Load free arguments
        for argument in args.arguments {
            if let Some(nameserver) = argument.strip_prefix('@') {
                trace!("Got nameserver -> {nameserver:?}");
                inputs.add_nameserver(nameserver);
            } else if is_constant_name(&argument) {
                if argument.eq_ignore_ascii_case("OPT") {
                    return Err(OptionsError::QueryTypeOPT);
                } else if let Some(class) = parse_class_name(&argument) {
                    trace!("Got qclass -> {:?}", &argument);
                    inputs.add_class(class);
                } else if let Some(record_type) = RecordType::from_type_name(&argument) {
                    trace!("Got qtype -> {:?}", &argument);
                    inputs.add_type(record_type);
                } else {
                    trace!("Got single-word domain -> {:?}", &argument);
                    inputs.add_domain(&argument)?;
                }
            } else {
                trace!("Got domain -> {:?}", &argument);
                inputs.add_domain(&argument)?;
            }
        }

        // Check for missing nameserver
        if inputs.resolver_types.is_empty() && inputs.transport_types == [TransportType::HTTPS] {
            return Err(OptionsError::MissingHttpsUrl);
        }

        // Load fallbacks
        if inputs.record_types.is_empty() {
            inputs.record_types.push(RecordType::A);
        }
        if inputs.classes.is_empty() {
            inputs.classes.push(QClass::IN);
        }
        if inputs.resolver_types.is_empty() {
            inputs.resolver_types.push(ResolverType::SystemDefault);
        }
        if inputs.transport_types.is_empty() {
            inputs.transport_types.push(TransportType::Automatic);
        }

        Ok(inputs)
    }

    fn add_domain(&mut self, input: &str) -> Result<(), OptionsError> {
        if let Ok(domain) = Labels::encode(input) {
            self.domains.push(domain);
            Ok(())
        } else {
            Err(OptionsError::InvalidDomain(input.into()))
        }
    }

    fn add_type(&mut self, rt: RecordType) {
        self.record_types.push(rt);
    }

    fn add_nameserver(&mut self, input: &str) {
        self.resolver_types
            .push(ResolverType::Specific(input.into()));
    }

    fn add_class(&mut self, class: QClass) {
        self.classes.push(class);
    }
}

fn is_constant_name(argument: &str) -> bool {
    let Some(first_char) = argument.chars().next() else {
        return false;
    };

    if !first_char.is_ascii_alphabetic() {
        return false;
    }

    argument.chars().all(|c| c.is_ascii_alphanumeric())
}

fn parse_class_name(input: &str) -> Option<QClass> {
    if input.eq_ignore_ascii_case("IN") {
        Some(QClass::IN)
    } else if input.eq_ignore_ascii_case("CH") {
        Some(QClass::CH)
    } else if input.eq_ignore_ascii_case("HS") {
        Some(QClass::HS)
    } else {
        None
    }
}

/// Clap value parser for `QClass`
fn parse_class(s: &str) -> Result<QClass, String> {
    if let Some(class) = parse_class_name(s) {
        Ok(class)
    } else if let Ok(num) = s.parse::<u16>() {
        Ok(QClass::Other(num))
    } else {
        Err(format!("Invalid class: {s}"))
    }
}

/// Clap value parser for transaction ID (decimal or hex)
fn parse_txid(s: &str) -> Result<u16, String> {
    if let Some(hex_str) = s.strip_prefix("0x") {
        u16::from_str_radix(hex_str, 16).map_err(|e| format!("Invalid hex txid: {e}"))
    } else {
        s.parse().map_err(|e| format!("Invalid txid: {e}"))
    }
}

/// Converts an IP address to its reverse DNS name (PTR format).
///
/// - IPv4: `8.8.8.8` → `8.8.8.8.in-addr.arpa`
/// - IPv6: `2001:4860:4860::8888` → `8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa`
fn ip_to_reverse_name(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;

    match addr {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Some(format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            ))
        }
        IpAddr::V6(ipv6) => {
            let mut nibbles = String::with_capacity(72);
            for byte in ipv6.octets().iter().rev() {
                use std::fmt::Write;
                let _ = write!(nibbles, "{:x}.{:x}.", byte & 0xf, byte >> 4);
            }
            nibbles.push_str("ip6.arpa");
            Some(nibbles)
        }
    }
}

impl TxidGenerator {
    fn deduce(args: &Args) -> Self {
        if let Some(txid) = args.txid {
            Self::Sequence(txid)
        } else {
            Self::Random
        }
    }
}

impl OutputFormat {
    fn deduce(args: &Args) -> Self {
        let text_format = TextFormat {
            format_durations: !args.seconds,
        };

        if args.short {
            Self::Short(text_format)
        } else if args.json {
            Self::JSON
        } else {
            let use_colours = match args.color {
                Some(ColorSetting::Always) => UseColours::Always,
                Some(ColorSetting::Never) => UseColours::Never,
                Some(ColorSetting::Automatic) | None => UseColours::Automatic,
            };
            Self::Text(use_colours, text_format)
        }
    }
}

impl UseEDNS {
    fn deduce(args: &Args) -> Self {
        match args.edns {
            Some(EdnsSetting::Disable) => Self::Disable,
            Some(EdnsSetting::Show) => Self::SendAndShow,
            Some(EdnsSetting::Hide) | None => Self::SendAndHide,
        }
    }
}

impl ProtocolTweaks {
    fn deduce(args: &Args) -> Result<Self, OptionsError> {
        let mut tweaks = Self::default();

        for tweak_str in &args.tweaks {
            match tweak_str.as_str() {
                "aa" | "authoritative" => {
                    tweaks.set_authoritative_flag = true;
                }
                "ad" | "authentic" => {
                    tweaks.set_authentic_flag = true;
                }
                "cd" | "checking-disabled" => {
                    tweaks.set_checking_disabled_flag = true;
                }
                otherwise => {
                    if let Some(remaining_num) = tweak_str.strip_prefix("bufsize=") {
                        match remaining_num.parse() {
                            Ok(parsed_bufsize) => {
                                tweaks.udp_payload_size = Some(parsed_bufsize);
                                continue;
                            }
                            Err(e) => {
                                warn!("Failed to parse buffer size: {e}");
                            }
                        }
                    }
                    return Err(OptionsError::InvalidTweak(otherwise.into()));
                }
            }
        }

        Ok(tweaks)
    }
}

/// Print shell completions to stdout
fn print_completions<G: Generator>(generator: G) {
    let mut cmd = Args::command();
    clap_complete::generate(generator, &mut cmd, "dog", &mut std::io::stdout());
}

/// The result of option parsing.
#[derive(Debug)]
pub enum OptionsResult {
    /// The options were parsed successfully.
    Ok(Options),

    /// There was an error with the combination of options the user selected.
    InvalidOptions(OptionsError),

    /// No domains were provided, show help message.
    Help(UseColours),

    /// Exit immediately with the given code (for --completions)
    Exit(i32),
}

/// Something wrong with the combination of options the user has picked.
#[derive(PartialEq, Debug)]
pub enum OptionsError {
    InvalidDomain(String),
    InvalidIPAddress(String),
    InvalidQueryType(String),
    InvalidTweak(String),
    QueryTypeOPT,
    MissingHttpsUrl,
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain(domain) => write!(f, "Invalid domain {domain:?}"),
            Self::InvalidIPAddress(ip) => write!(f, "Invalid IP address {ip:?}"),
            Self::InvalidQueryType(qt) => write!(f, "Invalid query type {qt:?}"),
            Self::InvalidTweak(tweak) => write!(f, "Invalid protocol tweak {tweak:?}"),
            Self::QueryTypeOPT => write!(f, "OPT request is sent by default (see -Z flag)"),
            Self::MissingHttpsUrl => {
                write!(f, "You must pass a URL as a nameserver when using --https")
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::connect::TransportType;
    use pretty_assertions::assert_eq;

    /// Helper to parse args and get Options
    fn parse_options(args: &[&str]) -> Result<Options, OptionsError> {
        let mut full_args = vec!["dog"];
        full_args.extend(args);
        let parsed = Args::try_parse_from(full_args).expect("clap parsing failed");
        Options::from_args(parsed).into_result()
    }

    impl OptionsResult {
        fn into_result(self) -> Result<Options, OptionsError> {
            match self {
                Self::Ok(opts) => Ok(opts),
                Self::InvalidOptions(e) => Err(e),
                Self::Help(_) => panic!("Got Help"),
                Self::Exit(_) => panic!("Got Exit"),
            }
        }
    }

    impl Inputs {
        fn fallbacks() -> Self {
            Self {
                domains: vec![],
                record_types: vec![RecordType::A],
                classes: vec![QClass::IN],
                resolver_types: vec![ResolverType::SystemDefault],
                transport_types: vec![TransportType::Automatic],
            }
        }
    }

    // === Basic parsing tests ===

    #[test]
    fn just_a_domain() {
        let options = parse_options(&["dom.ain"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec![Labels::encode("dom.ain").unwrap()],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn domain_and_type() {
        let options = parse_options(&["dom.ain", "MX"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec![Labels::encode("dom.ain").unwrap()],
                record_types: vec![RecordType::MX],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn domain_and_nameserver() {
        let options = parse_options(&["@1.1.1.1", "dom.ain"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec![Labels::encode("dom.ain").unwrap()],
                resolver_types: vec![ResolverType::Specific("1.1.1.1".into())],
                ..Inputs::fallbacks()
            }
        );
    }

    #[test]
    fn domain_and_class() {
        let options = parse_options(&["CH", "dom.ain"]).unwrap();
        assert_eq!(
            options.requests.inputs,
            Inputs {
                domains: vec![Labels::encode("dom.ain").unwrap()],
                classes: vec![QClass::CH],
                ..Inputs::fallbacks()
            }
        );
    }

    // === Explicit argument tests ===

    #[test]
    fn explicit_query() {
        let options = parse_options(&["-q", "dom.ain"]).unwrap();
        assert_eq!(
            options.requests.inputs.domains,
            vec![Labels::encode("dom.ain").unwrap()]
        );
    }

    #[test]
    fn explicit_type() {
        let options = parse_options(&["-t", "MX", "dom.ain"]).unwrap();
        assert_eq!(options.requests.inputs.record_types, vec![RecordType::MX]);
    }

    #[test]
    fn explicit_nameserver() {
        let options = parse_options(&["-n", "1.1.1.1", "dom.ain"]).unwrap();
        assert_eq!(
            options.requests.inputs.resolver_types,
            vec![ResolverType::Specific("1.1.1.1".into())]
        );
    }

    #[test]
    fn explicit_class() {
        let options = parse_options(&["--class", "HS", "dom.ain"]).unwrap();
        assert_eq!(options.requests.inputs.classes, vec![QClass::HS]);
    }

    #[test]
    fn numeric_type() {
        let options = parse_options(&["dom.ain", "-t", "33"]).unwrap();
        assert_eq!(
            options.requests.inputs.record_types,
            vec![RecordType::from(33)]
        );
    }

    #[test]
    fn numeric_class() {
        let options = parse_options(&["dom.ain", "--class", "4"]).unwrap();
        assert_eq!(options.requests.inputs.classes, vec![QClass::Other(4)]);
    }

    // === Transport tests ===

    #[test]
    fn udp_transport() {
        let options = parse_options(&["dom.ain", "--udp"]).unwrap();
        assert_eq!(
            options.requests.inputs.transport_types,
            vec![TransportType::UDP]
        );
    }

    #[test]
    fn tcp_transport() {
        let options = parse_options(&["dom.ain", "--tcp"]).unwrap();
        assert_eq!(
            options.requests.inputs.transport_types,
            vec![TransportType::TCP]
        );
    }

    #[test]
    fn all_transports() {
        let options = parse_options(&["dom.ain", "-H", "-S", "-T", "-U"]).unwrap();
        assert_eq!(
            options.requests.inputs.transport_types,
            vec![
                TransportType::HTTPS,
                TransportType::TLS,
                TransportType::TCP,
                TransportType::UDP
            ]
        );
    }

    // === Reverse DNS tests ===

    #[test]
    fn reverse_flag_ipv4() {
        let options = parse_options(&["-x", "8.8.8.8"]).unwrap();
        assert_eq!(
            options.requests.inputs.domains,
            vec![Labels::encode("8.8.8.8.in-addr.arpa").unwrap()]
        );
        assert_eq!(options.requests.inputs.record_types, vec![RecordType::PTR]);
    }

    #[test]
    fn reverse_flag_ipv6() {
        let options = parse_options(&["-x", "2001:4860:4860::8888"]).unwrap();
        assert_eq!(
            options.requests.inputs.domains,
            vec![
                Labels::encode(
                    "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa"
                )
                .unwrap()
            ]
        );
    }

    // === EDNS and tweaks tests ===

    #[test]
    fn edns_show() {
        let options = parse_options(&["dom.ain", "--edns", "show"]).unwrap();
        assert_eq!(options.requests.edns, UseEDNS::SendAndShow);
    }

    #[test]
    fn edns_disable() {
        let options = parse_options(&["dom.ain", "--edns", "disable"]).unwrap();
        assert_eq!(options.requests.edns, UseEDNS::Disable);
    }

    #[test]
    fn tweak_authentic() {
        let options = parse_options(&["dom.ain", "-Z", "ad"]).unwrap();
        assert!(options.requests.protocol_tweaks.set_authentic_flag);
    }

    #[test]
    fn tweak_authoritative() {
        let options = parse_options(&["dom.ain", "-Z", "aa"]).unwrap();
        assert!(options.requests.protocol_tweaks.set_authoritative_flag);
    }

    #[test]
    fn tweak_checking_disabled() {
        let options = parse_options(&["dom.ain", "-Z", "cd"]).unwrap();
        assert!(options.requests.protocol_tweaks.set_checking_disabled_flag);
    }

    #[test]
    fn tweak_bufsize() {
        let options = parse_options(&["dom.ain", "-Z", "bufsize=4096"]).unwrap();
        assert_eq!(
            options.requests.protocol_tweaks.udp_payload_size,
            Some(4096)
        );
    }

    #[test]
    fn multiple_tweaks() {
        let options = parse_options(&["dom.ain", "-Z", "aa", "-Z", "cd"]).unwrap();
        assert!(options.requests.protocol_tweaks.set_authoritative_flag);
        assert!(options.requests.protocol_tweaks.set_checking_disabled_flag);
    }

    // === Output format tests ===

    #[test]
    fn short_mode() {
        let options = parse_options(&["dom.ain", "--short"]).unwrap();
        assert!(matches!(options.format, OutputFormat::Short(_)));
    }

    #[test]
    fn json_output() {
        let options = parse_options(&["dom.ain", "--json"]).unwrap();
        assert_eq!(options.format, OutputFormat::JSON);
    }

    #[test]
    fn measure_time() {
        let options = parse_options(&["dom.ain", "--time"]).unwrap();
        assert!(options.measure_time);
    }

    #[test]
    fn format_seconds() {
        let options = parse_options(&["dom.ain", "--short", "--seconds"]).unwrap();
        if let OutputFormat::Short(tf) = options.format {
            assert!(!tf.format_durations);
        } else {
            panic!("Expected Short format");
        }
    }

    // === TXID tests ===

    #[test]
    fn specific_txid() {
        let options = parse_options(&["dom.ain", "--txid", "1234"]).unwrap();
        assert_eq!(
            options.requests.txid_generator,
            TxidGenerator::Sequence(1234)
        );
    }

    #[test]
    fn specific_txid_hex() {
        let options = parse_options(&["dom.ain", "--txid", "0xABCD"]).unwrap();
        assert_eq!(
            options.requests.txid_generator,
            TxidGenerator::Sequence(0xABCD)
        );
    }

    // === Error tests (not handled by clap) ===

    #[test]
    fn invalid_query_type() {
        let result = parse_options(&["dom.ain", "-t", "INVALID"]);
        assert_eq!(
            result,
            Err(OptionsError::InvalidQueryType("INVALID".into()))
        );
    }

    #[test]
    fn invalid_query_type_too_big() {
        let result = parse_options(&["dom.ain", "-t", "999999"]);
        assert_eq!(result, Err(OptionsError::InvalidQueryType("999999".into())));
    }

    #[test]
    fn invalid_tweak() {
        let result = parse_options(&["dom.ain", "-Z", "invalid"]);
        assert_eq!(result, Err(OptionsError::InvalidTweak("invalid".into())));
    }

    #[test]
    fn invalid_bufsize() {
        let result = parse_options(&["dom.ain", "-Z", "bufsize=notanumber"]);
        assert_eq!(
            result,
            Err(OptionsError::InvalidTweak("bufsize=notanumber".into()))
        );
    }

    #[test]
    fn invalid_bufsize_too_big() {
        let result = parse_options(&["dom.ain", "-Z", "bufsize=999999999"]);
        assert_eq!(
            result,
            Err(OptionsError::InvalidTweak("bufsize=999999999".into()))
        );
    }

    #[test]
    fn missing_https_url() {
        let result = parse_options(&["--https", "dom.ain"]);
        assert_eq!(result, Err(OptionsError::MissingHttpsUrl));
    }

    #[test]
    fn opt_query_type() {
        let result = parse_options(&["OPT", "dom.ain"]);
        assert_eq!(result, Err(OptionsError::QueryTypeOPT));
    }

    #[test]
    fn opt_query_type_lowercase() {
        let result = parse_options(&["opt", "dom.ain"]);
        assert_eq!(result, Err(OptionsError::QueryTypeOPT));
    }

    #[test]
    fn opt_explicit_type() {
        let result = parse_options(&["-t", "OPT", "dom.ain"]);
        assert_eq!(result, Err(OptionsError::QueryTypeOPT));
    }

    #[test]
    fn reverse_invalid_ip() {
        let result = parse_options(&["-x", "not-an-ip"]);
        assert_eq!(
            result,
            Err(OptionsError::InvalidIPAddress("not-an-ip".into()))
        );
    }

    // === Helper function tests ===

    #[test]
    fn reverse_ipv4() {
        assert_eq!(
            ip_to_reverse_name("8.8.8.8"),
            Some("8.8.8.8.in-addr.arpa".to_string())
        );
    }

    #[test]
    fn reverse_ipv4_different() {
        assert_eq!(
            ip_to_reverse_name("192.168.1.1"),
            Some("1.1.168.192.in-addr.arpa".to_string())
        );
    }

    #[test]
    fn reverse_ipv6() {
        assert_eq!(
            ip_to_reverse_name("2001:4860:4860::8888"),
            Some(
                "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa"
                    .to_string()
            )
        );
    }

    #[test]
    fn reverse_invalid() {
        assert_eq!(ip_to_reverse_name("not-an-ip"), None);
    }

    #[test]
    fn parse_txid_decimal() {
        assert_eq!(parse_txid("1234"), Ok(1234));
    }

    #[test]
    fn parse_txid_hex() {
        assert_eq!(parse_txid("0x1234"), Ok(0x1234));
    }

    #[test]
    fn parse_class_in() {
        assert_eq!(parse_class("IN"), Ok(QClass::IN));
    }

    #[test]
    fn parse_class_ch() {
        assert_eq!(parse_class("CH"), Ok(QClass::CH));
    }

    #[test]
    fn parse_class_hs() {
        assert_eq!(parse_class("HS"), Ok(QClass::HS));
    }

    #[test]
    fn parse_class_number() {
        assert_eq!(parse_class("4"), Ok(QClass::Other(4)));
    }

    #[test]
    fn constant_name_detection() {
        assert!(is_constant_name("MX"));
        assert!(is_constant_name("AAAA"));
        assert!(is_constant_name("A"));
        assert!(!is_constant_name("example.com"));
        assert!(!is_constant_name("123"));
        assert!(!is_constant_name(""));
    }
}
