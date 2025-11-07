//! Colours, colour schemes, and terminal styling.

use owo_colors::Style;

/// The **colours** are used to paint the input.
#[derive(Debug, Default)]
pub struct Colours {
    pub qname: Style,

    pub answer: Style,
    pub authority: Style,
    pub additional: Style,

    pub a: Style,
    pub aaaa: Style,
    pub caa: Style,
    pub cname: Style,
    pub eui48: Style,
    pub eui64: Style,
    pub hinfo: Style,
    pub loc: Style,
    pub mx: Style,
    pub ns: Style,
    pub naptr: Style,
    pub openpgpkey: Style,
    pub opt: Style,
    pub ptr: Style,
    pub sshfp: Style,
    pub soa: Style,
    pub srv: Style,
    pub tlsa: Style,
    pub txt: Style,
    pub uri: Style,
    pub unknown: Style,
}

impl Colours {
    /// Create a new colour palette that has a variety of different styles
    /// defined. This is used by default.
    pub fn pretty() -> Self {
        Self {
            qname: Style::new().blue().bold(),

            answer: Style::new(),
            authority: Style::new().cyan(),
            additional: Style::new().green(),

            a: Style::new().green().bold(),
            aaaa: Style::new().green().bold(),
            caa: Style::new().red(),
            cname: Style::new().yellow(),
            eui48: Style::new().yellow(),
            eui64: Style::new().yellow().bold(),
            hinfo: Style::new().yellow(),
            loc: Style::new().yellow(),
            mx: Style::new().cyan(),
            naptr: Style::new().green(),
            ns: Style::new().red(),
            openpgpkey: Style::new().cyan(),
            opt: Style::new().purple(),
            ptr: Style::new().red(),
            sshfp: Style::new().cyan(),
            soa: Style::new().purple(),
            srv: Style::new().cyan(),
            tlsa: Style::new().yellow(),
            txt: Style::new().yellow(),
            uri: Style::new().yellow(),
            unknown: Style::new().white().on_red(),
        }
    }

    /// Create a new colour palette where no styles are defined, causing
    /// output to be rendered as plain text without any formatting.
    /// This is used when output is not to a terminal.
    pub fn plain() -> Self {
        Self::default()
    }
}
