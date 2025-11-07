//! Rendering tables of DNS response results.

use dns::Answer;
use dns::record::Record;
use owo_colors::OwoColorize;
use std::time::Duration;

use crate::colours::Colours;
use crate::output::TextFormat;

/// A **table** is built up from all the response records present in a DNS
/// packet. It then gets displayed to the user.
#[derive(Debug)]
pub struct Table {
    colours: Colours,
    text_format: TextFormat,
    rows: Vec<Row>,
}

/// A row of the table. This contains all the fields
#[derive(Debug)]
pub struct Row {
    qtype: String,
    qname: String,
    ttl: Option<String>,
    section: Section,
    summary: String,
}

/// The section of the DNS response that a record was read from.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Section {
    /// This record was found in the **Answer** section.
    Answer,

    /// This record was found in the **Authority** section.
    Authority,

    /// This record was found in the **Additional** section.
    Additional,
}

impl Table {
    /// Create a new table with no rows.
    pub fn new(colours: Colours, text_format: TextFormat) -> Self {
        Self {
            colours,
            text_format,
            rows: Vec::new(),
        }
    }

    /// Adds a row to the table, containing the data in the given answer in
    /// the right section.
    pub fn add_row(&mut self, answer: Answer, section: Section) {
        match answer {
            Answer::Standard {
                record, qname, ttl, ..
            } => {
                let qtype = self.coloured_record_type(&record);
                let qname = qname.to_string();
                let summary = self.text_format.record_payload_summary(record);
                let ttl = Some(self.text_format.format_duration(ttl));
                self.rows.push(Row {
                    qtype,
                    qname,
                    ttl,
                    summary,
                    section,
                });
            }
            Answer::Pseudo { qname, opt } => {
                let qtype = "OPT".style(self.colours.opt).to_string();
                let qname = qname.to_string();
                let summary = self.text_format.pseudo_record_payload_summary(opt);
                self.rows.push(Row {
                    qtype,
                    qname,
                    ttl: None,
                    summary,
                    section,
                });
            }
        }
    }

    /// Prints the formatted table to stdout.
    pub fn print(self, duration: Option<Duration>) {
        if !self.rows.is_empty() {
            let qtype_len = self.max_qtype_len();
            let qname_len = self.max_qname_len();
            let ttl_len = self.max_ttl_len();

            for r in &self.rows {
                for _ in 0..qtype_len - r.qtype.len() {
                    print!(" ");
                }

                print!("{} {} ", r.qtype, r.qname.style(self.colours.qname));

                for _ in 0..qname_len - r.qname.len() {
                    print!(" ");
                }

                if let Some(ttl) = &r.ttl {
                    for _ in 0..ttl_len - ttl.len() {
                        print!(" ");
                    }

                    print!("{}", ttl);
                } else {
                    for _ in 0..ttl_len {
                        print!(" ");
                    }
                }

                println!(" {} {}", self.format_section(r.section), r.summary);
            }
        }

        if let Some(dur) = duration {
            println!("Ran in {}ms", dur.as_millis());
        }
    }

    fn coloured_record_type(&self, record: &Record) -> String {
        match *record {
            Record::A(_) => "A".style(self.colours.a).to_string(),
            Record::AAAA(_) => "AAAA".style(self.colours.aaaa).to_string(),
            Record::CAA(_) => "CAA".style(self.colours.caa).to_string(),
            Record::CNAME(_) => "CNAME".style(self.colours.cname).to_string(),
            Record::EUI48(_) => "EUI48".style(self.colours.eui48).to_string(),
            Record::EUI64(_) => "EUI64".style(self.colours.eui64).to_string(),
            Record::HINFO(_) => "HINFO".style(self.colours.hinfo).to_string(),
            Record::LOC(_) => "LOC".style(self.colours.loc).to_string(),
            Record::MX(_) => "MX".style(self.colours.mx).to_string(),
            Record::NAPTR(_) => "NAPTR".style(self.colours.naptr).to_string(),
            Record::NS(_) => "NS".style(self.colours.ns).to_string(),
            Record::OPENPGPKEY(_) => "OPENPGPKEY".style(self.colours.openpgpkey).to_string(),
            Record::PTR(_) => "PTR".style(self.colours.ptr).to_string(),
            Record::SSHFP(_) => "SSHFP".style(self.colours.sshfp).to_string(),
            Record::SOA(_) => "SOA".style(self.colours.soa).to_string(),
            Record::SRV(_) => "SRV".style(self.colours.srv).to_string(),
            Record::TLSA(_) => "TLSA".style(self.colours.tlsa).to_string(),
            Record::TXT(_) => "TXT".style(self.colours.txt).to_string(),
            Record::URI(_) => "URI".style(self.colours.uri).to_string(),

            Record::Other {
                ref type_number, ..
            } => type_number
                .to_string()
                .style(self.colours.unknown)
                .to_string(),
        }
    }

    fn max_qtype_len(&self) -> usize {
        self.rows.iter().map(|r| r.qtype.len()).max().unwrap()
    }

    fn max_qname_len(&self) -> usize {
        self.rows.iter().map(|r| r.qname.len()).max().unwrap()
    }

    fn max_ttl_len(&self) -> usize {
        self.rows
            .iter()
            .map(|r| r.ttl.as_ref().map_or(0, String::len))
            .max()
            .unwrap()
    }

    fn format_section(&self, section: Section) -> String {
        match section {
            Section::Answer => " ".style(self.colours.answer).to_string(),
            Section::Authority => "A".style(self.colours.authority).to_string(),
            Section::Additional => "+".style(self.colours.additional).to_string(),
        }
    }
}
