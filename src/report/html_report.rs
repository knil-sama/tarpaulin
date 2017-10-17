use std::fs::File;
use std::io::prelude::*;
use std::io::Cursor;
use horrorshow::prelude::*;
use horrorshow::helper::doctype;
use tracer::TracerData;
use config::Config;

pub fn export(coverage_data: &[TracerData], config: &Config) {
    let report = html! {
        :doctype::HTML;
        html {
            head {
                title: "Tarpaulin Coverage Report";
            }
            body {
                
            }
        }
    }.into_string().unwrap();

    let mut file = match File::create("tarpaulin.html") {
        Err(e) => {
            println!("Failed to export report {}", e);
            return;
        },
        Ok(file) => file,
    };
    let _ = file.write_all(report.as_bytes());

}
