use std::fs::File;
use std::io::prelude::*;
use horrorshow::prelude::*;
use horrorshow::helper::doctype;
use horrorshow::RenderBox;
use tracer::TracerData;
use config::Config;


fn render_results(res: &[TracerData]) -> Box<RenderBox> {
    box_html! {

    }
}

pub fn export(coverage_data: &[TracerData], config: &Config) {
    let report = html! {
        :doctype::HTML;
        html {
            head {
                title: "Tarpaulin Coverage Report";
                p {
                    :Raw(r#"<!-- Latest compiled and minified CSS -->
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" 
                    integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" 
                    crossorigin="anonymous">

                    <!-- Optional theme -->
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" 
                    integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" 
                    crossorigin="anonymous">

                    <!-- Latest compiled and minified JavaScript -->
                    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" 
                    integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" 
                    crossorigin="anonymous"></script>"#)
                }
            }
            body {
                div(class="container") {
                    div(class="page-header") {
                        h1 {
                            :"Tarpaulin Coverage Report"
                        }
                    }
                    h3 {
                        :"Run Summary"
                    }
                    p {
                        :format!("Manifest path {}", config.manifest.display()) 
                    }
                    h3 {
                        :"Coverage Results"
                    }
                    p {
                        render_results(coverage_data)
                    }
                }
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
