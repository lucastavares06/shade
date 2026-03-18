#![windows_subsystem = "windows"]

mod core;
mod ui;

use std::cell::RefCell;
use std::rc::Rc;

use native_windows_gui as nwg;

use ui::app::UnloaderApp;
use ui::builder::build_and_run;

fn main() {
    nwg::init().expect("Failed to initialize NWG");
    nwg::Font::set_global_family("Segoe UI").ok();

    let app = Rc::new(RefCell::new(UnloaderApp::default()));
    build_and_run(app);
}
