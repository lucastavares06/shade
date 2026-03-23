use std::cell::RefCell;
use std::rc::Rc;

use native_windows_gui as nwg;

use super::app::UnloaderApp;
use crate::core::unloader::{unload_dll, UnloadConfig};

const WINDOW_WIDTH: i32 = 600;
const WINDOW_HEIGHT: i32 = 620;
const CONTENT_MARGIN: i32 = 20;
const CONTENT_WIDTH: i32 = WINDOW_WIDTH - CONTENT_MARGIN * 2;

const FONT_HEADING: &str = "Segoe UI";
const FONT_MONO: &str = "Courier New";

struct Fonts {
    title: nwg::Font,
    subtitle: nwg::Font,
    label: nwg::Font,
    input: nwg::Font,
    button: nwg::Font,
    output: nwg::Font,
    status: nwg::Font,
    options: nwg::Font,
}

impl Fonts {
    fn build() -> Self {
        Self {
            title: make_font(FONT_HEADING, 24, 700),
            subtitle: make_font(FONT_HEADING, 13, 400),
            label: make_font(FONT_HEADING, 14, 600),
            input: make_font(FONT_MONO, 16, 400),
            button: make_font(FONT_HEADING, 14, 700),
            output: make_font(FONT_MONO, 16, 400),
            status: make_font(FONT_HEADING, 11, 400),
            options: make_font(FONT_HEADING, 12, 600),
        }
    }
}

fn make_font(family: &str, size: u32, weight: u32) -> nwg::Font {
    let mut font = nwg::Font::default();
    nwg::Font::builder()
        .family(family)
        .size(size)
        .weight(weight)
        .build(&mut font)
        .unwrap();
    font
}

pub fn build_and_run(app: Rc<RefCell<UnloaderApp>>) {
    let fonts = Fonts::build();

    {
        let mut borrowed = app.borrow_mut();
        build_window(&mut borrowed);
        build_header(&mut borrowed, &fonts);
        build_inputs(&mut borrowed, &fonts);
        build_options(&mut borrowed, &fonts);
        build_action_button(&mut borrowed, &fonts);
        build_output_section(&mut borrowed, &fonts);
    }

    let event_handler = bind_events(Rc::clone(&app));

    nwg::dispatch_thread_events();
    nwg::unbind_event_handler(&event_handler);
}

fn build_window(app: &mut UnloaderApp) {
    nwg::Window::builder()
        .title("shade")
        .size((WINDOW_WIDTH, WINDOW_HEIGHT))
        .center(true)
        .flags(
            nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE | nwg::WindowFlags::MINIMIZE_BOX,
        )
        .build(&mut app.window)
        .unwrap();
}

fn build_header(app: &mut UnloaderApp, fonts: &Fonts) {
    nwg::Frame::builder()
        .parent(&app.window)
        .position((0, 0))
        .size((WINDOW_WIDTH, 76))
        .build(&mut app.title_frame)
        .unwrap();

    nwg::Label::builder()
        .text("shade / module hider")
        .font(Some(&fonts.title))
        .parent(&app.title_frame)
        .position((CONTENT_MARGIN, 10))
        .size((400, 32))
        .build(&mut app.title_label)
        .unwrap();

    nwg::Label::builder()
        .text("frozen stub remap  /  shellcode FreeLibrary  /  DllMain patch")
        .font(Some(&fonts.subtitle))
        .parent(&app.title_frame)
        .position((CONTENT_MARGIN + 2, 44))
        .size((CONTENT_WIDTH, 20))
        .build(&mut app.subtitle_label)
        .unwrap();
}

fn build_inputs(app: &mut UnloaderApp, fonts: &Fonts) {
    nwg::Label::builder()
        .text("Target Process")
        .font(Some(&fonts.label))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 90))
        .size((200, 22))
        .build(&mut app.process_label)
        .unwrap();

    nwg::TextInput::builder()
        .font(Some(&fonts.input))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 114))
        .size((CONTENT_WIDTH, 24))
        .placeholder_text(Some("e.g. gta_sa.exe"))
        .build(&mut app.process_input)
        .unwrap();

    nwg::Label::builder()
        .text("Module / DLL")
        .font(Some(&fonts.label))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 152))
        .size((200, 22))
        .build(&mut app.dll_label)
        .unwrap();

    nwg::TextInput::builder()
        .font(Some(&fonts.input))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 176))
        .size((CONTENT_WIDTH, 24))
        .placeholder_text(Some("e.g. crashes.asi"))
        .build(&mut app.dll_input)
        .unwrap();
}

fn build_options(app: &mut UnloaderApp, fonts: &Fonts) {
    nwg::CheckBox::builder()
        .text("Keep frozen stub  -  prevents crashes from pending hooks")
        .font(Some(&fonts.subtitle))
        .parent(&app.window)
        .position((34, 234))
        .size((CONTENT_WIDTH - 28, 22))
        .check_state(nwg::CheckBoxState::Checked)
        .build(&mut app.stub_checkbox)
        .unwrap();

    nwg::CheckBox::builder()
        .text("Neutralize DllMain  -  patches entry point before unload")
        .font(Some(&fonts.subtitle))
        .parent(&app.window)
        .position((34, 260))
        .size((CONTENT_WIDTH - 28, 22))
        .check_state(nwg::CheckBoxState::Checked)
        .build(&mut app.patch_checkbox)
        .unwrap();

    nwg::Frame::builder()
        .parent(&app.window)
        .position((CONTENT_MARGIN, 220))
        .size((CONTENT_WIDTH, 72))
        .build(&mut app.options_frame)
        .unwrap();

    nwg::Label::builder()
        .text(" Options ")
        .font(Some(&fonts.options))
        .parent(&app.window)
        .position((32, 213))
        .size((68, 18))
        .build(&mut app.options_label)
        .unwrap();
}

fn build_action_button(app: &mut UnloaderApp, fonts: &Fonts) {
    nwg::Button::builder()
        .text("HIDE MODULE")
        .font(Some(&fonts.button))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 306))
        .size((CONTENT_WIDTH, 40))
        .build(&mut app.unload_button)
        .unwrap();
}

fn build_output_section(app: &mut UnloaderApp, fonts: &Fonts) {
    nwg::Label::builder()
        .text("Output")
        .font(Some(&fonts.label))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 360))
        .size((100, 20))
        .build(&mut app.output_label)
        .unwrap();

    nwg::TextBox::builder()
        .font(Some(&fonts.output))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 382))
        .size((CONTENT_WIDTH, 196))
        .readonly(true)
        .build(&mut app.output_box)
        .unwrap();

    nwg::Label::builder()
        .text("Ready")
        .font(Some(&fonts.status))
        .parent(&app.window)
        .position((CONTENT_MARGIN, 586))
        .size((CONTENT_WIDTH, 18))
        .build(&mut app.status_label)
        .unwrap();
}

fn bind_events(app: Rc<RefCell<UnloaderApp>>) -> nwg::EventHandler {
    let window_handle = app.borrow().window.handle;

    nwg::full_bind_event_handler(&window_handle, move |event, _, handle| {
        let borrowed = app.borrow();

        match event {
            nwg::Event::OnWindowClose if handle == borrowed.window.handle => {
                nwg::stop_thread_dispatch();
            }
            nwg::Event::OnButtonClick if handle == borrowed.unload_button.handle => {
                handle_unload_click(&borrowed);
            }
            _ => {}
        }
    })
}

fn handle_unload_click(app: &UnloaderApp) {
    let process_name = app.process_input.text();
    let dll_name = app.dll_input.text();

    if process_name.trim().is_empty() || dll_name.trim().is_empty() {
        app.output_box
            .set_text("[-] Please fill in both fields.\r\n");
        app.status_label.set_text("Error: empty fields");
        return;
    }

    app.status_label.set_text("Running...");
    app.output_box.set_text("");

    let mut config = UnloadConfig::new(process_name, dll_name);
    config.patch_dllmain = app.patch_checkbox.check_state() == nwg::CheckBoxState::Checked;
    config.freeze_stub = app.stub_checkbox.check_state() == nwg::CheckBoxState::Checked;

    match unload_dll(&config) {
        Ok(unload_result) => {
            app.output_box
                .set_text(&unload_result.log.replace('\n', "\r\n"));

            let status_text = if unload_result.module_unloaded {
                if unload_result.stub_remapped {
                    "Unloaded + stub active"
                } else {
                    "Unloaded (no stub)"
                }
            } else {
                "Failed to unload"
            };
            app.status_label.set_text(status_text);
        }
        Err(unload_error) => {
            app.output_box
                .set_text(&format!("[-] Error: {}\r\n", unload_error));
            app.status_label.set_text("Failed");
        }
    }
}
