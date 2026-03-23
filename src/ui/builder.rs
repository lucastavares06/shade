use std::cell::RefCell;
use std::rc::Rc;

use native_windows_gui as nwg;

use super::app::UnloaderApp;
use crate::core::unloader::{unload_dll, UnloadConfig};

fn build_font(family: &str, size: u32, weight: u32) -> nwg::Font {
    let mut font: nwg::Font = Default::default();
    nwg::Font::builder()
        .family(family)
        .size(size)
        .weight(weight)
        .build(&mut font)
        .unwrap();
    font
}

fn build_font_plain(family: &str, size: u32) -> nwg::Font {
    build_font(family, size, 400)
}

pub fn build_and_run(app: Rc<RefCell<UnloaderApp>>) {
    let mut borrowed = app.borrow_mut();

    let title_font = build_font("Segoe UI", 24, 700);
    let subtitle_font = build_font_plain("Segoe UI", 13);
    let label_font = build_font("Segoe UI", 14, 600);
    let input_font = build_font_plain("Courier New", 16);
    let button_font = build_font("Segoe UI", 14, 700);
    let output_font = build_font_plain("Courier New", 16);
    let status_font = build_font_plain("Segoe UI", 11);
    let options_font = build_font("Segoe UI", 12, 600);

    nwg::Window::builder()
        .title("shade")
        .size((600, 620))
        .center(true)
        .flags(
            nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE | nwg::WindowFlags::MINIMIZE_BOX,
        )
        .build(&mut borrowed.window)
        .unwrap();

    nwg::Frame::builder()
        .parent(&borrowed.window)
        .position((0, 0))
        .size((600, 76))
        .build(&mut borrowed.title_frame)
        .unwrap();

    nwg::Label::builder()
        .text("shade / module hider")
        .font(Some(&title_font))
        .parent(&borrowed.title_frame)
        .position((20, 10))
        .size((400, 32))
        .build(&mut borrowed.title_label)
        .unwrap();

    nwg::Label::builder()
        .text("frozen stub remap  /  shellcode FreeLibrary  /  DllMain patch")
        .font(Some(&subtitle_font))
        .parent(&borrowed.title_frame)
        .position((22, 44))
        .size((560, 20))
        .build(&mut borrowed.subtitle_label)
        .unwrap();

    nwg::Label::builder()
        .text("Target Process")
        .font(Some(&label_font))
        .parent(&borrowed.window)
        .position((20, 90))
        .size((200, 22))
        .build(&mut borrowed.process_label)
        .unwrap();

    nwg::TextInput::builder()
        .font(Some(&input_font))
        .parent(&borrowed.window)
        .position((20, 114))
        .size((560, 24))
        .placeholder_text(Some("e.g. gta_sa.exe"))
        .build(&mut borrowed.process_input)
        .unwrap();

    nwg::Label::builder()
        .text("Module / DLL")
        .font(Some(&label_font))
        .parent(&borrowed.window)
        .position((20, 152))
        .size((200, 22))
        .build(&mut borrowed.dll_label)
        .unwrap();

    nwg::TextInput::builder()
        .font(Some(&input_font))
        .parent(&borrowed.window)
        .position((20, 176))
        .size((560, 24))
        .placeholder_text(Some("e.g. crashes.asi"))
        .build(&mut borrowed.dll_input)
        .unwrap();

    nwg::CheckBox::builder()
        .text("Keep frozen stub  -  prevents crashes from pending hooks")
        .font(Some(&subtitle_font))
        .parent(&borrowed.window)
        .position((34, 234))
        .size((532, 22))
        .check_state(nwg::CheckBoxState::Checked)
        .build(&mut borrowed.stub_checkbox)
        .unwrap();

    nwg::CheckBox::builder()
        .text("Neutralize DllMain  -  patches entry point before unload")
        .font(Some(&subtitle_font))
        .parent(&borrowed.window)
        .position((34, 260))
        .size((532, 22))
        .check_state(nwg::CheckBoxState::Checked)
        .build(&mut borrowed.patch_checkbox)
        .unwrap();

    nwg::Frame::builder()
        .parent(&borrowed.window)
        .position((20, 220))
        .size((560, 72))
        .build(&mut borrowed.options_frame)
        .unwrap();

    nwg::Label::builder()
        .text(" Options ")
        .font(Some(&options_font))
        .parent(&borrowed.window)
        .position((32, 213))
        .size((68, 18))
        .build(&mut borrowed.options_label)
        .unwrap();

    nwg::Button::builder()
        .text("HIDE MODULE")
        .font(Some(&button_font))
        .parent(&borrowed.window)
        .position((20, 306))
        .size((560, 40))
        .build(&mut borrowed.unload_button)
        .unwrap();

    nwg::Label::builder()
        .text("Output")
        .font(Some(&label_font))
        .parent(&borrowed.window)
        .position((20, 360))
        .size((100, 20))
        .build(&mut borrowed.output_label)
        .unwrap();

    nwg::TextBox::builder()
        .font(Some(&output_font))
        .parent(&borrowed.window)
        .position((20, 382))
        .size((560, 196))
        .readonly(true)
        .build(&mut borrowed.output_box)
        .unwrap();

    nwg::Label::builder()
        .text("Ready")
        .font(Some(&status_font))
        .parent(&borrowed.window)
        .position((20, 586))
        .size((560, 18))
        .build(&mut borrowed.status_label)
        .unwrap();

    let window_handle = borrowed.window.handle;
    drop(borrowed);

    let event_handler = {
        let app = Rc::clone(&app);
        nwg::full_bind_event_handler(&window_handle, move |event, _, handle| {
            let borrowed = app.borrow();

            match event {
                nwg::Event::OnWindowClose => {
                    if handle == borrowed.window.handle {
                        nwg::stop_thread_dispatch();
                    }
                }
                nwg::Event::OnButtonClick => {
                    if handle != borrowed.unload_button.handle {
                        return;
                    }

                    let process_name = borrowed.process_input.text();
                    let dll_name = borrowed.dll_input.text();

                    if process_name.trim().is_empty() || dll_name.trim().is_empty() {
                        borrowed
                            .output_box
                            .set_text("[-] Please fill in both fields.\r\n");
                        borrowed.status_label.set_text("Error: empty fields");
                        return;
                    }

                    let should_patch =
                        borrowed.patch_checkbox.check_state() == nwg::CheckBoxState::Checked;
                    let should_freeze =
                        borrowed.stub_checkbox.check_state() == nwg::CheckBoxState::Checked;

                    borrowed.status_label.set_text("Running...");
                    borrowed.output_box.set_text("");

                    let mut config = UnloadConfig::new(process_name, dll_name);
                    config.patch_dllmain = should_patch;
                    config.freeze_stub = should_freeze;

                    match unload_dll(&config) {
                        Ok(unload_result) => {
                            borrowed
                                .output_box
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
                            borrowed.status_label.set_text(status_text);
                        }
                        Err(unload_error) => {
                            borrowed
                                .output_box
                                .set_text(&format!("[-] Error: {}\r\n", unload_error));
                            borrowed.status_label.set_text("Failed");
                        }
                    }
                }
                _ => {}
            }
        })
    };

    nwg::dispatch_thread_events();
    nwg::unbind_event_handler(&event_handler);
}
