use native_windows_gui as nwg;

pub struct UnloaderApp {
    pub window: nwg::Window,
    pub title_frame: nwg::Frame,
    pub title_label: nwg::Label,
    pub subtitle_label: nwg::Label,
    pub process_label: nwg::Label,
    pub process_input: nwg::TextInput,
    pub dll_label: nwg::Label,
    pub dll_input: nwg::TextInput,
    pub options_frame: nwg::Frame,
    pub options_label: nwg::Label,
    pub stub_checkbox: nwg::CheckBox,
    pub patch_checkbox: nwg::CheckBox,
    pub unload_button: nwg::Button,
    pub output_label: nwg::Label,
    pub output_box: nwg::TextBox,
    pub status_label: nwg::Label,
}

impl Default for UnloaderApp {
    fn default() -> Self {
        Self {
            window: Default::default(),
            title_frame: Default::default(),
            title_label: Default::default(),
            subtitle_label: Default::default(),
            process_label: Default::default(),
            process_input: Default::default(),
            dll_label: Default::default(),
            dll_input: Default::default(),
            options_frame: Default::default(),
            options_label: Default::default(),
            stub_checkbox: Default::default(),
            patch_checkbox: Default::default(),
            unload_button: Default::default(),
            output_label: Default::default(),
            output_box: Default::default(),
            status_label: Default::default(),
        }
    }
}
