extern crate fromsoftware_shared as shared;

mod stl;
pub use stl::*;

pub(crate) mod rva;
pub use rva::verify_ww272_file;

/// True after verified WW272 RVA/task bindings have been initialized.
pub fn is_ww272() -> bool {
    rva::ww272_selected()
}

/// Initialize version/identity and publish layout selection before callbacks or
/// hooks start. Unknown identities return an error without supplying addresses.
pub fn initialize_game_bindings() -> Result<(), String> {
    rva::try_get().map(|_| ()).map_err(str::to_owned)
}

pub mod asterids;
pub mod cs;
pub mod dlcr;
pub mod dlio;
pub mod dlkr;
pub mod dlkrd;
pub mod dlrf;
pub mod dltx;
pub mod dlut;
pub mod ez_state;
pub mod fd4;
pub mod ffx;
pub mod from_net;
pub mod gxffx;
pub mod param;
pub mod position;
pub mod rotation;
pub mod util;
