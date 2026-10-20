use pelite::pe64::PeView;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::core::PCSTR;

/// Exact WW1.17.2 identity; adding a version string alone cannot admit a changed file.
pub fn verify_ww272_file(bytes: &[u8]) -> bool {
    bytes.len() == 86_973_008
        && format!("{:x}", Sha256::digest(bytes))
            == "f9118fea2cfd8fa3901e8060bfadb1552cb2471771ded8a5b662c4e298ffb328"
}

mod bundle;
mod rva_jp;
mod rva_ww;

// Published before a task receives bindings. Owned offline struct fixtures keep
// the legacy layout unless they explicitly test the pure offset selector.
static WW272_SELECTED: AtomicBool = AtomicBool::new(false);
pub(crate) fn ww272_selected() -> bool {
    WW272_SELECTED.load(Ordering::Acquire)
}

pub use bundle::RvaBundle;

use fromsoftware_shared::game_version::{GameVersion, LANG_ID_EN, LANG_ID_JP};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ERGameVersion {
    Ww262,
    Jp2621,
    Ww2700,
    Jp2701,
    Ww2710,
    Ww2720,
}

impl GameVersion for ERGameVersion {
    const NAME: &'static str = "elden ring";

    fn from_lang_version(lang_id: u16, version: &str) -> Option<Self> {
        match (lang_id, version) {
            (LANG_ID_EN, "2.6.2.0") => Some(Self::Ww262),
            (LANG_ID_JP, "2.6.2.1") => Some(Self::Jp2621),
            (LANG_ID_EN, "2.7.0.0") => Some(Self::Ww2700),
            (LANG_ID_JP, "2.7.0.1") => Some(Self::Jp2701),
            (LANG_ID_EN, "2.7.1.0") => Some(Self::Ww2710),
            (LANG_ID_EN, "2.7.2.0") => Some(Self::Ww2720),
            _ => None,
        }
    }
}

impl ERGameVersion {
    const fn rvas(self) -> RvaBundle {
        match self {
            Self::Ww262 => rva_ww::RVAS_262,
            Self::Jp2621 => rva_jp::RVAS_2621,
            Self::Ww2700 => rva_ww::RVAS_2700,
            Self::Jp2701 => rva_jp::RVAS_2701,
            Self::Ww2710 => rva_ww::RVAS_2710,
            Self::Ww2720 => rva_ww::RVAS_2720,
        }
    }
}

/// Returns the RVA bundle for the current executable region and version.
///
/// This will panic if the current executable isn't supported by this package.
pub fn try_get() -> Result<&'static RvaBundle, &'static str> {
    static RVAS: LazyLock<Result<RvaBundle, String>> = LazyLock::new(|| {
        let handle =
            unsafe { GetModuleHandleA(PCSTR(std::ptr::null())) }.map_err(|e| e.to_string())?;
        let module = unsafe { PeView::module(handle.0 as *const u8) };
        let version = ERGameVersion::detect(&module).map_err(|e| e.to_string())?;
        if version == ERGameVersion::Ww2720 {
            let path = std::env::current_exe().map_err(|e| e.to_string())?;
            let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
            if !verify_ww272_file(&bytes) {
                return Err("unverified WW2.7.2 executable; no RVA bindings supplied".into());
            }
            WW272_SELECTED.store(true, Ordering::Release);
        }
        Ok(version.rvas())
    });
    RVAS.as_ref().map_err(String::as_str)
}

pub fn get() -> &'static RvaBundle {
    try_get().unwrap_or_else(|error| panic!("{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_1172_without_changing_1171() {
        let current = ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.2.0")
            .unwrap()
            .rvas();
        assert_eq!(current.register_task, 0xeb5540);
        assert_eq!(current.game_data_man, 0x3d64fb8);
        assert_eq!(ERGameVersion::Ww2710.rvas().register_task, 0xeb3e50);
        assert!(ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.3.0").is_none());
        assert!(ERGameVersion::from_lang_version(LANG_ID_JP, "2.7.2.1").is_none());
        assert!(!verify_ww272_file(&[]));
        assert!(!verify_ww272_file(&[0; 4096]));
    }

    #[test]
    fn installed_1172_identity_rejects_corruption_when_supplied() {
        let Some(path) = std::env::var_os("ER_GAME_EXE") else {
            return;
        };
        let mut bytes = std::fs::read(path).unwrap();
        assert!(verify_ww272_file(&bytes));
        bytes[0x400] ^= 1;
        assert!(!verify_ww272_file(&bytes));
    }

    #[test]
    fn recognizes_1171_and_routes_changed_native_entries() {
        let version = ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.1.0")
            .expect("verified WW 1.17.1 must be recognized");
        let rvas = version.rvas();
        assert_eq!(rvas.register_task, 0xeb3e50);
        assert_eq!(rvas.cs_phys_world_cast_ray, 0xc71e00);
        assert_eq!(rvas.cs_ez_draw_draw_line, 0x2652640);
        assert_eq!(rvas.cs_ez_draw_draw_triangle, 0x2652390);
        assert_eq!(rvas.cs_ez_draw_draw_wedge, 0x2651f40);
        assert_eq!(rvas.cs_bullet_manager_spawn_bullet, 0x3a2cb0);
        assert_eq!(rvas.chr_ins_apply_speffect, 0x3e8dc0);
        assert_eq!(rvas.chr_ins_remove_speffect, 0x3ee2e0);
    }

    #[test]
    fn retains_1170_entries_and_rejects_unverified_1171_regions() {
        let old = ERGameVersion::Ww2700.rvas();
        assert_eq!(old.register_task, 0xeb3de0);
        assert_eq!(old.cs_phys_world_cast_ray, 0xc71d90);
        assert_eq!(old.cs_ez_draw_draw_line, 0x26525d0);
        assert_eq!(old.cs_ez_draw_draw_triangle, 0x2652320);
        assert_eq!(old.cs_ez_draw_draw_wedge, 0x2651ed0);
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_JP, "2.7.1.0"),
            None
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_JP, "2.7.1.1"),
            None
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.1.1"),
            None
        );
    }

    #[test]
    fn recognizes_retained_and_current_executable_versions() {
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_EN, "2.6.2.0"),
            Some(ERGameVersion::Ww262)
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_JP, "2.6.2.1"),
            Some(ERGameVersion::Jp2621)
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.0.0"),
            Some(ERGameVersion::Ww2700)
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_JP, "2.7.0.1"),
            Some(ERGameVersion::Jp2701)
        );
    }

    #[test]
    fn rejects_unmapped_executable_versions() {
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.0.1"),
            None
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_JP, "2.7.0.0"),
            None
        );
        assert_eq!(
            ERGameVersion::from_lang_version(LANG_ID_EN, "2.8.0.0"),
            None
        );
    }

    #[test]
    fn selects_version_specific_bullet_spawn_rvas() {
        assert_eq!(
            ERGameVersion::Ww262.rvas().cs_bullet_manager_spawn_bullet,
            0x3a2ca0
        );
        assert_eq!(
            ERGameVersion::Jp2621.rvas().cs_bullet_manager_spawn_bullet,
            0x3a2ca0
        );
        assert_eq!(
            ERGameVersion::Ww2700.rvas().cs_bullet_manager_spawn_bullet,
            0x3a2cb0
        );
        assert_eq!(
            ERGameVersion::Jp2701.rvas().cs_bullet_manager_spawn_bullet,
            0x3a2cb0
        );
    }
}
