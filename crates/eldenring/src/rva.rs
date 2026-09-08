use pelite::pe64::PeView;
use std::sync::LazyLock;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::core::PCSTR;

mod bundle;
mod rva_jp;
mod rva_ww;

pub use bundle::RvaBundle;

use fromsoftware_shared::game_version::{GameVersion, LANG_ID_EN, LANG_ID_JP};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ERGameVersion {
    Ww2700,
    Ww2710,
    Jp2701,
}

impl GameVersion for ERGameVersion {
    const NAME: &'static str = "elden ring";

    fn from_lang_version(lang_id: u16, version: &str) -> Option<Self> {
        match (lang_id, version) {
            (LANG_ID_EN, "2.7.0.0") => Some(Self::Ww2700),
            (LANG_ID_EN, "2.7.1.0") => Some(Self::Ww2710),
            (LANG_ID_JP, "2.7.0.1") => Some(Self::Jp2701),
            _ => None,
        }
    }
}

impl ERGameVersion {
    const fn rvas(self) -> RvaBundle {
        match self {
            Self::Ww2700 => rva_ww::RVAS,
            // Mapped from WW 1.17.1 (product version 2.7.1.0).
            // All other entries match the WW 1.17 map.
            Self::Ww2710 => RvaBundle {
                register_task: 0xeb3e50,
                cs_phys_world_cast_ray: 0xc71e00,
                cs_ez_draw_draw_line: 0x2652640,
                cs_ez_draw_draw_triangle: 0x2652390,
                cs_ez_draw_draw_wedge: 0x2651f40,
                ..rva_ww::RVAS
            },
            Self::Jp2701 => rva_jp::RVAS,
        }
    }
}

/// Returns the RVA bundle for the current executable region and version.
///
/// This will panic if the current executable isn't supported by this package.
pub fn get() -> &'static RvaBundle {
    static RVAS: LazyLock<RvaBundle> = LazyLock::new(|| {
        let module = unsafe {
            PeView::module(GetModuleHandleA(PCSTR(std::ptr::null())).unwrap().0 as *const u8)
        };
        ERGameVersion::detect(&module)
            .unwrap_or_else(|e| panic!("{e}"))
            .rvas()
    });

    &RVAS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ww_1171_is_distinct_from_117_and_unknown_versions_are_rejected() {
        let old = ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.0.0").unwrap();
        let new = ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.1.0").unwrap();
        assert_eq!(old.rvas().register_task, 0xeb3de0);
        assert_eq!(new.rvas().register_task, 0xeb3e50);
        assert_eq!(new.rvas().game_data_man, old.rvas().game_data_man);
        assert!(ERGameVersion::from_lang_version(LANG_ID_EN, "2.7.2.0").is_none());
        assert!(ERGameVersion::from_lang_version(LANG_ID_JP, "2.7.1.0").is_none());
    }
}
