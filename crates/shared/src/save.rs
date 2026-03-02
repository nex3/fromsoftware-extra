use ilhook::x64::ClosureHookPoint;

/// An enum of different circumstances in which a save file can be loaded.
pub enum OnLoadType {
    /// The fake save file for the main menu is loading. This happens when the
    /// game starts (after the first button press), and again each time the
    /// player quits their game.
    ///
    /// The `on_save` callback is not run for the main menu save, so this
    /// never has modded data associated with it.
    MainMenu,

    /// A non-menu save file with data written by the `on_save` callback is
    /// loading. This contains the written data.
    SavedData(Vec<u8>),

    /// A non-menu save file without data written by `on_save` is loading. This
    /// could be because `on_save` returned `None`, or because this is a vanilla
    /// save file that was written without hooking the save information.
    NoSavedData,
}

/// A hook created by `on_save_load` functions. When this is dropped, the hook
/// will be unregistered.
pub struct SaveLoadHook<'a> {
    _save: ClosureHookPoint<'a>,
    _load: ClosureHookPoint<'a>,
}

impl<'a> SaveLoadHook<'a> {
    /// Creates a new hook that tracks the given save and load hook points. This
    /// is not intended for end users, only for `fromsoftware-extra` crates.
    pub fn new(save: ClosureHookPoint<'a>, load: ClosureHookPoint<'a>) -> Self {
        Self {
            _save: save,
            _load: load,
        }
    }
}
