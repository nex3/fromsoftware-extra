use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use bitflags::bitflags;
use ilhook::{HookError, x64::*};
use pelite::pe64::Pe;
use shared::Program;

use crate::rva;

/// The singleton instance of InputBlocker, if it's been initialized.
static INPUT_BLOCKER: OnceLock<InputBlocker> = OnceLock::new();

/// This is an inelegant workaround to ensure that two separate threads don't
/// both start initializing [INPUT_BLOCKER] at the same time. We can't just use
/// [OnceLock.get_or_init] because we want to avoid initializing if a hook fails
/// This would be much better handled by [OnceLock.get_or_try_init] once it's
/// stable.
static INITIALIZING_INPUT_BLOCKER: Mutex<()> = Mutex::new(());

/// A struct that allows programs to toggle DS3's ability to handle input on and
/// off.
pub struct InputBlocker(AtomicU8);

impl InputBlocker {
    /// Returns the singleton [InputBlocker] instance, injecting hooks into the
    /// process to create one if necessary. This returns a [HookError] if the
    ///
    /// ## Safety
    ///
    /// This is subject to all the standard [ilhook safety concerns].
    ///
    /// [ilhook safety concerns]: https://docs.rs/ilhook/latest/ilhook/x64/struct.Hooker.html#method.hook
    pub unsafe fn get_instance() -> Result<&'static InputBlocker, HookError> {
        // Don't even bother messing with the loader mutex if we don't have to.
        if let Some(blocker) = INPUT_BLOCKER.get() {
            return Ok(blocker);
        }

        let _guard = INITIALIZING_INPUT_BLOCKER
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let rvas = rva::get();
        let inputs_and_rvas = [
            (
                InputFlags::GamePad,
                rvas.dluid_pad_device_should_block_input,
            ),
            (
                InputFlags::Keyboard,
                rvas.dluid_keyboard_device_should_block_input,
            ),
            (
                InputFlags::Mouse,
                rvas.dluid_mouse_device_should_block_input,
            ),
        ];

        let mut hooks: [Option<ClosureHookPoint>; _] =
            [const { None }; InputFlags::all().bits().count_ones() as usize];
        assert!(hooks.len() == inputs_and_rvas.len());

        for (input, rva) in inputs_and_rvas {
            let va = Program::current()
                .rva_to_va(rva)
                .expect("Call target for input block RVA was not in exe");

            let closure = move |reg: *mut Registers, original| {
                let blocked =
                    InputFlags::from_bits_retain(INPUT_BLOCKER.wait().0.load(Ordering::Relaxed));
                if blocked.contains(input) {
                    0usize
                } else {
                    let original: unsafe extern "win64" fn(u64, u64) -> usize =
                        unsafe { std::mem::transmute(original) };
                    unsafe { original((*reg).rcx, (*reg).rdx) }
                }
            };

            let hook = unsafe {
                hook_closure_retn(
                    va as usize,
                    closure,
                    CallbackOption::None,
                    HookFlags::empty(),
                )?
            };

            // flag.highest_one() - 1 will be clearer once it's not
            // experimental.
            hooks[input.bits().ilog2() as usize] = Some(hook);
        }

        // Wait to forget the hooks until they're all initialized, so that if
        // one fails they all get unregistered.
        std::mem::forget(hooks);

        // The mutex guarantees that this won't be set at this point.
        let _ = INPUT_BLOCKER.set(InputBlocker(AtomicU8::new(0)));
        Ok(INPUT_BLOCKER.wait())
    }

    /// Blocks all input from inputs selected by [InputFlags]. Leaves inputs
    /// that aren't selected as-is.
    pub fn block(&self, inputs: InputFlags) {
        self.0.fetch_or(inputs.bits(), Ordering::Relaxed);
    }

    /// Blocks all input from inputs selected by [InputFlags] and unblocks all
    /// input from inputs that aren't selected.
    ///
    /// This removes blocks added by [block](Self::block) and
    /// [block_only](Self::block_only), but it doesn't remove blocks added by
    /// the game itself (for example because the Steam overlay is active).
    pub fn block_only(&self, inputs: InputFlags) {
        self.0.store(inputs.bits(), Ordering::Relaxed);
    }

    /// Unblocks all input from inputs selected by [InputFlags].
    ///
    /// This removes blocks added by [block](Self::block) and
    /// [block_only](Self::block_only), but it doesn't remove blocks added by
    /// the game itself (for example because the Steam overlay is active).
    pub fn unblock(&self, inputs: InputFlags) {
        // The logical operation we want here is NIMPLY, which is equivalent to
        // A & !B.
        self.0
            .fetch_and(inputs.complement().bits(), Ordering::Relaxed);
    }
}

bitflags! {
    /// A bit flag that indicates a set of input methods to target.
    #[derive(Debug, Clone, Copy)]
    pub struct InputFlags: u8 {
        /// Input from a player's controller.
        const GamePad = 0b001;

        /// Input from a player's keyboard.
        const Keyboard = 0b010;

        /// Input from a player's mouse.
        const Mouse = 0b100;
    }
}
