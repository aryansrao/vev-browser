//! macOS NSApplication subclass required by CEF.
//!
//! Chromium's message pump on macOS requires that `NSApp` conforms to
//! `CefAppProtocol` (tracking `isHandlingSendEvent` to avoid event
//! re-entrancy bugs). Tauri's event loop (tao) normally instantiates the
//! shared NSApplication itself, so we must instantiate our subclass *before*
//! anything else touches `NSApplication`; `+sharedApplication` returns the
//! existing instance from then on.
//!
//! Known limitation (documented in README): tao's own NSApplication subclass
//! is displaced by this one, so tao-level default key-equivalent handling is
//! bypassed. Menu/shortcut handling will be wired explicitly in Phase 1.

use cef::application_mac::{CefAppProtocol, CrAppControlProtocol, CrAppProtocol};
use objc2::{
    define_class, extern_methods, msg_send,
    rc::Retained,
    runtime::{Bool, NSObjectProtocol},
    ClassType, DefinedClass, MainThreadMarker,
};
use objc2_app_kit::{NSApp, NSApplication, NSEvent};
use std::cell::Cell;

/// Instance variables of `VevApplication`.
#[derive(Default)]
pub struct VevApplicationIvars {
    handling_send_event: Cell<Bool>,
}

define_class!(
    /// An `NSApplication` subclass conforming to `CefAppProtocol`, which CEF
    /// requires of the browser-process application object on macOS.
    #[unsafe(super(NSApplication))]
    #[ivars = VevApplicationIvars]
    pub struct VevApplication;

    impl VevApplication {
        #[unsafe(method(sendEvent:))]
        unsafe fn send_event(&self, event: &NSEvent) {
            let was_sending_event = self.is_handling_send_event();
            if !was_sending_event {
                self.set_handling_send_event(true);
            }

            let _: () = msg_send![super(self), sendEvent: event];

            if !was_sending_event {
                self.set_handling_send_event(false);
            }
        }
    }

    unsafe impl NSObjectProtocol for VevApplication {}

    unsafe impl CrAppControlProtocol for VevApplication {
        #[unsafe(method(setHandlingSendEvent:))]
        unsafe fn _set_handling_send_event(&self, handling_send_event: Bool) {
            self.ivars().handling_send_event.set(handling_send_event);
        }
    }

    unsafe impl CrAppProtocol for VevApplication {
        #[unsafe(method(isHandlingSendEvent))]
        unsafe fn _is_handling_send_event(&self) -> Bool {
            self.ivars().handling_send_event.get()
        }
    }

    unsafe impl CefAppProtocol for VevApplication {}
);

impl VevApplication {
    extern_methods! {
        #[unsafe(method(sharedApplication))]
        fn shared_application() -> Retained<Self>;

        #[unsafe(method(setHandlingSendEvent:))]
        fn set_handling_send_event(&self, handling_send_event: bool);

        #[unsafe(method(isHandlingSendEvent))]
        fn is_handling_send_event(&self) -> bool;
    }
}

/// Instantiate the shared `VevApplication`. Must run on the main thread
/// before tauri/tao (or anything else) creates the shared NSApplication.
pub fn install() -> Result<(), &'static str> {
    let mtm = MainThreadMarker::new().ok_or("must be called on the main thread")?;
    let _ = VevApplication::shared_application();

    // If NSApp was touched before this point it will not be a VevApplication
    // and CEF event handling would be subtly broken — fail loudly instead.
    if !NSApp(mtm).isKindOfClass(VevApplication::class()) {
        return Err("NSApp is not a VevApplication; NSApplication was initialized too early");
    }
    Ok(())
}
