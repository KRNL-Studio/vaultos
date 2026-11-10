//! The few OS services the desktop needs beyond Tauri: Touch ID, a clipboard copy that
//! clipboard managers and Universal Clipboard skip, and whether the screen is locked.

use std::sync::Mutex;
#[cfg(not(target_os = "macos"))]
use vaultos_core::crypto::sha256;

/// What a copy left on the clipboard, so clearing never removes something copied after it.
#[derive(Debug)]
enum Copied {
    /// macOS: the pasteboard's change count right after our write.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Change(isize),
    /// Elsewhere: a digest of the text.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Digest([u8; 32]),
}

#[derive(Default)]
pub struct Clipboard {
    copied: Mutex<Option<Copied>>,
    #[cfg(not(target_os = "macos"))]
    board: Mutex<Option<arboard::Clipboard>>,
}

/// Never prints what was copied.
impl std::fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clipboard").finish_non_exhaustive()
    }
}

impl Clipboard {
    /// Copies text. Returns "concealed" when macOS marked it concealed, transient and
    /// current-host-only, else "plain".
    pub fn write(&self, text: &str) -> Result<&'static str, String> {
        self.clear();
        let (copied, mode) = self.put(text)?;
        *self.copied.lock().unwrap_or_else(|e| e.into_inner()) = Some(copied);
        Ok(mode)
    }

    /// Writes ordinary text (a username), which needs no clearing.
    pub fn write_plain(&self, text: &str) -> Result<(), String> {
        self.put_plain(text)
    }

    /// Clears our copy if it is still on the clipboard.
    pub fn clear(&self) {
        let Some(copied) = self.copied.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        match copied {
            Copied::Change(n) => mac::clear_if(n),
            Copied::Digest(d) => self.clear_if_digest(d),
        }
    }

    #[cfg(target_os = "macos")]
    fn put(&self, text: &str) -> Result<(Copied, &'static str), String> {
        match mac::write_concealed(text) {
            Some(n) => Ok((Copied::Change(n), "concealed")),
            None => Err("The clipboard could not be written".into()),
        }
    }

    #[cfg(target_os = "macos")]
    fn put_plain(&self, text: &str) -> Result<(), String> {
        mac::write_plain(text)
            .then_some(())
            .ok_or("The clipboard could not be written".into())
    }

    #[cfg(target_os = "macos")]
    fn clear_if_digest(&self, _: [u8; 32]) {}

    #[cfg(not(target_os = "macos"))]
    fn with_board<R>(&self, f: impl FnOnce(&mut arboard::Clipboard) -> R) -> Result<R, String> {
        let mut slot = self.board.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(arboard::Clipboard::new().map_err(|_| "The clipboard is unavailable")?);
        }
        Ok(f(slot.as_mut().ok_or("The clipboard is unavailable")?))
    }

    #[cfg(not(target_os = "macos"))]
    fn put(&self, text: &str) -> Result<(Copied, &'static str), String> {
        self.put_plain(text)?;
        Ok((Copied::Digest(sha256(text.as_bytes())), "plain"))
    }

    #[cfg(not(target_os = "macos"))]
    fn put_plain(&self, text: &str) -> Result<(), String> {
        self.with_board(|b| b.set_text(text.to_owned()))?
            .map_err(|_| "The clipboard could not be written".into())
    }

    #[cfg(not(target_os = "macos"))]
    fn clear_if_digest(&self, digest: [u8; 32]) {
        let _ = self.with_board(|b| {
            if b.get_text().is_ok_and(|t| sha256(t.as_bytes()) == digest) {
                let _ = b.clear();
            }
        });
    }
}

#[cfg(not(target_os = "macos"))]
mod mac {
    pub fn clear_if(_: isize) {}
}

pub fn touch_id_available() -> bool {
    #[cfg(target_os = "macos")]
    return mac::touch_id_available();
    #[cfg(not(target_os = "macos"))]
    false
}

/// Shows the system Touch ID sheet ("VaultOS is trying to <reason>") and blocks until it is
/// answered. Call it off the main thread.
pub fn touch_id_prompt(reason: &str) -> bool {
    #[cfg(target_os = "macos")]
    return mac::touch_id_prompt(reason);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        false
    }
}

/// Runs `f` just before the Mac sleeps or switches to another user. Elsewhere the watch loop
/// notices a sleep from the clock after waking.
pub fn on_sleep(f: impl Fn() + Send + Sync + 'static) {
    #[cfg(target_os = "macos")]
    mac::on_sleep(f);
    #[cfg(not(target_os = "macos"))]
    let _ = f;
}

/// Whether the login session's screen is locked; `None` when that cannot be told.
pub fn screen_locked() -> Option<bool> {
    #[cfg(target_os = "macos")]
    return mac::screen_locked();
    #[cfg(not(target_os = "macos"))]
    linux::screen_locked()
}

#[cfg(target_os = "macos")]
pub(crate) mod mac {
    use block2::RcBlock;
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;
    use objc2::rc::Retained;
    use objc2::runtime::{Bool, ProtocolObject};
    use objc2_app_kit::{
        NSPasteboard, NSPasteboardContentsOptions, NSPasteboardItem, NSPasteboardTypeString,
        NSPasteboardWriting, NSWorkspace, NSWorkspaceSessionDidResignActiveNotification,
        NSWorkspaceWillSleepNotification,
    };
    use objc2_foundation::{NSArray, NSData, NSError, NSNotification, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::ptr::NonNull;

    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

    pub fn touch_id_available() -> bool {
        // SAFETY: a fresh context; canEvaluatePolicy only reads device state.
        unsafe { LAContext::new().canEvaluatePolicy_error(POLICY) }.is_ok()
    }

    pub fn touch_id_prompt(reason: &str) -> bool {
        evaluated(reason).is_some()
    }

    /// Asks for Touch ID and returns the confirmed context: a Secure Enclave key bound to
    /// biometry accepts it without asking again.
    pub fn evaluated(reason: &str) -> Option<Retained<LAContext>> {
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let reply = RcBlock::new(move |ok: Bool, _: *mut NSError| {
            let _ = tx.send(ok.as_bool());
        });
        // SAFETY: the context lives until the reply arrives (we wait for it below), and the
        // reply block only sends on a channel.
        let context = unsafe { LAContext::new() };
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                POLICY,
                &NSString::from_str(reason),
                &reply,
            );
        }
        rx.recv().unwrap_or(false).then_some(context)
    }

    fn item(text: &str, concealed: bool) -> Option<Retained<NSPasteboardItem>> {
        let item = NSPasteboardItem::new();
        // SAFETY: plain AppKit calls on objects we own.
        unsafe {
            if !item.setString_forType(&NSString::from_str(text), NSPasteboardTypeString) {
                return None;
            }
            if concealed {
                let empty = NSData::new();
                for t in [
                    "org.nspasteboard.ConcealedType",
                    "org.nspasteboard.TransientType",
                ] {
                    if !item.setData_forType(&empty, &NSString::from_str(t)) {
                        return None;
                    }
                }
            }
        }
        Some(item)
    }

    fn write(text: &str, concealed: bool) -> Option<isize> {
        let item = item(text, concealed)?;
        let board = NSPasteboard::generalPasteboard();
        if concealed {
            board.prepareForNewContentsWithOptions(NSPasteboardContentsOptions::CurrentHostOnly);
        } else {
            board.clearContents();
        }
        let writer: Retained<ProtocolObject<dyn NSPasteboardWriting>> =
            ProtocolObject::from_retained(item);
        if !board.writeObjects(&NSArray::from_retained_slice(&[writer])) {
            return None;
        }
        Some(board.changeCount())
    }

    /// Concealed and transient (clipboard managers skip it), current host only (Universal
    /// Clipboard does not send it to other devices).
    pub fn write_concealed(text: &str) -> Option<isize> {
        write(text, true)
    }

    pub fn write_plain(text: &str) -> bool {
        write(text, false).is_some()
    }

    pub fn clear_if(change_count: isize) {
        let board = NSPasteboard::generalPasteboard();
        if board.changeCount() == change_count {
            board.clearContents();
        }
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    pub fn screen_locked() -> Option<bool> {
        // SAFETY: returns a dictionary we own (create rule) or null outside a GUI session.
        let raw = unsafe { CGSessionCopyCurrentDictionary() };
        if raw.is_null() {
            return None;
        }
        let dict: CFDictionary<CFString, core_foundation::base::CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(raw) };
        let locked = dict
            .find(CFString::from_static_string("CGSSessionScreenIsLocked"))
            .and_then(|v| v.downcast::<CFBoolean>())
            .is_some_and(bool::from);
        Some(locked)
    }

    pub fn on_sleep(f: impl Fn() + Send + Sync + 'static) {
        let f = std::sync::Arc::new(f);
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: AppKit's notification names are immutable statics.
        let names = unsafe {
            [
                NSWorkspaceWillSleepNotification,
                NSWorkspaceSessionDidResignActiveNotification,
            ]
        };
        for name in names {
            let f = f.clone();
            let block = RcBlock::new(move |_: NonNull<NSNotification>| f());
            // SAFETY: no sender filter and no queue, so the block runs on the posting thread
            // (the main thread); it holds only a Send + Sync closure. The observer stays for
            // the app's lifetime.
            let token = unsafe {
                center.addObserverForName_object_queue_usingBlock(Some(name), None, None, &block)
            };
            std::mem::forget(token);
        }
    }

    /// What macOS posts before sleeping, for the UI test.
    #[cfg(feature = "ui-test")]
    pub fn post_will_sleep() {
        let center = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: an AppKit notification name with no sender.
        unsafe { center.postNotificationName_object(NSWorkspaceWillSleepNotification, None) };
    }
}

#[cfg(not(target_os = "macos"))]
mod linux {
    use std::process::Command;

    /// logind's LockedHint for this session, which screen lockers set.
    pub fn screen_locked() -> Option<bool> {
        let id = std::env::var("XDG_SESSION_ID").ok()?;
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        let out = Command::new("loginctl")
            .args(["show-session", &id, "-p", "LockedHint", "--value"])
            .output()
            .ok()?;
        match String::from_utf8_lossy(&out.stdout).trim() {
            "yes" => Some(true),
            "no" => Some(false),
            _ => None,
        }
    }
}
