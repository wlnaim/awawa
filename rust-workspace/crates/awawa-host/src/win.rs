//! Funciones Win32 de la UI del host: atajo global de revocacion, enumeracion de las ventanas del
//! hilo de la UI, geometria/z-order de ventanas y portapapeles.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, RegisterHotKey, UnregisterHotKey, VK_END, VK_PAUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, GetMessageW, GetSystemMetrics, GetWindowRect, GetWindowTextW, HWND_TOPMOST,
    MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, SM_CXSCREEN, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOSIZE, SetWindowPos, WM_HOTKEY, WM_QUIT, WM_USER,
};
use windows::core::BOOL;

const HOTKEY_ID_PAUSE: i32 = 1;
const HOTKEY_ID_CTRL_ALT_END: i32 = 2;

/// Atajo global de revocacion (Pausa y/o Ctrl+Alt+Fin).
///
/// Vive en un hilo propio con su bucle de mensajes: `RegisterHotKey` sin ventana entrega
/// `WM_HOTKEY` a la cola del hilo que lo registro, y el bucle de eventos de la UI no lo vería.
/// Se arma al abrir el modal y se libera al volver a la espera, para no retener la tecla Pausa del
/// sistema mientras no haya una solicitud en curso.
pub struct KillSwitchHotkey {
    pressed: Arc<AtomicBool>,
    thread_id: u32,
    armed: Vec<&'static str>,
    join: Option<JoinHandle<()>>,
}

impl KillSwitchHotkey {
    /// Registra los atajos. `on_press` corre en el hilo del atajo, sin esperar a la UI (detiene
    /// video y entrada al instante); `ctx` se usa despues para despertar la UI.
    pub fn arm(ctx: egui::Context, on_press: Arc<dyn Fn() + Send + Sync>) -> Self {
        let pressed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<(u32, Vec<&'static str>)>();
        let thread_pressed = Arc::clone(&pressed);
        let abandoned = Arc::new(AtomicBool::new(false));
        let thread_abandoned = Arc::clone(&abandoned);
        let mut join = std::thread::Builder::new()
            .name("kill-switch-hotkey".to_string())
            .spawn(move || hotkey_thread(ctx, on_press, thread_pressed, thread_abandoned, tx))
            .ok();
        let (thread_id, armed) = match rx.recv_timeout(Duration::from_secs(2)) {
            // Sin ningun atajo registrado el hilo termina solo: no hay a quien avisar.
            Ok((_, armed)) if armed.is_empty() => (0, armed),
            Ok(started) => started,
            Err(_) => {
                // No se puede avisar a un hilo cuyo id se desconoce: se le indica que se retire
                // si termina de arrancar y no se espera por el.
                abandoned.store(true, Ordering::SeqCst);
                // Si el id llego justo despues del plazo, el hilo pudo pasar ya la comprobacion de
                // `abandoned` con el atajo registrado: se le pide salir de su bucle.
                if let Ok((late_thread_id, _)) = rx.try_recv() {
                    // SAFETY: llamada Win32 sin punteros; si el hilo ya termino, el error se ignora.
                    let _ = unsafe {
                        PostThreadMessageW(late_thread_id, WM_QUIT, WPARAM(0), LPARAM(0))
                    };
                }
                join = None;
                (0, Vec::new())
            }
        };
        Self {
            pressed,
            thread_id,
            armed,
            join,
        }
    }

    /// `true` si al menos un atajo quedo registrado.
    pub fn is_armed(&self) -> bool {
        !self.armed.is_empty()
    }

    /// Teclas registradas, para mostrarlas al usuario (p. ej. "Pausa / Ctrl+Alt+Fin").
    pub fn description(&self) -> String {
        self.armed.join(" / ")
    }

    /// Devuelve y limpia la marca de "se pulso el atajo".
    pub fn take_pressed(&self) -> bool {
        self.pressed.swap(false, Ordering::SeqCst)
    }
}

impl Drop for KillSwitchHotkey {
    fn drop(&mut self) {
        if self.thread_id != 0 {
            // SAFETY: llamada Win32 sin punteros; si el hilo ya termino, el error se ignora.
            let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn hotkey_thread(
    ctx: egui::Context,
    on_press: Arc<dyn Fn() + Send + Sync>,
    pressed: Arc<AtomicBool>,
    abandoned: Arc<AtomicBool>,
    ready: mpsc::Sender<(u32, Vec<&'static str>)>,
) {
    // SAFETY: llamadas Win32 sobre el hilo actual; `msg` es un MSG valido y exclusivo.
    unsafe {
        let thread_id = GetCurrentThreadId();
        let mut msg = MSG::default();
        // Fuerza la creacion de la cola de mensajes antes de publicar el id del hilo.
        let _ = PeekMessageW(&mut msg, None, WM_USER, WM_USER, PM_NOREMOVE);

        let mut armed = Vec::new();
        let mut ids = Vec::new();
        if RegisterHotKey(None, HOTKEY_ID_PAUSE, MOD_NOREPEAT, u32::from(VK_PAUSE.0)).is_ok() {
            armed.push("Pausa");
            ids.push(HOTKEY_ID_PAUSE);
        }
        if RegisterHotKey(
            None,
            HOTKEY_ID_CTRL_ALT_END,
            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
            u32::from(VK_END.0),
        )
        .is_ok()
        {
            armed.push("Ctrl+Alt+Fin");
            ids.push(HOTKEY_ID_CTRL_ALT_END);
        }
        let _ = ready.send((thread_id, armed));
        if ids.is_empty() {
            return;
        }
        if abandoned.load(Ordering::SeqCst) {
            for id in ids {
                let _ = UnregisterHotKey(None, id);
            }
            return;
        }

        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            if msg.message == WM_HOTKEY {
                on_press();
                pressed.store(true, Ordering::SeqCst);
                ctx.request_repaint();
            }
        }
        for id in ids {
            let _ = UnregisterHotKey(None, id);
        }
    }
}

/// Ventanas de primer nivel (incluidas las ocultas y los popups con propietario) del hilo actual.
/// Debe llamarse desde el hilo de la UI: ahi viven la ventana principal, el modal y el banner.
pub fn thread_windows() -> Vec<isize> {
    unsafe extern "system" fn collect(hwnd: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: `lparam` es el `*mut Vec<isize>` que pasa `thread_windows`, vivo durante la llamada.
        let list = unsafe { &mut *(lparam.0 as *mut Vec<isize>) };
        list.push(hwnd.0 as isize);
        BOOL(1)
    }
    let mut list: Vec<isize> = Vec::new();
    // SAFETY: `collect` solo usa el puntero a `list`, que sobrevive a la enumeracion.
    let _ = unsafe {
        EnumThreadWindows(
            GetCurrentThreadId(),
            Some(collect),
            LPARAM(&mut list as *mut Vec<isize> as isize),
        )
    };
    list
}

fn hwnd_from(raw: isize) -> HWND {
    HWND(raw as *mut c_void)
}

/// Titulo de la ventana (vacio si no tiene o ya no existe).
pub fn window_title(raw: isize) -> String {
    let mut buf = [0u16; 128];
    // SAFETY: `buf` es un buffer valido; con un HWND invalido la funcion devuelve 0.
    let len = unsafe { GetWindowTextW(hwnd_from(raw), &mut buf) };
    String::from_utf16_lossy(&buf[..usize::try_from(len).unwrap_or(0).min(buf.len())])
}

/// Rectangulo de la ventana en pixeles fisicos `(left, top, right, bottom)`.
pub fn window_rect(raw: isize) -> Option<(i32, i32, i32, i32)> {
    let mut rect = RECT::default();
    // SAFETY: `rect` es un RECT valido y exclusivo durante la llamada.
    unsafe { GetWindowRect(hwnd_from(raw), &mut rect) }.ok()?;
    Some((rect.left, rect.top, rect.right, rect.bottom))
}

/// Reafirma la ventana por encima de las demas (sin activarla ni cambiar su tamano) y, si se
/// indica `origin`, la coloca en esa esquina superior izquierda en pixeles fisicos.
pub fn place_topmost(raw: isize, origin: Option<(i32, i32)>) {
    let (x, y, flags) = match origin {
        Some((x, y)) => (x, y, SWP_NOSIZE | SWP_NOACTIVATE),
        None => (0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE),
    };
    // SAFETY: llamada Win32 sin punteros; con un HWND invalido solo devuelve error.
    let _ = unsafe { SetWindowPos(hwnd_from(raw), Some(HWND_TOPMOST), x, y, 0, 0, flags) };
}

/// Ancho en pixeles del monitor principal.
pub fn primary_screen_width() -> i32 {
    // SAFETY: llamada Win32 sin precondiciones.
    unsafe { GetSystemMetrics(SM_CXSCREEN) }
}

/// Copia texto al portapapeles del sistema. Devuelve `false` si no se pudo.
pub fn copy_to_clipboard(text: &str) -> bool {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * std::mem::size_of::<u16>();
    // SAFETY: se sigue el protocolo de portapapeles de Win32: el bloque global movible se llena
    // mientras esta bloqueado y, si SetClipboardData lo acepta, pasa a pertenecer al sistema;
    // si no, se libera aqui.
    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }
        let mut stored = false;
        if EmptyClipboard().is_ok()
            && let Ok(hglobal) = GlobalAlloc(GMEM_MOVEABLE, bytes)
        {
            let dst = GlobalLock(hglobal) as *mut u16;
            if dst.is_null() {
                let _ = GlobalFree(Some(hglobal));
            } else {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
                let _ = GlobalUnlock(hglobal);
                if SetClipboardData(u32::from(CF_UNICODETEXT.0), Some(HANDLE(hglobal.0))).is_ok() {
                    stored = true;
                } else {
                    let _ = GlobalFree(Some(hglobal));
                }
            }
        }
        let _ = CloseClipboard();
        stored
    }
}
