//! CEF helper process executable.
//!
//! On macOS, Chromium spawns its renderer/GPU/plugin/utility/service-worker
//! sub-processes from separate helper .app bundles inside the main bundle's
//! Frameworks directory. This binary is the entry point for all of them; CEF
//! decides the process type from the command line passed by the browser
//! process.
//!
//! Fingerprint resistance is injected here, in the render process, via a
//! RenderProcessHandler: `on_context_created` fires for EVERY V8 context — the
//! main frame, cross-origin iframes, dedicated/shared workers, AND service
//! workers — before any page/worker script runs. Injecting at this layer (not
//! only the browser-process `on_load_start`) is what closes the worker /
//! service-worker fingerprint leaks CreepJS exploits: a worker was otherwise a
//! fresh global that saw the real GPU, core count, and platform.

use cef::{args::Args, rc::*, *};

wrap_render_process_handler! {
    struct VevRenderProcessHandler;

    impl RenderProcessHandler {
        fn on_context_created(
            &self,
            _browser: Option<&mut Browser>,
            _frame: Option<&mut Frame>,
            context: Option<&mut V8Context>,
        ) {
            // Run the spoof in this context before its own scripts. The script
            // is guarded (self.__vevFp) so a double-inject with the browser-
            // process on_load_start path is a no-op, and it is worker-safe
            // (typeof guards for window/document/screen).
            if let Some(ctx) = context {
                let _ = ctx.eval(
                    Some(&CefString::from(vev_fingerprint::spoof_js())),
                    Some(&CefString::from("vev://fingerprint")),
                    0,
                    None,
                    None,
                );
            }
        }
    }
}

wrap_app! {
    struct VevHelperApp {}

    impl App {
        fn render_process_handler(&self) -> Option<RenderProcessHandler> {
            Some(VevRenderProcessHandler::new())
        }
    }
}

fn main() {
    let args = Args::new();

    // The macOS V2 sandbox must be initialized before the CEF framework is
    // loaded, using the exact argc/argv the process was launched with.
    #[cfg(all(target_os = "macos", feature = "sandbox"))]
    let _sandbox = {
        let mut sandbox = cef::sandbox::Sandbox::new();
        sandbox.initialize(args.as_main_args());
        sandbox
    };

    #[cfg(target_os = "macos")]
    let _loader = {
        let loader = library_loader::LibraryLoader::new(
            &std::env::current_exe().unwrap_or_default(),
            true,
        );
        if !loader.load() {
            // Cannot do anything useful without the framework; exiting is the
            // only option in a helper process.
            std::process::exit(1);
        }
        loader
    };

    // Initialize the CEF API version before any other CEF call.
    let _ = api_hash(sys::CEF_API_VERSION_LAST, 0);

    let mut app = VevHelperApp::new();
    execute_process(
        Some(args.as_main_args()),
        Some(&mut app),
        std::ptr::null_mut(),
    );
}
