use std::fs;
use std::path::Path;
use std::sync::OnceLock;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;
use dashmap::DashMap;
use crate::types::{TtyEventRaw, RAW_TTY_EVENT_SIZE};

pub fn tty_activity() -> &'static DashMap<u32, Instant> {
    static MAP: OnceLock<DashMap<u32, Instant>> = OnceLock::new();
    MAP.get_or_init(DashMap::new)
}

pub struct TtyListener {
    socket_path: String,
}

impl TtyListener {
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_string(),
        }
    }

    #[cfg(unix)]
    pub async fn start(self) -> Result<(), std::io::Error> {
        let path = Path::new(&self.socket_path);

        if path.exists() {
            fs::remove_file(path)?;
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(path)?;

        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o660);
        fs::set_permissions(path, permissions)?;

        println!("[TtyListener] Listening on Unix Domain Socket: {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; RAW_TTY_EVENT_SIZE];
                        loop {
                            match tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await {
                                Ok(_) => {
                                    let raw_event: TtyEventRaw = unsafe {
                                        std::ptr::read_unaligned(buf.as_ptr() as *const TtyEventRaw)
                                    };
                                    tty_activity().insert(raw_event.pid, Instant::now());
                                }
                                Err(_) => {
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[TtyListener] Failed to accept connection: {}", e);
                }
            }
        }
    }

    #[cfg(windows)]
    pub async fn start(self) -> Result<(), std::io::Error> {
        println!("[TtyListener] TTY listener not supported on Windows. Skipping.");
        std::future::pending::<()>().await;
        Ok(())
    }
}
