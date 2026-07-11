use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use crate::types::{TelemetryEventRaw, RAW_EVENT_SIZE};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct IpcServer {
    socket_path: String,
    auth_token: String,
    event_tx: mpsc::Sender<TelemetryEventRaw>,
}

impl IpcServer {
    pub fn new(socket_path: &str, auth_token: &str, event_tx: mpsc::Sender<TelemetryEventRaw>) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            auth_token: auth_token.to_string(),
            event_tx,
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

        println!("[Agent IPC] Listening on Unix Domain Socket: {}", self.socket_path);

        let auth_token = Arc::new(self.auth_token);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let token = Arc::clone(&auth_token);
                    let tx = self.event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, token, tx).await {
                            eprintln!("[Agent IPC] Error handling client connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[Agent IPC] Failed to accept connection: {}", e);
                }
            }
        }
    }

    #[cfg(windows)]
    pub async fn start(self) -> Result<(), std::io::Error> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = if self.socket_path.starts_with("\\\\.\\pipe\\") {
            self.socket_path.clone()
        } else {
            "\\\\.\\pipe\\kinnector-ipc".to_string()
        };
        
        println!("[Agent IPC] Listening on Named Pipe: {}", pipe_name);

        let auth_token = Arc::new(self.auth_token);
        let mut first = true;

        loop {
            let server = match ServerOptions::new()
                .first_pipe_instance(first)
                .create(&pipe_name) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[Agent IPC] Failed to create named pipe: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };
            first = false;

            match server.connect().await {
                Ok(_) => {
                    let token = Arc::clone(&auth_token);
                    let tx = self.event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(server, token, tx).await {
                            eprintln!("[Agent IPC] Error handling client connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[Agent IPC] Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection<S>(
        mut stream: S,
        auth_token: Arc<String>,
        event_tx: mpsc::Sender<TelemetryEventRaw>,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // --- 1. Handshake Phase ---
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_ne_bytes(len_buf) as usize;

        if len > 256 {
            stream.write_all(&[0u8]).await?;
            return Err("Token length abnormally large".into());
        }

        let mut token_bytes = vec![0u8; len];
        stream.read_exact(&mut token_bytes).await?;
        let token_str = std::str::from_utf8(&token_bytes)?;

        let auth_status = if token_str == *auth_token {
            println!("[Agent IPC] Telemetry connection AUTHENTICATED successfully");
            1u8
        } else {
            eprintln!("[Agent IPC] Telemetry connection AUTHENTICATION FAILED");
            0u8
        };

        stream.write_all(&[auth_status]).await?;
        if auth_status == 0 {
            return Ok(());
        }

        // --- 2. Ingestion Phase ---
        let mut buffer = vec![0u8; RAW_EVENT_SIZE];

        loop {
            if let Err(e) = stream.read_exact(&mut buffer).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    println!("[Agent IPC] Telemetry client disconnected cleanly");
                    break;
                }
                return Err(e.into());
            }

            let raw_event = unsafe {
                std::ptr::read_unaligned(buffer.as_ptr() as *const TelemetryEventRaw)
            };

            if event_tx.send(raw_event).await.is_err() {
                eprintln!("[Agent IPC] Event receiver channel closed, shutting down connection");
                break;
            }
        }

        Ok(())
    }
}
