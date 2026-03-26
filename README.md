tapo-camera-privacy-control
===========================

A lightweight Rust library and binary to control Tapo camera privacy mode (lens mask) over the local LAN.

Features
- Login (secure and insecure modes)
- Set and get privacy mode (lens mask)
- Uses your Tapo cloud account credentials (see note below)

Quick library usage example
---------

```rust
use tapo_camera_privacy_control::TapoCamera;
use tapo_camera_privacy_control::PrivacyMode;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cam = TapoCamera::new("192.168.1.42", "admin", "password")?;

    // NOTE: the username/password here must be your Tapo cloud account
    // credentials (the same account you use with the Tapo mobile app),
    // not any local/device-only admin account. The library performs the
    // same authentication flow as the camera expects for cloud-linked
    // credentials.

    // Use reqwest default timeout (do nothing), or set a custom timeout:
    cam.set_timeout(Some(Duration::from_secs(4)))?;

    cam.login().await?;

    cam.set_privacy_mode(PrivacyMode::Off).await?;

    let mode = cam.get_privacy_mode().await?;
    println!("privacy mode is {}", mode);

    Ok(())
}
```

CLI usage
---------

The crate includes a `tapo-camera-privacy-control` binary. Credentials can be passed via
flags or environment variables.

```bash
# Check current privacy mode
tapo-camera-privacy-control -i 192.168.1.42 -u 'your@email.com' -p 'your_password' status

# Enable privacy mode (cover the lens)
tapo-camera-privacy-control -i 192.168.1.42 -u 'your@email.com' -p 'your_password' on

# Disable privacy mode (uncover the lens)
tapo-camera-privacy-control -i 192.168.1.42 -u 'your@email.com' -p 'your_password' off

# Or use environment variables
export TAPO_CAMERA_IP=192.168.1.42
export TAPO_USERNAME='your@email.com'
export TAPO_PASSWORD='your_password'
tapo-camera-privacy-control status
```