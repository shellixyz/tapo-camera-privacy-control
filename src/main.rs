#![warn(clippy::pedantic)]
use clap::{Parser, Subcommand};
use tapo_camera_privacy_control::{PrivacyMode, TapoCamera};

#[derive(Parser)]
#[command(
    name = "tapo-camera-privacy-control",
    about = "Control Tapo camera privacy mode (lens mask)"
)]
struct Cli {
    /// Camera IP address
    #[arg(short, long, env = "TAPO_CAMERA_IP")]
    ip: String,

    /// Camera account username
    #[arg(short, long, env = "TAPO_USERNAME")]
    username: String,

    /// Camera account password
    #[arg(short, long, env = "TAPO_PASSWORD")]
    password: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enable privacy mode (cover the lens)
    On,
    /// Disable privacy mode (uncover the lens)
    Off,
    /// Get current privacy mode status
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut camera = TapoCamera::new(&cli.ip, &cli.username, &cli.password)?;
    camera.login().await?;

    match cli.command {
        Command::On => {
            camera.set_privacy_mode(PrivacyMode::On).await?;
            println!("Privacy mode enabled (lens covered)");
        }
        Command::Off => {
            camera.set_privacy_mode(PrivacyMode::Off).await?;
            println!("Privacy mode disabled (lens uncovered)");
        }
        Command::Status => {
            let mode = camera.get_privacy_mode().await?;
            println!("Privacy mode: {mode}");
        }
    }

    Ok(())
}
