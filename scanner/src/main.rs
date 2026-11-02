use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use rand::Rng;

// --- Domains na vitu ka hizo ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVector {
    SqlInjection,
    ZeroDayExploit,
    CredentialStuffing,
    PhishingCampaign,
}

#[derive(Debug, Clone)]
pub struct AttackEvent {
    pub vector: AttackVector,
    pub payload_hash: String,
    pub severity: u8, // 1 - 10
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefenseOutcome {
    Allowed,
    LoggedAndAlerted,
    Blocked,
}

#[derive(Debug)]
pub struct ThreatTelemetry {
    pub active_threat_level: u32,
    pub blocked_attacks: u64,
    pub successful_breaches: u64,
}

// --- Hi Part Ni Ya Blue Team Engine ---

pub struct BlueTeamEngine {
    telemetry: Arc<Mutex<ThreatTelemetry>>,
    known_signatures: HashMap<String, AttackVector>,
}

impl BlueTeamEngine {
    pub fn new() -> Self {
        let mut known_signatures = HashMap::new();
        // Pre-loaded IOCs (Indicators of Compromise)
        known_signatures.insert("hash_sqli_known".into(), AttackVector::SqlInjection);
        known_signatures.insert("hash_phish_known".into(), AttackVector::PhishingCampaign);

        Self {
            telemetry: Arc::new(Mutex::new(ThreatTelemetry {
                active_threat_level: 0,
                blocked_attacks: 0,
                successful_breaches: 0,
            })),
            known_signatures,
        }
    }

    pub fn analyze_and_defend(&mut self, event: &AttackEvent) -> DefenseOutcome {
        let mut telemetry = self.telemetry.lock().unwrap();

        // 1. Signature Matching (Fast Path)
        if self.known_signatures.contains_key(&event.payload_hash) {
            telemetry.blocked_attacks += 1;
            return DefenseOutcome::Blocked;
        }

        // 2. Behavioral Threat Assessment (Heuristics)
        let risk_score = match (event.vector, event.severity) {
            (AttackVector::ZeroDayExploit, s) if s > 7 => 95,
            (AttackVector::SqlInjection, s) if s > 5 => 70,
            (AttackVector::CredentialStuffing, s) => s as u32 * 8,
            _ => 30,
        };

        telemetry.active_threat_level += risk_score;

        // 3. Automated Mitigation Logic
        if risk_score >= 75 {
            telemetry.blocked_attacks += 1;
            DefenseOutcome::Blocked
        } else if risk_score >= 40 {
            DefenseOutcome::LoggedAndAlerted
        } else {
            telemetry.successful_breaches += 1;
            DefenseOutcome::Allowed
        }
    }

    pub fn get_telemetry_handle(&self) -> Arc<Mutex<ThreatTelemetry>> {
        Arc::clone(&self.telemetry)
    }
}

// --- Wasee wa Red Team ---

pub struct RedTeamOperator {
    tx: mpsc::Sender<AttackEvent>,
}

impl RedTeamOperator {
    pub fn new(tx: mpsc::Sender<AttackEvent>) -> Self {
        Self { tx }
    }

    pub async fn launch_campaign(&self, rounds: usize) {
        let mut rng = rand::thread_rng();

        for i in 0..rounds {
            let vector = match rng.gen_range(0..4) {
                0 => AttackVector::SqlInjection,
                1 => AttackVector::ZeroDayExploit,
                2 => AttackVector::CredentialStuffing,
                _ => AttackVector::PhishingCampaign,
            };

            // Random payload signatures to mimic zero-days vs known hashes
            let payload_hash = if rng.gen_bool(0.3) {
                "hash_sqli_known".to_string()
            } else {
                format!("zero_day_payload_{}", rng.gen_range(1000..9999))
            };

            let event = AttackEvent {
                vector,
                payload_hash,
                severity: rng.gen_range(1..=10),
            };

            println!("[RED TEAM] Launching {:?} (Severity: {})", event.vector, event.severity);
            
            if self.tx.send(event).await.is_err() {
                eprintln!("[RED TEAM] Telemetry stream closed.");
                break;
            }

            sleep(Duration::from_millis(300)).await;
        }
    }
}



pub async fn launch_campaign(&self, rounds: usize) {
    for _ in 0..rounds {
        // rng is created and dropped inside this block, before any .await
        let event = {
            let mut rng = rand::thread_rng();

            let vector = match rng.gen_range(0..4) {
                0 => AttackVector::SqlInjection,
                1 => AttackVector::ZeroDayExploit,
                2 => AttackVector::CredentialStuffing,
                _ => AttackVector::PhishingCampaign,
            };

            let payload_hash = if rng.gen_bool(0.3) {
                "hash_sqli_known".to_string()
            } else {
                format!("zero_day_payload_{}", rng.gen_range(1000..9999))
            };

            AttackEvent {
                vector,
                payload_hash,
                severity: rng.gen_range(1..=10),
            }
        };

        println!("[RED TEAM] Launching {:?} (Severity: {})", event.vector, event.severity);

        if self.tx.send(event).await.is_err() {
            eprintln!("[RED TEAM] Telemetry stream closed.");
            break;
        }

        sleep(Duration::from_millis(300)).await;
    }
}

// --- Main Part ---

#[tokio::main]
async fn main() {
    println!("=== Starting Threat Assessment Engine ===\n");

    // Async MPSC Channel for Telemetry Streaming
    let (tx, mut rx) = mpsc::channel::<AttackEvent>(32);

    let red_team = RedTeamOperator::new(tx);
    let mut blue_team = BlueTeamEngine::new();
    let telemetry_handle = blue_team.get_telemetry_handle();

    // Spawn Red Team offensive worker task
    let red_task = tokio::spawn(async move {
        red_team.launch_campaign(8).await;
    });

    // Main event loop processing incoming threats (Blue Team SIEM)
    while let Some(event) = rx.recv().await {
        let outcome = blue_team.analyze_and_defend(&event);
        
        match outcome {
            DefenseOutcome::Blocked => {
                println!("  └─> [BLUE TEAM] 🛑 BLOCKED {:?}", event.vector);
            }
            DefenseOutcome::LoggedAndAlerted => {
                println!("  └─> [BLUE TEAM] ⚠️  ALERT LOGGED for {:?}", event.vector);
            }
            DefenseOutcome::Allowed => {
                println!("  └─> [BLUE TEAM] 💥 BREACH DETECTED via {:?}", event.vector);
            }
        }
    }

    red_task.await.unwrap();

    // Final Assessment Report
    let final_stats = telemetry_handle.lock().unwrap();
    println!("\n=== Final Assessment Report ===");
    println!("Total Threat Level Accumulation : {}", final_stats.active_threat_level);
    println!("Blocked Attacks                 : {}", final_stats.blocked_attacks);
    println!("Successful Breaches             : {}", final_stats.successful_breaches);
}