use std::env;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

const MAX_PORT: u16 = 1024;

fn main() {
    let args: Vec<String> = env::args().collect();

    let target_host = if args.len() > 1 {
        &args[1]
    } else {
        "192.168.100.250"
    };

    println!("Resolving domain {}...", target_host);

    let target_addr = match format!("{}:80", target_host).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => {
                eprintln!("Error: Could not resolve IP for target host.");
                return;
            }
        },
        Err(e) => {
            eprintln!("DNS resolution failed for {}: {}", target_host, e);
            return;
        }
    };

    println!("Scanning {} ({}) across ports 1-{}...", target_host, target_addr, MAX_PORT);
    println!("--------------------------------------------------");

    let (tx, rx) = channel();

    for port in 1..=MAX_PORT {
        let tx_clone = tx.clone();
        thread::spawn(move || {
            scan_port(tx_clone, target_addr, port);
        });
    }

    drop(tx);

    let mut open_ports: Vec<u16> = Vec::new();
    for port in rx {
        open_ports.push(port);
    }

    open_ports.sort();

    if open_ports.is_empty() {
        println!("No open ports found.");
    } else {
        for port in open_ports {
            let service_name = get_service_name(port);
            println!("Port {:<5} {:<12} OPEN", port, format!("({})", service_name));
        }
    }

    println!("--------------------------------------------------");
}

fn scan_port(tx: Sender<u16>, ip: IpAddr, port: u16) {
    let address = SocketAddr::new(ip, port);
    let timeout = Duration::from_millis(1000);

    if TcpStream::connect_timeout(&address, timeout).is_ok() {
        let _ = tx.send(port);
    }
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        8080 => "HTTP-Alt",
        _ => "Unknown", // Wildcard arm catches all remaining numbers (0..19, 24, 26..52, etc.)
    }
}
