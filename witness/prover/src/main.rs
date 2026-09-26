//! TLSNotary prover for a tlsn-extension style verifier ("witness") server.
//!
//! Protocol (all over WebSocket):
//!   1. `/session`                  -> {"type":"register",...}  <- {"type":"session_registered","sessionId"}
//!   2. `/verifier?sessionId=…`     TLSNotary prover <-> verifier (proxy or MPC mode)
//!   3. `/session`                  -> {"type":"reveal_config",...}
//!   4. `/session`                  <- {"type":"session_completed",...} (with signed receipt)
//!
//! In proxy mode the verifier itself opens the TCP connection to the target
//! server; in MPC mode the prover reaches it through `/proxy?token=<host>`.

use std::{future::IntoFuture, path::PathBuf, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use async_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use k256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::info;
use ws_stream_tungstenite::WsStream;

use tlsn::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::{DnsName, ServerName},
    webpki::RootCertStore,
    Session,
};

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

#[derive(Clone, Copy, ValueEnum, Debug)]
enum Mode {
    /// Notary connects to the target itself (stronger, cheaper).
    Proxy,
    /// Classic MPC-TLS; prover reaches the target via the notary's /proxy bridge.
    Mpc,
}

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// HTTPS URL to notarize.
    #[arg(long)]
    url: String,
    /// Notary base URL.
    #[arg(long, default_value = "https://pavoltravnik.witness.directcase.ai")]
    notary: String,
    /// Output directory.
    #[arg(long)]
    out: PathBuf,
    #[arg(long, value_enum, default_value_t = Mode::Proxy)]
    mode: Mode,
    #[arg(long, default_value_t = 4096)]
    max_sent: usize,
    #[arg(long, default_value_t = 1 << 20)]
    max_recv: usize,
    /// Abort after this many seconds.
    #[arg(long, default_value_t = 300)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tlsn=warn,mpc_tls=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.out)?;
    tokio::time::timeout(Duration::from_secs(args.timeout), run(&args))
        .await
        .map_err(|_| anyhow!("timed out after {}s", args.timeout))?
}

async fn run(args: &Args) -> Result<()> {
    let target = url::Url::parse(&args.url)?;
    if target.scheme() != "https" {
        bail!("only https URLs can be notarized");
    }
    let host = target.host_str().ok_or_else(|| anyhow!("URL has no host"))?.to_string();
    let path = &target[url::Position::BeforePath..url::Position::AfterQuery];
    let notary = url::Url::parse(&args.notary)?;
    let ws_base = format!(
        "{}://{}",
        if notary.scheme() == "https" { "wss" } else { "ws" },
        notary.host_str().ok_or_else(|| anyhow!("notary URL has no host"))?
    );
    let http = reqwest::Client::new();

    // Notary identity at the time of the session.
    let info: Value = http.get(notary.join("/info")?).send().await?.json().await?;
    let keys: Value = http.get(notary.join("/keys.json")?).send().await?.json().await?;
    std::fs::write(args.out.join("notary-info.json"), serde_json::to_string_pretty(&info)?)?;
    std::fs::write(args.out.join("notary-keys.json"), serde_json::to_string_pretty(&keys)?)?;

    // 1. Register a session.
    // The final message embeds the whole transcript (several times for binary
    // bodies), so lift tungstenite's 16 MB frame / 64 MB message limits.
    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = None;
    ws_config.max_frame_size = None;
    let (session_ws, _) = async_tungstenite::tokio::connect_async_with_config(
        format!("{ws_base}/session"),
        Some(ws_config),
    )
    .await
        .context("connecting to /session")?;
    let (mut session_tx, mut session_rx) = session_ws.split();
    session_tx
        .send(Message::Text(
            json!({
                "type": "register",
                "maxRecvData": args.max_recv,
                "maxSentData": args.max_sent,
                "sessionData": { "url": args.url, "tool": "witness-prover" },
            })
            .to_string()
            .into(),
        ))
        .await?;
    let session_id = loop {
        match session_rx.next().await {
            Some(Ok(Message::Text(t))) => {
                let v: Value = serde_json::from_str(&t)?;
                match v["type"].as_str() {
                    Some("session_registered") => {
                        break v["sessionId"].as_str().unwrap_or_default().to_string()
                    }
                    Some("error") => bail!("notary refused session: {}", v["message"]),
                    _ => {}
                }
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => return Err(e.into()),
            None => bail!("session socket closed before registration"),
        }
    };
    info!("session {session_id}");

    // Keep reading the session socket in the background (answers pings,
    // collects the final result).
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<Value>();
    let reader = tokio::spawn(async move {
        while let Some(msg) = session_rx.next().await {
            match msg {
                Ok(Message::Text(t)) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        let _ = msg_tx.send(v);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = msg_tx.send(json!({"type": "error", "message": format!("session socket: {e}")}));
                    break;
                }
            }
        }
    });

    // 2. Run the prover.
    let (verifier_ws, _) = async_tungstenite::tokio::connect_async(format!(
        "{ws_base}/verifier?sessionId={session_id}"
    ))
    .await
    .context("connecting to /verifier")?;
    let session = Session::new(WsStream::new(verifier_ws));
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle.new_prover(ProverConfig::builder().build()?)?;
    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(host.clone().try_into()?))
        .root_store(RootCertStore::mozilla())
        .build()?;
    let started = chrono::Utc::now();

    let request = Request::builder()
        .uri(path)
        .header("Host", &host)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Language", "cs-CZ,cs;q=0.9,en;q=0.8")
        // TLSNotary tooling cannot decompress.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())?;

    macro_rules! exchange {
        ($tls:expr, $prover:expr) => {{
            let tls = TokioIo::new($tls.compat());
            let prover_task = tokio::spawn($prover.into_future());
            let (mut sender, conn) = hyper::client::conn::http1::handshake(tls).await?;
            tokio::spawn(conn);
            let http_exchange = async move {
                let resp = sender.send_request(request).await?;
                let status = resp.status();
                resp.into_body().collect().await?;
                anyhow::Ok(status)
            };
            tokio::pin!(http_exchange);
            tokio::pin!(prover_task);
            // If TLS fails the HTTP exchange never completes: race both.
            tokio::select! {
                r = &mut http_exchange => { let s = r?; (s, prover_task.await??) }
                p = &mut prover_task => {
                    let p = p?.context("TLS session failed")?;
                    (http_exchange.await?, p)
                }
            }
        }};
    }

    let (status, mut prover) = match args.mode {
        Mode::Proxy => {
            let prover = prover
                .commit(
                    ProxyTlsConfig::builder()
                        .server_name(DnsName::try_from(host.as_str())?)
                        .build()?,
                )
                .await?;
            let (tls, prover) = prover.connect(tls_config)?;
            exchange!(tls, prover)
        }
        Mode::Mpc => {
            let prover = prover
                .commit(
                    MpcTlsConfig::builder()
                        .max_sent_data(args.max_sent)
                        .max_recv_data(args.max_recv)
                        .build()?,
                )
                .await?;
            let (proxy_ws, _) = async_tungstenite::tokio::connect_async(format!(
                "{ws_base}/proxy?token={host}"
            ))
            .await
            .context("connecting to /proxy")?;
            let (tls, prover) = prover.connect(tls_config, WsStream::new(proxy_ws))?;
            exchange!(tls, prover)
        }
    };
    info!("server responded {status}");

    let sent = prover.transcript().sent().to_vec();
    let recv = prover.transcript().received().to_vec();
    info!("transcript: sent {} B, received {} B", sent.len(), recv.len());

    let mut prove = ProveConfig::builder(prover.transcript());
    prove.server_identity();
    prove.reveal_sent(&(0..sent.len()))?;
    prove.reveal_recv(&(0..recv.len()))?;
    prover.prove(&prove.build()?).await?;
    prover.close().await?;
    handle.close();
    driver_task.await??;

    // 3. Tell the notary which ranges were revealed.
    let all = |t: &str, end: usize| {
        json!([{ "start": 0, "end": end,
                 "handler": { "type": t, "part": "ALL", "action": { "kind": "REVEAL" } } }])
    };
    session_tx
        .send(Message::Text(
            json!({ "type": "reveal_config", "sent": all("SENT", sent.len()), "recv": all("RECV", recv.len()) })
                .to_string()
                .into(),
        ))
        .await?;

    // 4. Wait for the result.
    let completed = loop {
        let v = msg_rx.recv().await.ok_or_else(|| anyhow!("session closed without result"))?;
        match v["type"].as_str() {
            Some("session_completed") => break v,
            Some("error") => bail!("notary reported error: {}", v["message"]),
            _ => {}
        }
    };
    let _ = session_tx.close().await;
    reader.abort();
    let finished = chrono::Utc::now();

    std::fs::write(args.out.join("transcript-sent.bin"), &sent)?;
    std::fs::write(args.out.join("transcript-recv.bin"), &recv)?;
    std::fs::write(args.out.join("session-result.json"), serde_json::to_string_pretty(&completed)?)?;

    // 5. Check the signed receipt, locally and with the notary.
    let receipt = find_receipt(&completed);
    let local = match &receipt {
        Some(r) => verify_receipt(r, &keys, &sent, &recv),
        None => Err(anyhow!("session_completed carried no receipt")),
    };
    let remote: Value = match &receipt {
        Some(r) => http
            .post(notary.join("/verify")?)
            .json(r)
            .send()
            .await?
            .json()
            .await
            .unwrap_or(Value::Null),
        None => Value::Null,
    };
    if let Some(r) = &receipt {
        std::fs::write(args.out.join("receipt.json"), serde_json::to_string_pretty(r)?)?;
    }

    let summary = json!({
        "url": args.url,
        "mode": format!("{:?}", args.mode).to_lowercase(),
        "notary": args.notary,
        "session_id": session_id,
        "http_status": status.as_u16(),
        "sent_bytes": sent.len(),
        "recv_bytes": recv.len(),
        "sent_sha256": hex::encode(Sha256::digest(&sent)),
        "recv_sha256": hex::encode(Sha256::digest(&recv)),
        "started_utc": started.to_rfc3339(),
        "finished_utc": finished.to_rfc3339(),
        "receipt_present": receipt.is_some(),
        "receipt_local_check": match &local { Ok(s) => json!({"ok": true, "detail": s}), Err(e) => json!({"ok": false, "error": e.to_string()}) },
        "receipt_notary_check": remote,
    });
    std::fs::write(args.out.join("tlsn.json"), serde_json::to_string_pretty(&summary)?)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    local.map(|_| ())
}

/// Find an object shaped like {alg, key_id, payload, signature} anywhere in `v`.
fn find_receipt(v: &Value) -> Option<Value> {
    match v {
        Value::Object(m) => {
            if ["alg", "key_id", "payload", "signature"].iter().all(|k| m.contains_key(*k)) {
                return Some(v.clone());
            }
            m.values().find_map(find_receipt)
        }
        Value::Array(a) => a.iter().find_map(find_receipt),
        _ => None,
    }
}

/// ECDSA/secp256k1 over SHA-256 of the payload's UTF-8 bytes, 64-byte r||s hex,
/// key looked up in the notary's key history and checked against its active window;
/// the signed transcript must equal the bytes this prover saw.
fn verify_receipt(receipt: &Value, keys: &Value, sent: &[u8], recv: &[u8]) -> Result<String> {
    use base64::Engine as _;
    let key_id = receipt["key_id"].as_str().ok_or_else(|| anyhow!("receipt.key_id missing"))?;
    let payload = receipt["payload"].as_str().ok_or_else(|| anyhow!("receipt.payload is not a string"))?;
    let sig_hex = receipt["signature"].as_str().ok_or_else(|| anyhow!("receipt.signature missing"))?;
    let key = keys["keys"]
        .as_array()
        .and_then(|ks| ks.iter().find(|k| k["key_id"] == key_id))
        .ok_or_else(|| anyhow!("key {key_id} not in notary key history"))?;
    let pubkey = hex::decode(key["public_key"].as_str().unwrap_or_default())?;
    let vk = VerifyingKey::from_sec1_bytes(&pubkey)?;
    let sig = Signature::from_slice(&hex::decode(sig_hex)?)?;
    vk.verify(payload.as_bytes(), &sig)
        .map_err(|_| anyhow!("receipt signature does not verify"))?;

    let body: Value = serde_json::from_str(payload).unwrap_or(Value::Null);
    for (dir, local) in [("sent", sent), ("recv", recv)] {
        let signed = body[dir]["data_b64"]
            .as_str()
            .ok_or_else(|| anyhow!("receipt payload has no {dir}.data_b64"))?;
        let signed = base64::engine::general_purpose::STANDARD.decode(signed)?;
        if signed != local {
            bail!("signed {dir} bytes differ from the local transcript");
        }
    }
    if let Some(at) = body["verified_at"].as_str() {
        let at = chrono::DateTime::parse_from_rfc3339(at)?;
        let from = chrono::DateTime::parse_from_rfc3339(key["created_at"].as_str().unwrap_or_default())?;
        if at < from {
            bail!("verified_at {at} precedes key activation {from}");
        }
        if let Some(r) = key["retired_at"].as_str() {
            if at > chrono::DateTime::parse_from_rfc3339(r)? {
                bail!("verified_at {at} is after key retirement {r}");
            }
        }
    }
    Ok(format!("signature valid for key {key_id}; signed transcript matches local bytes"))
}
