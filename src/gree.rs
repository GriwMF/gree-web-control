use base64::{Engine as _, engine::general_purpose};
use openssl::symm::{Cipher, Crypter, Mode};
// use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::time::Duration;
use std::str;

const GENERIC_KEY: &[u8] = "a3K8Bx%2r8Y7#xDh".as_bytes();

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub ip: String,
    pub cid: String,
    pub key: Vec<u8>,
    pub name: String,
}

fn decrypt(pack_encoded: &str, key: &[u8]) -> String {
    let pack_decoded = general_purpose::STANDARD.decode(pack_encoded).unwrap();
    
    let mut decryptor = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();
    let mut decrypted = vec![0; pack_decoded.len() + Cipher::aes_128_ecb().block_size()];
    let mut count = decryptor.update(&pack_decoded, &mut decrypted).unwrap();
    count += decryptor.finalize(&mut decrypted[count..]).unwrap();
    
    decrypted.truncate(count);

    str::from_utf8(&decrypted).expect("Failed to convert to UTF-8").to_string()
}

fn decrypt_generic(pack_encoded: &str) -> String {
    decrypt(pack_encoded, GENERIC_KEY)
}

fn encrypt(pack: &str, key: &[u8]) -> String {
    let mut encryptor = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    // let pack_padded = add_pkcs7_padding(pack);
    let mut encrypted = vec![0; pack.len() + Cipher::aes_128_ecb().block_size()];
    let mut count = encryptor.update(pack.as_bytes(), &mut encrypted).unwrap();
    count += encryptor.finalize(&mut encrypted[count..]).unwrap();

    general_purpose::STANDARD.encode(&encrypted[..count])
}

fn encrypt_generic(pack: &str) -> String {
    encrypt(pack, GENERIC_KEY)
}

fn create_request(tcid: &str, pack_encrypted: &str, i: u32) -> String {
    format!(
        r#"{{"cid":"app","i":{},"t":"pack","uid":0,"tcid":"{}","pack":"{}"}}"#,
        i, tcid, pack_encrypted
    )
}

fn create_status_request_pack(tcid: &str) -> String {
    format!(
        r#"{{"cols":["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet",
           "Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt"],"mac":"{}","t":"status"}}"#,
        tcid
    )
}

pub fn search_devices() -> Vec<ScanResult> {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    socket.set_broadcast(true).expect("Failed to set broadcast");
    socket.set_read_timeout(Some(Duration::new(1, 0))).expect("Failed to set read timeout");
    
    let message = b"{\"t\":\"scan\"}";
    socket.send_to(message, format!("{}:7000", "192.168.1.255")).expect("Failed to send message");

    let mut results: Vec<ScanResult> = Vec::new();

    loop {
        let mut buf = [0; 1024];
        match socket.recv_from(&mut buf) {
            Ok((size, addr)) => {
                let response = &buf[..size];
                // println!("Received response from {}: {}", addr, std::str::from_utf8(response).unwrap());

                // Parse JSON response
                let resp: Value = serde_json::from_slice(response).expect("Failed to parse JSON");
                let pack_encoded = resp["pack"].as_str().expect("Missing or invalid 'pack' field");

                // Decrypt and parse 'pack' if present
                let decrypted_pack = decrypt_generic(pack_encoded);
                let pack: Value = serde_json::from_str(&decrypted_pack).expect("Failed to parse decrypted JSON");

                // Extract 'cid' from decrypted pack or fallback to response cid
                let cid = pack["cid"].as_str().unwrap_or(resp["cid"].as_str().unwrap_or(""));

                    // Extract values from pack and construct ScanResult
                let name = pack["name"].as_str().unwrap_or("<unknown>").to_string();

                let result = ScanResult {
                    ip: match addr.ip() {
                        IpAddr::V4(ipv4) => ipv4.to_string(),
                        IpAddr::V6(ipv6) => ipv6.to_string(),
                    },
                    cid: cid.to_string(),
                    key: vec![],
                    name: name,
                };

                // Append result to results vector
                results.push(result);
                },
            Err(_) => break, // Timeout or other error, exit loop
        }
    }

    results
}

fn send_data(ip: &str, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:7000")?; // Bind to any available local address

    // Set socket options
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    // Send data to specified IP and port
    let addr = format!("{}:{}", ip, 7000);
    socket.send_to(data, &addr)?;

    // Receive response
    let mut buf = [0; 1024];
    let (size, _) = socket.recv_from(&mut buf)?;
    Ok(buf[..size].to_vec())
}

pub fn bind_device(search_result: &ScanResult) -> Vec<u8> {
    println!("Binding device: {} ({}, ID: {})", search_result.ip, search_result.name, search_result.cid);

    let pack = format!("{{\"mac\":\"{}\",\"t\":\"bind\",\"uid\":0}}", search_result.cid);
    let pack_encrypted = encrypt_generic(&pack);

    let request = create_request(&search_result.cid, &pack_encrypted, 1);
    let result = send_data(&search_result.ip, request.as_bytes()).expect("Failed to send data");

    let response_str = String::from_utf8_lossy(&result);
    let response: serde_json::Value = serde_json::from_str(&response_str).expect("Failed to parse JSON response");

    if let Some(t) = response["t"].as_str() {
        if t.to_lowercase() == "pack" {
            if let Some(pack) = response["pack"].as_str() {
                let pack_decrypted = decrypt_generic(pack);

                let bind_resp: serde_json::Value = serde_json::from_str(&pack_decrypted).expect("Failed to parse decrypted JSON");

                if let Some(t) = bind_resp["t"].as_str() {
                    if t.to_lowercase() == "bindok" {
                        if let Some(key) = bind_resp["key"].as_str() {
                            println!("Bind to {} succeeded, key = {}", search_result.cid, key);
                            return key.as_bytes().to_vec();
                        }
                    }
                }
            }
        }
    }
    panic!("Error in bind pack response")
}

pub fn get_param(cid: &String, ip: &String, key: &Vec<u8>, params: Vec<&str>) -> HashMap<String, u64> {
    println!("Getting parameters: {}", params.join(", "));

    let cols = params.iter().map(|i| format!("\"{}\"", i)).collect::<Vec<_>>().join(",");

    let pack = format!(r#"{{"cols":[{}],"mac":"{}","t":"status"}}"#, cols, cid);
    let pack_encrypted = encrypt(&pack, key);

    let request = format!(r#"{{"cid":"app","i":0,"pack":"{}","t":"pack","tcid":"{}","uid":0}}"#, pack_encrypted, cid);

    let result = send_data(&ip, request.as_bytes()).expect("Failed to send data");

    let response_str = String::from_utf8_lossy(&result);
    let response: serde_json::Value = serde_json::from_str(&response_str).expect("Failed to parse JSON response");

    if let Some(t) = response["t"].as_str() {
        if t == "pack" {
            if let Some(pack) = response["pack"].as_str() {
                let pack_decrypted = decrypt(pack, key);
                let pack_json: Value = serde_json::from_str(&pack_decrypted).expect("Failed to parse decrypted JSON");
                let rez_array = pack_json["cols"].as_array().unwrap().iter().zip(pack_json["dat"].as_array().unwrap().iter());

                let mut response_params = HashMap::new();
                for (col, dat) in rez_array {
                    if let (Value::String(c), Value::Number(d)) = (col, dat) {
                        response_params.insert(c.clone(), d.as_u64().unwrap());
                    }
                }
                return response_params;
            }
        }
    }
    panic!("Failed to parse JSON response");
}


pub fn set_param(cid: &String, ip: &String, key: &Vec<u8>, params: HashMap<&str, &str>) {
    println!("Setting parameters: {:#?}", params);

    let params_keys: String = params.keys().map(|key| format!("\"{}\"", key)).collect::<Vec<String>>().join(", ");
    let params_values: String = params.values().map(|key| key.to_string()).collect::<Vec<String>>().join(", ");

    let pack = format!(r#"{{"opt":[{}],"p":[{}],"t":"cmd"}}"#, params_keys, params_values);
    println!("{pack}");
    let pack_encrypted = encrypt(&pack, key);

    let request = format!(r#"{{"cid":"app","i":0,"pack":"{}","t":"pack","tcid":"{}","uid":0}}"#, pack_encrypted, cid);

    let result = send_data(&ip, request.as_bytes()).expect("Failed to send data");

    let response_str = String::from_utf8_lossy(&result);
    let response: serde_json::Value = serde_json::from_str(&response_str).expect("Failed to parse JSON response");

    if let Some(t) = response["t"].as_str() {
        if t == "pack" {
            if let Some(pack) = response["pack"].as_str() {
                let pack_decrypted = decrypt(pack, key);
                let pack_json: Value = serde_json::from_str(&pack_decrypted).expect("Failed to parse decrypted JSON");
              
                if pack_json["r"].as_i64().unwrap() != 200 {
                    println!("Failed to set parameter");
                }
            }
        }
    }
}