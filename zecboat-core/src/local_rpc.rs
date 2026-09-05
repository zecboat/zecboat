use axum::{
    routing::post,
    Router,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Deserialize, Debug)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Vec<Value>,
}

#[derive(Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

pub async fn start_server() {
    let app = Router::new().route("/", post(handle_rpc));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8238));
    println!("Starting local Zecboat RPC server on {}", addr);
    
    if let Ok(listener) = TcpListener::bind(addr).await {
        let _ = axum::serve(listener, app).await;
    }
}

async fn handle_rpc(body: String) -> impl IntoResponse {
    // We take a raw string because some curl requests might not send application/json
    let req: Result<RpcRequest, _> = serde_json::from_str(&body);
    
    match req {
        Ok(request) => {
            let result = match request.method.as_str() {
                "getnewaccount" => {
                    match crate::rpc::create_new_account().await {
                        Ok(acc) => Ok(json!(acc)),
                        Err(e) => Err(e.to_string()),
                    }
                },
                "getnewaddress" => {
                    match crate::rpc::generate_new_address().await {
                        Ok(addr) => Ok(json!(addr)),
                        Err(e) => Err(e.to_string()),
                    }
                },
                "listaddresses" => {
                    match crate::rpc::get_addresses().await {
                        Ok(addrs) => Ok(json!(addrs)),
                        Err(e) => Err(e.to_string()),
                    }
                },
                "send_transaction" | "z_sendmany" => {
                    // Extract params: address, amount, memo
                    // For simplicity, we assume params = [address (string), amount (float), memo (string)]
                    if request.params.len() >= 3 {
                        let address = request.params[0].as_str().unwrap_or("");
                        let amount = request.params[1].as_f64().unwrap_or(0.0);
                        let memo = request.params[2].as_str().unwrap_or("");
                        
                        match crate::rpc::send_transaction(address, amount, memo, None).await {
                            Ok(txid) => Ok(json!(txid)),
                            Err(e) => Err(e.to_string()),
                        }
                    } else {
                        Err("Invalid parameters for send_transaction. Expected [address, amount, memo]".to_string())
                    }
                },
                // Renamed from "batch_mint". It batches SENDS; it has never minted anything.
        // The old name contradicted the documented rule that this codebase
        // contains no mint path, and anyone grepping to check would have found it.
        "batch_send" => {
                    // Expecting an array of objects: [{"address": "u1...", "amount": 0.0001, "memo": "..."}]
                    if request.params.len() >= 1 {
                        let mut outputs = Vec::new();
                        if let Some(arr) = request.params[0].as_array() {
                            for item in arr {
                                let addr = item.get("address").and_then(|a| a.as_str()).unwrap_or("").to_string();
                                let amount = item.get("amount").and_then(|a| a.as_f64()).unwrap_or(0.0);
                                let memo = item.get("memo").and_then(|m| m.as_str()).unwrap_or("").to_string();
                                outputs.push((addr, amount, memo));
                            }
                        }
                        
                        match crate::rpc::batch_send_transaction(outputs).await {
                            Ok(txid) => Ok(json!(txid)),
                            Err(e) => Err(e.to_string()),
                        }
                    } else {
                        Err("Invalid parameters for batch_send. Expected an array of output objects.".to_string())
                    }
                },
                "unlock_wallet" => {
                    if request.params.len() >= 1 {
                        let password = request.params[0].as_str().unwrap_or("").to_string();
                        // Assume use_yubikey is false for RPC for now, or take it as a second boolean param
                        let use_yubikey = if request.params.len() >= 2 {
                            request.params[1].as_bool().unwrap_or(false)
                        } else {
                            false
                        };
                        match crate::rpc::unlock_wallet(password, use_yubikey).await {
                            Ok(_) => Ok(json!("Unlocked")),
                            Err(e) => Err(e.to_string()),
                        }
                    } else {
                        Err("Invalid parameters for unlock_wallet. Expected [password]".to_string())
                    }
                },
                "getinfo" | "getblockchaininfo" => {
                    match crate::rpc::sync_status().await {
                        Ok(status) => {
                            // sync_status returns a string containing json, parse it
                            let v: Value = serde_json::from_str(&status).unwrap_or(json!({}));
                            Ok(v)
                        },
                        Err(e) => Err(e.to_string()),
                    }
                },
                _ => {
                    Err(format!("Method {} not supported", request.method))
                }
            };

            match result {
                Ok(val) => {
                    axum::Json(RpcResponse {
                        jsonrpc: request.jsonrpc,
                        id: request.id,
                        result: Some(val),
                        error: None,
                    })
                },
                Err(err) => {
                    axum::Json(RpcResponse {
                        jsonrpc: request.jsonrpc,
                        id: request.id,
                        result: None,
                        error: Some(json!({"code": -32601, "message": err})),
                    })
                }
            }
        },
        Err(e) => {
            axum::Json(RpcResponse {
                jsonrpc: "1.0".to_string(),
                id: json!(null),
                result: None,
                error: Some(json!({"code": -32700, "message": format!("Parse error: {}", e)})),
            })
        }
    }
}
