use std::env;
use std::path::Path;

#[path = "../crypto.rs"]
mod crypto;
#[path = "../key_manager.rs"]
mod key_manager;
#[path = "../keyword_state.rs"]
mod keyword_state;

use crypto::{
    base64_to_biguint, derive_dk, derive_ut, st_init, st_next,
};
use key_manager::{get_key, get_tdp_d, get_tdp_e, get_tdp_n, init, tdp_init};
use keyword_state::DirMap;
use num_bigint_dig::BigUint;

fn main() {
    if let Err(e) = init() {
        eprintln!("Failed to initialize master key: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = tdp_init() {
        eprintln!("Failed to initialize TDP key: {}", e);
        std::process::exit(1);
    }

    let index_dir = env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("index"));
    let index_dir = Path::new(&index_dir);

    let dir_map = DirMap::load_or_create();
    println!("Loaded dir_map: {} paths, {} states", dir_map.path_to_keyword.len(), dir_map.keyword_to_state.len());
    println!("Index directory: {}", index_dir.display());

    if !index_dir.exists() {
        eprintln!("WARNING: index directory does not exist!");
    } else if !index_dir.is_dir() {
        eprintln!("WARNING: index path is not a directory!");
    } else {
        match std::fs::read_dir(index_dir) {
            Ok(entries) => {
                let mut files: Vec<String> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_file())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                files.sort();
                println!("Actual files in index directory: {}", files.len());
                for f in files.iter().take(20) {
                    println!("  - {}", f);
                }
                if files.len() > 20 {
                    println!("  ... and {} more", files.len() - 20);
                }
            }
            Err(e) => eprintln!("WARNING: failed to read index directory: {}", e),
        }
    }
    println!();

    let master_key = get_key();
    let n = get_tdp_n();
    let d = get_tdp_d();
    let e = get_tdp_e();

    let mut total_keywords = 0usize;
    let mut total_mismatches = 0usize;

    for (keyword_id, state) in &dir_map.keyword_to_state {
        total_keywords += 1;

        // keyword_id から対応する path を逆引き
        let paths: Vec<&String> = dir_map
            .path_to_keyword
            .iter()
            .filter(|(_, v)| *v == keyword_id)
            .map(|(k, _)| k)
            .collect();
        let path_str = paths.first().map(|s| s.as_str()).unwrap_or("<unknown>");

        println!("=================================================================");
        println!("keyword_id: {}", keyword_id);
        println!("path:       {}", path_str);
        println!("counter:    {}", state.counter);
        println!("latest_st:  {}", state.latest_st);

        if state.counter == 0 {
            println!("  (counter is 0, skipping)");
            println!();
            continue;
        }

        let dk = derive_dk(master_key, keyword_id);
        println!("dk (hex):   {}", hex::encode(dk));
        println!();

        // ---- Forward 計算 (Rust クライアント側と同じ) ----
        // 結果は [最古, ..., 最新] なので、後で reverse して [最新, ..., 最古] に揃える
        let mut forward_sts: Vec<BigUint> = Vec::with_capacity(state.counter as usize);
        let mut st = st_init(master_key, keyword_id, &n);
        forward_sts.push(st.clone());
        for _ in 1..state.counter {
            st = st_next(&st, &d, &n);
            forward_sts.push(st.clone());
        }
        forward_sts.reverse();

        // ---- Backward 計算 (Go サーバ側 searchHandler と同じ) ----
        let mut backward_sts: Vec<BigUint> = Vec::with_capacity(state.counter as usize);
        let latest_st = base64_to_biguint(&state.latest_st).unwrap_or_else(|| {
            eprintln!("  ERROR: failed to decode latest_st '{}'", state.latest_st);
            BigUint::from(0u32)
        });
        let mut st = latest_st.clone();
        backward_sts.push(st.clone());
        for _ in 1..state.counter {
            st = st.modpow(&e, &n);
            backward_sts.push(st.clone());
        }

        // ---- 比較テーブル出力 ----
        println!("  gen | forward_ut                     | backward_ut                    | match | index_file | note");
        println!("  ----+--------------------------------+--------------------------------+-------+------------+------");

        for i in 0..state.counter as usize {
            let fwd_st = forward_sts.get(i).cloned().unwrap_or_else(|| BigUint::from(0u32));
            let bwd_st = backward_sts.get(i).cloned().unwrap_or_else(|| BigUint::from(0u32));

            let fwd_ut = derive_ut(&dk, &fwd_st);
            let bwd_ut = derive_ut(&dk, &bwd_st);

            let ut_match = fwd_ut == bwd_ut;
            let index_path = index_dir.join(&fwd_ut);
            let index_exists = index_path.exists();

            let mut note = String::new();
            if !ut_match {
                note.push_str("UT_MISMATCH ");
                total_mismatches += 1;
            }
            if !index_exists {
                note.push_str("INDEX_MISSING ");
            }

            println!(
                "  {:3} | {} | {} | {:5} | {:10} | {}",
                i,
                truncate(&fwd_ut, 30),
                truncate(&bwd_ut, 30),
                if ut_match { "OK" } else { "NG" },
                if index_exists { "EXISTS" } else { "MISSING" },
                if note.is_empty() { "-" } else { &note.trim() }
            );
        }
        println!();
    }

    println!("=================================================================");
    println!("Summary: {} keyword(s), {} UT mismatch(es)", total_keywords, total_mismatches);
    if total_mismatches == 0 {
        println!("All forward/backward UT calculations are consistent.");
    } else {
        println!("Found inconsistencies. Please check PEM/n/e/d or ST chain logic.");
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        format!("{:<width$}", s, width = max_len)
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
