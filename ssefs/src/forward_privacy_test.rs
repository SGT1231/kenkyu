#[cfg(test)]
mod forward_privacy_tests {
    use crate::crypto;
    use crate::keyword_state::{DirMap, KeywordState};
    use num_bigint_dig::BigUint;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    fn generate_test_key() -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).unwrap()
    }

    #[test]
    fn test_st_chain_generation() {
        let priv_key = generate_test_key();
        let n = priv_key.n().clone();
        let d = priv_key.d().clone();

        let master_key = b"01234567890123456789012345678901";
        let keyword_id = "kw_chain_test";

        let st0 = crypto::st_init(master_key, keyword_id, &n);
        let mut st = st0.clone();
        let mut states = vec![st0.clone()];

        for _ in 0..4 {
            st = crypto::st_next(&st, &d, &n);
            states.push(st.clone());
        }

        assert_eq!(states.len(), 5, "expected 5 STs");
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(
                    states[i], states[j],
                    "ST[{}] must differ from ST[{}]",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_client_forward_server_backward() {
        let priv_key = generate_test_key();
        let n = priv_key.n().clone();
        let d = priv_key.d().clone();
        let e = RsaPublicKey::from(&priv_key).e().clone();

        let master_key = b"01234567890123456789012345678901";
        let keyword_id = "kw_bidirectional_test";

        let st = crypto::st_init(master_key, keyword_id, &n);
        let mut st_fwd = st.clone();
        let mut forward_states = vec![];
        for _ in 0..4 {
            st_fwd = crypto::st_next(&st_fwd, &d, &n);
            forward_states.push(st_fwd.clone());
        }

        let mut st_back = st_fwd.clone();
        for i in (0..4).rev() {
            st_back = st_back.modpow(&e, &n);
            assert_eq!(
                st_back, forward_states[i],
                "backward mismatch at step {}",
                i
            );
        }
        st_back = st_back.modpow(&e, &n);
        assert_eq!(st_back, st, "backward did not reach initial ST");
    }

    #[test]
    fn test_ut_uniqueness_per_update() {
        let priv_key = generate_test_key();
        let n = priv_key.n().clone();
        let d = priv_key.d().clone();

        let master_key = b"01234567890123456789012345678901";
        let keyword_id = "kw_ut_unique";
        let dk = crypto::derive_dk(master_key, keyword_id);

        let st0 = crypto::st_init(master_key, keyword_id, &n);
        let mut st = st0.clone();
        let mut uts = std::collections::HashSet::new();

        for i in 0..4 {
            st = crypto::st_next(&st, &d, &n);
            let ut = crypto::derive_ut(&dk, &st);
            assert!(
                uts.insert(ut.clone()),
                "duplicate UT at iteration {}: {}",
                i,
                ut
            );
        }
        assert_eq!(uts.len(), 4);
    }

    #[test]
    fn test_keyword_state_persistence() {
        let mut dir_map = DirMap::default();
        let keyword_id = "kw_persist_test";
        let state = KeywordState {
            counter: 3,
            latest_st: "AbCdEf1234".to_string(),
        };
        dir_map.update_state(keyword_id, state.clone());

        let tmp_path = std::env::temp_dir().join("fp_test_dir_map.json");
        {
            let json = serde_json::to_string_pretty(&dir_map).unwrap();
            std::fs::write(&tmp_path, json).unwrap();
        }

        let contents = std::fs::read_to_string(&tmp_path).unwrap();
        let dir_map2: DirMap = serde_json::from_str(&contents).unwrap();
        let state2 = dir_map2.get_state(keyword_id).unwrap();

        assert_eq!(state2.counter, 3);
        assert_eq!(state2.latest_st, "AbCdEf1234");

        std::fs::remove_file(&tmp_path).unwrap();
    }

    #[test]
    fn test_forward_privacy_search_then_update() {
        let priv_key = generate_test_key();
        let n = priv_key.n().clone();
        let d = priv_key.d().clone();
        let e = RsaPublicKey::from(&priv_key).e().clone();

        let master_key = b"01234567890123456789012345678901";
        let keyword_id = "kw_fp_core";
        let dk = crypto::derive_dk(master_key, keyword_id);

        let st0 = crypto::st_init(master_key, keyword_id, &n);
        let mut st = st0.clone();

        for _ in 0..3 {
            st = crypto::st_next(&st, &d, &n);
        }
        let st3 = st.clone();
        let ut3 = crypto::derive_ut(&dk, &st3);

        let st4 = crypto::st_next(&st3, &d, &n);
        let ut4 = crypto::derive_ut(&dk, &st4);

        let st3_backward = st3.modpow(&e, &n);
        assert_ne!(
            st3_backward, st4,
            "server must not reach ST4 using public e"
        );

        let st4_client = crypto::st_next(&st3, &d, &n);
        assert_eq!(st4_client, st4);
        assert_ne!(ut3, ut4, "consecutive UTs must differ");
    }

    #[test]
    fn test_derive_functions_consistency() {
        let master_key = b"01234567890123456789012345678901";
        let keyword_id = "kw_consistency";
        let dk1 = crypto::derive_dk(master_key, keyword_id);
        let dk2 = crypto::derive_dk(master_key, keyword_id);
        assert_eq!(dk1, dk2, "derive_dk must be deterministic");

        let st = BigUint::from(12345u32);
        let ut1 = crypto::derive_ut(&dk1, &st);
        let ut2 = crypto::derive_ut(&dk2, &st);
        assert_eq!(ut1, ut2, "derive_ut must be deterministic for same inputs");
        assert_eq!(ut1.len(), 64, "UT must be 64-char hex (256 bits)");
    }
}
