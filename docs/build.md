# qlite — Implementation Build Plan

Each **Phase** is a testable milestone — nothing in the next phase starts until
the current one passes its test gate.  Each Phase is broken into **Chunks**,
and each Chunk into **Sub-chunks** that map directly to functions or groups of
functions in `qlite.h`.

Dependencies flow strictly downward: lower phases never depend on higher ones.

---

## Dependency graph (high level)

```
Phase 1 — Primitives & Wire Format
    │
    ▼
Phase 2 — Crypto & Packet Protection
    │
    ▼
Phase 3 — Connection Bootstrap & Handshake
    │
    ▼
Phase 4 — Streams & Flow Control
    │
    ▼
Phase 5 — Loss Detection & Congestion Control
    │
    ▼
Phase 6 — Path Migration & Key Update
    │
    ▼
Phase 7 — Server Listener & Full Integration
```

---

## Phase 1 — Primitives & Wire Format

**Goal:** Every byte on the wire can be encoded and decoded correctly.
No crypto, no connections, no state machines — just serialisation.

### Chunk 1.1 — Varint encoding (§16)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 1.2.1 | `ql_varint_encoded_len()` | 1/2/4/8 bytes, no writes |
| 1.2.2 | `ql_varint_encode()` | writes 2-MSB prefix + value |
| 1.2.3 | `ql_varint_decode()` | reads prefix, returns bytes consumed |

**Test gate 1.1:** Round-trip all four length boundaries (`0`, `63`, `64`, `16383`, `16384`, `1073741823`, `1073741824`, `QL_VARINT_MAX`).  Verify decode rejects truncated input.

---

### Chunk 1.2 — Packet number encode / decode (§17.1, Appendix A)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 1.3.1 | `ql_pkt_num_encode()` | smallest k-bit truncation given largest_acked |
| 1.3.2 | `ql_pkt_num_decode()` | reconstruct full 62-bit from truncated + largest_pn |

**Test gate 1.2:** Use the RFC Appendix A.2 / A.3 sample vectors.  Verify edge cases: wrap-around at 2^62, pn=0 with no prior.

---

### Chunk 1.3 — Frame encode / decode (§19)

Order within this chunk matters — simpler frames first, STREAM last.

| Sub-chunk | Frames covered | Notes |
|---|---|---|
| 1.3.1 | PADDING, PING | trivial, zero-field |
| 1.3.2 | ACK, ACK_ECN | varint-heavy; include ECN counts |
| 1.3.3 | RESET_STREAM, STOP_SENDING | 3-field and 2-field |
| 1.3.4 | CRYPTO, NEW_TOKEN | data pointer + length |
| 1.3.5 | STREAM (all 8 variants 0x08–0x0F) | OFF/LEN/FIN flag combinations |
| 1.3.6 | MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_BIDI/UNI | flow control frames |
| 1.3.7 | DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED_BIDI/UNI | blocked signals |
| 1.3.8 | NEW_CONNECTION_ID, RETIRE_CONNECTION_ID | CID management |
| 1.3.9 | PATH_CHALLENGE, PATH_RESPONSE | 8-byte data blob |
| 1.3.10 | CONNECTION_CLOSE (0x1C), CONNECTION_CLOSE_APP (0x1D) | reason phrase |
| 1.3.11 | HANDSHAKE_DONE | zero-field; server→client only |
| 1.3.12 | `ql_frame_encode()` dispatch | switch over `ql_frame_t.type` |
| 1.3.13 | `ql_frame_decode()` dispatch | read type varint, route to handler |

**Test gate 1.3:** Encode every frame type with known values, decode the output, compare field-by-field.  Test truncated-buffer rejection for each type.  Test unknown frame type returns `QLITE_ERR_PROTO`.

---

### Chunk 1.4 — Transport parameter encode / decode (§18)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 1.4.1 | `ql_tp_encode()` | iterate known IDs, write TLV entries |
| 1.4.2 | `ql_tp_decode()` | parse TLV loop, unknown IDs silently skipped §7.4.2 |
| 1.4.3 | Default value injection | fill in RFC defaults for absent params |

**Test gate 1.4:** Encode a fully-populated `ql_transport_params_t`, decode into a fresh struct, compare all fields.  Verify unknown ID (e.g. 0xFF) is skipped without error.  Verify duplicate ID triggers `QLITE_ERR_PROTO`.

---

### Chunk 1.5 — UDP socket I/O

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 1.5.1 | `ql_udp_socket()` | create, bind, set `O_NONBLOCK` |
| 1.5.2 | `ql_udp_send()` | `sendto` wrapper, maps EAGAIN → `QLITE_ERR_WOULDBLOCK` |
| 1.5.3 | `ql_udp_recv()` | `recvfrom` wrapper, maps EAGAIN → `QLITE_ERR_AGAIN` |
| 1.5.4 | `ql_now_ms()` | `clock_gettime(CLOCK_MONOTONIC)` → ms |

**Test gate 1.5:** Open two sockets on loopback, send a datagram from one to the other, recv it, compare bytes.  Verify non-blocking behaviour (recv on empty socket → `QLITE_ERR_AGAIN`).

---

**Phase 1 exit gate:** All chunk test gates pass.  No crypto or connection code involved.

---

## Phase 2 — Crypto & Packet Protection

**Goal:** Packets can be AEAD-sealed, header-protected, header-unprotected, and AEAD-opened.  Initial keys can be derived from a DCID.

Depends on: Phase 1 (varint, frame encode/decode for payload construction).

### Chunk 2.1 — AEAD seal / open (RFC 9001 §5.3)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 2.1.1 | Nonce construction | XOR packet number (big-endian padded) into IV |
| 2.1.2 | `ql_aead_seal()` | AES-128-GCM or AES-256-GCM via OpenSSL EVP |
| 2.1.3 | `ql_aead_open()` | authenticate + decrypt; `QLITE_ERR_CRYPTO` on tag failure |

**Test gate 2.1:** Use RFC 9001 Appendix B sample vectors for AES-128-GCM.  Flip one ciphertext byte, verify `QLITE_ERR_CRYPTO`.

---

### Chunk 2.2 — Header protection (RFC 9001 §5.4)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 2.2.1 | AES-ECB mask generation | encrypt 16-byte sample under HP key |
| 2.2.2 | `ql_hp_protect()` | XOR mask into first-byte bits and pkt-num bytes |
| 2.2.3 | `ql_hp_remove()` | identical operation (XOR is self-inverse) |

**Test gate 2.2:** Use RFC 9001 Appendix B sample.  Protect then remove, verify original bytes recovered byte-for-byte.

---

### Chunk 2.3 — Initial key derivation (RFC 9001 §5.2)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 2.3.1 | HKDF-Extract with `QL_INITIAL_SALT` + DCID | produces `initial_secret` |
| 2.3.2 | HKDF-Expand-Label for client/server secrets | `"client in"` / `"server in"` |
| 2.3.3 | Key + IV + HP derivation from secret | `"quic key"` / `"quic iv"` / `"quic hp"` |
| 2.3.4 | Fill `ql_key_pair_t` for `QL_ENC_LEVEL_INITIAL` | both read and write sides |

**Test gate 2.3:** Derive Initial keys from the RFC 9001 Appendix A DCID (`0x8394c8f03e515708`).  Compare all six derived byte strings (client key, iv, hp; server key, iv, hp) against the RFC vectors.

---

### Chunk 2.4 — Retry integrity tag (RFC 9001 Appendix A)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 2.4.1 | Build pseudo-packet from Retry packet fields | fixed format per RFC |
| 2.4.2 | AES-128-GCM seal with `QL_RETRY_INTEGRITY_KEY` + `QL_RETRY_INTEGRITY_NONCE` | tag is 16 bytes |
| 2.4.3 | Verification path | re-compute tag, constant-time compare |

**Test gate 2.4:** Compute Retry integrity tag for the RFC 9001 Appendix A sample Retry packet.  Verify match.

---

### Chunk 2.5 — Packet encode / decode (§17)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 2.5.1 | Long-header serialise | write first byte, version, DCID len, DCID, SCID len, SCID |
| 2.5.2 | Initial-specific fields | token length + token, then payload length + pkt-num |
| 2.5.3 | Short-header serialise | first byte, DCID, pkt-num |
| 2.5.4 | `ql_pkt_encode()` | header → `ql_aead_seal()` → `ql_hp_protect()` |
| 2.5.5 | Long-header parse | read first byte, version, CID lengths, CIDs |
| 2.5.6 | Short-header parse | read first byte, DCID (known length) |
| 2.5.7 | `ql_pkt_decode()` | `ql_hp_remove()` → pkt-num decode → `ql_aead_open()` |
| 2.5.8 | Version Negotiation parse | no crypto; list of supported versions |

**Test gate 2.5:** Encode a synthetic Initial packet with known payload, decode it, verify payload and all header fields match.  Decode with wrong key, verify `QLITE_ERR_CRYPTO`.  Test Version Negotiation parse from raw bytes.

---

**Phase 2 exit gate:** Full Initial-level send/receive loop works on loopback with RFC-derived keys.

---

## Phase 3 — Connection Bootstrap & Handshake

**Goal:** A client and server can complete the QUIC+TLS handshake to `QL_CONN_CONNECTED`, including Retry and Version Negotiation paths.

Depends on: Phase 2 complete.

### Chunk 3.1 — Connection init & CID management

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 3.1.1 | `ql_cid_generate()` | cryptographically random bytes via `getrandom` / `arc4random` |
| 3.1.2 | `ql_cid_cmp()` | constant-time byte comparison |
| 3.1.3 | `ql_conn_init()` | zero struct, set role, copy config, generate initial local CID, init CC |
| 3.1.4 | CID table helpers | find active local CID, find remote CID by value, retire CID |

**Test gate 3.1:** Init a client and server conn, verify CIDs are non-zero and distinct.  Retire a CID, verify it is marked retired and a new one is available.

---

### Chunk 3.2 — TLS callback wiring

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 3.2.1 | `ql_tls_init()` | validate all 7 callbacks non-NULL |
| 3.2.2 | `ql_tls_provide_data()` | call `tls->provide_data`, feed into CRYPTO reorder buffer |
| 3.2.3 | `ql_tls_get_data()` | call `tls->get_data`, build CRYPTO frame(s) for outbound queue |
| 3.2.4 | `ql_tls_install_keys()` | call `tls->set_keys`, populate `conn->keys[level]` |
| 3.2.5 | `ql_tls_handshake_done()` | delegate to `tls->is_done` |

**Test gate 3.2:** Build a mock TLS engine that feeds canned ClientHello / ServerHello bytes.  Verify CRYPTO frames are produced at the right encryption levels and key installation is called once per level.

---

### Chunk 3.3 — CRYPTO frame reassembly (§7.5)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 3.3.1 | In-order receive path | offset matches `rx_offset` → copy to TLS immediately |
| 3.3.2 | Out-of-order buffering | offset > `rx_offset` → hold in `ql_crypto_buf_t.buf` |
| 3.3.3 | Gap-fill flush | when a gap is filled, drain buffered bytes in order |
| 3.3.4 | Overflow guard | total buffered > `QL_CRYPTO_BUF_SIZE` → `QL_ERR_CRYPTO_BUFFER_EXCEEDED` |

**Test gate 3.3:** Deliver CRYPTO frames at offsets [100, 0, 50] in that order.  Verify TLS receives them assembled as [0..150] in one contiguous feed.

---

### Chunk 3.4 — Handshake state machine

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 3.4.1 | Client: send Initial (ClientHello) | encode token if retried, pad to 1200 bytes §14.1 |
| 3.4.2 | Server: receive Initial, send Initial + Handshake | address validation check first |
| 3.4.3 | Client: receive Initial + Handshake, send Handshake (Finished) | discard Initial keys §4.9.1 RFC9001 |
| 3.4.4 | Server: receive Handshake Finished, send HANDSHAKE_DONE | promote to CONNECTED |
| 3.4.5 | Client: receive HANDSHAKE_DONE | set `handshake_confirmed`, discard Handshake keys |
| 3.4.6 | Key discard after promotion | zero out old-level keys per §4.9 RFC9001 |

**Test gate 3.4:** Full handshake on loopback using a real OpenSSL `SSL*` (or mock).  Both sides reach `QL_CONN_CONNECTED`.  Verify old keys are zeroed.

---

### Chunk 3.5 — Retry & Version Negotiation

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 3.5.1 | Server: generate Retry packet | new SCID, compute integrity tag, send |
| 3.5.2 | Client: receive Retry | verify integrity tag, resend Initial with token |
| 3.5.3 | Server: validate Retry token | HMAC over client address + timestamp; reject replays §8.1.4 |
| 3.5.4 | Version Negotiation send | server sends VN when version unknown |
| 3.5.5 | Version Negotiation receive | client aborts with supported-version list |

**Test gate 3.5:** Force Retry path — server sends Retry, client resends, handshake completes.  Force VN — client aborts cleanly.

---

### Chunk 3.6 — Anti-amplification & address validation (§8 / §21.3)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 3.6.1 | Byte tracking in `ql_addr_valid_t` | increment on every send/recv |
| 3.6.2 | Send gate | block send if `bytes_sent >= 3 × bytes_received` and not validated |
| 3.6.3 | Validation on Handshake receipt | receiving valid Handshake → `validated = true` §8.1 |
| 3.6.4 | `ql_conn_free()` | free stream list, zero keys |

**Test gate 3.6:** Simulate server receiving 1200 bytes.  Verify server cannot send more than 3600 bytes before a Handshake packet arrives.  After Handshake, verify gate is lifted.

---

**Phase 3 exit gate:** Loopback handshake completes end-to-end.  Both sides at `QL_CONN_CONNECTED` with correct keys.  Anti-amplification enforced.

---

## Phase 4 — Streams & Flow Control

**Goal:** Application data moves reliably over streams with correct flow control on both sides.

Depends on: Phase 3 complete.

### Chunk 4.1 — Stream lifecycle

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 4.1.1 | `ql_stream_init()` | zero struct, set ID/type, copy FC limits from remote TP |
| 4.1.2 | `ql_stream_find()` | linear search of `conn->stream_list` |
| 4.1.3 | `qlite_stream_open()` | alloc via `ql_new`, assign next ID, link into list |
| 4.1.4 | Peer-opened stream creation | auto-create on first STREAM frame for unknown ID |
| 4.1.5 | `qlite_stream_close()` | FIN path (code=0) vs RESET_STREAM path (code≠0) |
| 4.1.6 | Stream state transitions | enforce §3.1 / §3.2 state machines, return `QLITE_ERR_STREAM` on violation |

**Test gate 4.1:** Open 4 streams (one of each type), verify IDs.  Close with FIN, verify `DATA_SENT` state.  Reset with code, verify `RESET_SENT`.  Attempt write after FIN, verify error.

---

### Chunk 4.2 — Stream send path

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 4.2.1 | `qlite_send()` | copy into `tx_buf` ring, advance `tx_head` |
| 4.2.2 | `ql_stream_tx_dequeue()` | pull bytes respecting stream FC + connection FC |
| 4.2.3 | STREAM frame construction | choose OFF/LEN/FIN variant, set correct flags |
| 4.2.4 | FIN flag emission | set FIN on last STREAM frame when stream closed with code=0 |
| 4.2.5 | `QL_RETX_FLAG_STREAM` | mark sent packet for potential retransmit |

**Test gate 4.2:** Write 200 KB to a stream with a 64 KB flow-control window.  Verify dequeue stops at 64 KB limit.  Advance peer window, verify dequeue resumes.

---

### Chunk 4.3 — Stream receive path

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 4.3.1 | `ql_stream_rx_push()` | write to `rx_buf` ring at correct offset |
| 4.3.2 | Out-of-order gap handling | hold future bytes, deliver in order |
| 4.3.3 | FIN handling | set `rx_state = SIZE_KNOWN`, record `final_size` |
| 4.3.4 | Final size consistency | error if data arrives beyond FIN offset §4.5 |
| 4.3.5 | `qlite_recv()` | drain `rx_buf`, advance `rx_head` |
| 4.3.6 | RESET_STREAM receive | transition `rx_state`, discard buffer, surface error code |

**Test gate 4.3:** Push frames at offsets [1000, 0, 500] out of order.  Verify `qlite_recv` returns them assembled in order.  Push FIN at offset 1500 with wrong final_size, verify `QLITE_ERR_PROTO`.

---

### Chunk 4.4 — Flow control

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 4.4.1 | `ql_fc_stream_init()` | set send/recv limits from TP |
| 4.4.2 | `ql_fc_conn_check()` | connection-level gate check |
| 4.4.3 | `ql_fc_update()` | issue MAX_DATA / MAX_STREAM_DATA when window half-consumed |
| 4.4.4 | Blocked signalling | emit DATA_BLOCKED / STREAM_DATA_BLOCKED when send-blocked |
| 4.4.5 | MAX_DATA receive | update `conn->fc.send_limit` |
| 4.4.6 | MAX_STREAM_DATA receive | update `stream->fc.send_limit` |
| 4.4.7 | MAX_STREAMS receive | update `conn->max_streams_bidi/uni` |
| 4.4.8 | STREAMS_BLOCKED receive | no-op (informational, server may open more) |

**Test gate 4.4:** Client at connection limit, verify DATA_BLOCKED emitted.  Server sends MAX_DATA, verify client unblocks.  Same for stream level.

---

**Phase 4 exit gate:** Bidirectional data transfer over multiple simultaneous streams with correct flow control.  100 MB bulk transfer test passes with no data corruption.

---

## Phase 5 — Loss Detection & Congestion Control

**Goal:** Packet loss is detected and recovered.  The congestion window is correctly maintained.

Depends on: Phase 4 complete (sent-packet tracking populated by stream send path).

### Chunk 5.1 — ACK processing

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 5.1.1 | `ql_ack_record()` | insert pkt-num into `ql_ack_state_t` range list |
| 5.1.2 | Range coalescing | merge adjacent ranges into one |
| 5.1.3 | `ql_ack_build()` | serialise into `ql_frame_ack_t` (and `ACK_ECN` if ECN active) |
| 5.1.4 | ACK send threshold | send after 2 ack-eliciting pkts (§13.2.2) or deadline |
| 5.1.5 | `ql_on_ack_received()` | walk ACK ranges, mark sent-pkts as acked |
| 5.1.6 | RTT update on ACK | update `latest_rtt`, `smoothed_rtt`, `rtt_var` per RFC 9002 §5 |
| 5.1.7 | ACK of ACK | non-ack-eliciting; do not loop |

**Test gate 5.1:** Send 10 packets, receive ACK for [0, 2, 4, 5, 6, 9].  Verify exactly those are marked acked, RTT updated, and range list is [0..0, 2..2, 4..6, 9..9] coalesced.

---

### Chunk 5.2 — Loss detection (RFC 9002 §6)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 5.2.1 | Packet threshold detection | pkt lost if ACK for pkt+3 arrived (§6.1.1) |
| 5.2.2 | Time threshold detection | pkt lost if oldest outstanding > `max(9/8 × SRTT, 1ms)` after largest acked (§6.1.2) |
| 5.2.3 | `ql_loss_detect()` | run both; mark `is_lost`, subtract from `bytes_in_flight` |
| 5.2.4 | Loss time tracking | `cc.loss_time[space]` for earliest outstanding unacked |
| 5.2.5 | PTO arm / disarm | arm when ack-eliciting pkts in flight; disarm on ACK receipt |
| 5.2.6 | PTO expiry | send 1–2 probe packets; increment `pto_count` |
| 5.2.7 | PTO backoff | `PTO = SRTT + max(4×RTTVAR, 1ms) + max_ack_delay × 2^pto_count` |

**Test gate 5.2:** Send pkts 0–9.  Deliver ACK for 3–9, none for 0–2.  Verify 0–2 declared lost by packet threshold.  Separately test time threshold by fast-forwarding `now_ms`.

---

### Chunk 5.3 — Retransmission

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 5.3.1 | `ql_retransmit()` | scan `sent_pkts` for `is_lost`, enqueue by `frame_flags` |
| 5.3.2 | CRYPTO retransmit | re-enqueue original CRYPTO data at same enc-level |
| 5.3.3 | STREAM retransmit | re-send from `tx_buf` at original offset |
| 5.3.4 | Control frame retransmit | MAX_DATA, MAX_STREAM_DATA, NEW_CID, etc. |
| 5.3.5 | New packet number | retransmits always use a new pkt-num (never reuse) |

**Test gate 5.3:** Declare pkt 5 lost (stream data).  Call `ql_retransmit`.  Verify a new packet with a higher pkt-num is enqueued carrying the same stream offset range.

---

### Chunk 5.4 — Congestion control (RFC 9002 §7 — NewReno)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 5.4.1 | `ql_cc_init()` | `cwnd = QL_CC_INITIAL_CWND`, `ssthresh = UINT64_MAX`, SLOW_START |
| 5.4.2 | `ql_cc_can_send()` | `bytes_in_flight + bytes <= cwnd` |
| 5.4.3 | `ql_cc_on_ack()` slow-start | `cwnd += acked_bytes` while cwnd < ssthresh |
| 5.4.4 | `ql_cc_on_ack()` congestion avoidance | `cwnd += MSS × acked_bytes / cwnd` |
| 5.4.5 | `ql_cc_on_loss()` | `ssthresh = max(cwnd/2, QL_CC_MIN_CWND)`, `cwnd = ssthresh`, enter RECOVERY |
| 5.4.6 | Recovery exit | return to CONGESTION_AVD when all pkts at loss time are acked |
| 5.4.7 | `ql_cc_on_ecn_ce()` | treat CE mark as loss signal (same as §7.1 loss event) |

**Test gate 5.4:** Start with default cwnd.  ACK 10 packets in slow-start, verify cwnd doubled.  Inject loss, verify cwnd halved.  ACK all recovery packets, verify state returns to CA.

---

**Phase 5 exit gate:** 1% random packet-loss simulation over loopback.  All data delivered without corruption, retransmit count matches loss count.

---

## Phase 6 — Path Migration & Key Update

**Goal:** Connections survive path changes.  Keys can be updated mid-connection.

Depends on: Phase 5 complete.

### Chunk 6.1 — Path validation (§8.2)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 6.1.1 | `ql_path_probe()` | send PATH_CHALLENGE with 8 random bytes; arm challenge timer |
| 6.1.2 | PATH_CHALLENGE receive | send PATH_RESPONSE with same 8 bytes immediately |
| 6.1.3 | PATH_RESPONSE receive | compare to sent challenge; set `QL_PATH_VALIDATED` |
| 6.1.4 | Challenge timer expiry | retry up to 3 times; then `QL_PATH_FAILED` |

**Test gate 6.1:** Send PATH_CHALLENGE on loopback.  Verify correct PATH_RESPONSE received and path validated.  Drop the response, verify retry and eventual failure.

---

### Chunk 6.2 — Connection migration (§9)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 6.2.1 | `qlite_migrate()` | validate new local address first via 6.1, then promote |
| 6.2.2 | Peer-initiated migration detect | packet arrives from new peer address |
| 6.2.3 | Probing path CC isolation | probing path uses independent CC state §9.4 |
| 6.2.4 | Promote on validation | copy `probing_path` → `active_path`, reset CC |
| 6.2.5 | CID rotation on migration | consume a new remote CID for the new path §9.5 |
| 6.2.6 | `disable_active_migration` guard | return `QLITE_ERR_PROTO` if TP disables it |

**Test gate 6.2:** Simulate client changing port mid-transfer.  Verify PATH_CHALLENGE sent, validation succeeds, data flow continues on new path.  No data loss across migration.

---

### Chunk 6.3 — Key update (RFC 9001 §6)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 6.3.1 | Next-key derivation | `HKDF-Expand-Label(current_secret, "quic ku", …)` |
| 6.3.2 | `ql_key_update_initiate()` | derive `next` keys, set `update_pending` |
| 6.3.3 | Send with flipped key_phase | first 1-RTT packet with new keys sets bit |
| 6.3.4 | Peer key update detect | see key_phase flip on incoming packet |
| 6.3.5 | Decrypt with next keys | try `current` first, then `next` |
| 6.3.6 | Key rotation commit | after successful decrypt with `next`, promote to `current` |
| 6.3.7 | Cooldown period | do not initiate another update until peer acks first §6.5 |

**Test gate 6.3:** Initiate key update.  Verify next 1-RTT packet carries new phase bit.  Peer decrypts with new keys.  Verify old keys are discarded.  Attempt second update before first acked, verify blocked.

---

**Phase 6 exit gate:** Mid-transfer path migration succeeds with no data loss.  Key update completes, old keys are zeroed.

---

## Phase 7 — Server Listener & Connection Close

**Goal:** A server accepts multiple connections.  Connections close gracefully or abruptly.

Depends on: Phase 6 complete.

### Chunk 7.1 — Server demultiplexing

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 7.1.1 | `qlite_listen()` | create UDP socket, init `ql_server_t`, generate token secret |
| 7.1.2 | Datagram dispatch loop | recv → look up `conn` by DCID → route or create |
| 7.1.3 | New-connection path | allocate `ql_conn_t` via `ql_new`, call `ql_conn_init` |
| 7.1.4 | Stateless reset detect | check 16-byte tail against known reset tokens §10.3.1 |
| 7.1.5 | Version Negotiation send | QUIC version unknown → send VN packet, discard datagram |
| 7.1.6 | `QL_SERVER_MAX_CONNS` guard | reject new connections when table is full |

**Test gate 7.1:** Open `qlite_listen`, connect 3 clients simultaneously, verify all 3 land in `conns[]` at different indices.  Send data on all 3.  Verify no cross-talk.

---

### Chunk 7.2 — Connection close (§10)

| Sub-chunk | Symbol(s) | Notes |
|---|---|---|
| 7.2.1 | `qlite_close()` (local initiation) | build CONNECTION_CLOSE, cache in `close_pkt`, enter `CLOSING` |
| 7.2.2 | Echo on receive during CLOSING | re-send `close_pkt` on any inbound packet §10.2.1 |
| 7.2.3 | DRAINING entry | receiving CONNECTION_CLOSE → arm drain timer, no further sends |
| 7.2.4 | Drain timer expiry | `timer_drain` fires → `QL_CONN_CLOSED`; fire `on_close` callback |
| 7.2.5 | Idle timeout (§10.1) | `timer_idle` fires → silent close, fire `on_close` |
| 7.2.6 | `ql_conn_free()` | walk `stream_list`, `ql_del` each stream; zero keys |

**Test gate 7.2:** Client calls `qlite_close`.  Verify server receives CONNECTION_CLOSE, enters DRAINING, fires `on_close` after drain period.  Verify all stream memory freed.  Idle timeout: suppress all packets for idle_timeout_ms, verify connection closes silently.

---

### Chunk 7.3 — The tick loop (`ql_conn_tick`)

This is the glue that drives all previous chunks on every iteration.

| Sub-chunk | What it drives | Notes |
|---|---|---|
| 7.3.1 | Inbound datagram receive | `ql_udp_recv` loop until AGAIN |
| 7.3.2 | Packet dispatch | decrypt → frame loop → route each frame to handler |
| 7.3.3 | TLS progress | `ql_tls_get_data` → CRYPTO frames → send queue |
| 7.3.4 | Stream send scheduling | dequeue from each stream respecting CC + FC |
| 7.3.5 | ACK emission | check `ack_send_deadline_ms`, build + send if due |
| 7.3.6 | Loss detection | call `ql_loss_detect`, then `ql_retransmit` |
| 7.3.7 | Timer checks | idle, drain, PTO, ACK delay, path challenge |
| 7.3.8 | Send queue flush | `ql_udp_send` all enqueued datagrams |
| 7.3.9 | Callback dispatch | `on_connected`, `on_data`, `on_stream_open`, `on_close` |

**Test gate 7.3:** Full end-to-end: client opens connection, opens stream, sends 1 MB, server echoes it back, client verifies data, both close gracefully.  No manual calls other than `ql_conn_tick` in a loop.

---

**Phase 7 exit gate — Final integration test:**

- Server accepts 50 concurrent connections
- Each connection transfers 10 MB bidirectionally over 4 streams
- 2% simulated packet loss injected at UDP layer
- All data delivered correctly (SHA-256 checksum match)
- All connections close cleanly, all memory freed (valgrind clean)
- Peak memory per connection within 10% of `sizeof(ql_conn_t)` + stream count × `sizeof(ql_stream_t)`

---

## Summary table

| Phase | What you can do after | Key test |
|---|---|---|
| 1 | Encode/decode any frame and packet header | Frame round-trip, varint boundary |
| 2 | Protect and open any packet with correct keys | RFC 9001 sample vectors |
| 3 | Complete a QUIC+TLS handshake | Loopback handshake, Retry path |
| 4 | Transfer data on streams with flow control | 100 MB bulk, multi-stream |
| 5 | Recover from packet loss, maintain cwnd | 1% loss, retransmit verification |
| 6 | Migrate paths, update keys mid-connection | Port-change during transfer |
| 7 | Run a multi-client server, close cleanly | 50-client 10 MB integration test |

---

## What is explicitly out of scope (future phases)

- DPLPMTUD / PMTU probing (§14.3)
- DATAGRAM extension (RFC 9221)
- 0-RTT data (structures present, send/receive path deferred)
- CUBIC / BBR congestion controllers (NewReno is Phase 5)
- Multipath QUIC (draft)
- Windows / Winsock socket layer