/**
 * @file    qlite.h
 * @brief   quic-lite — single-header QUIC v1 type definitions (RFC 9000/9001/9002)
 * LICENSE  MIT
 * DATE     2026-06-17
 *
 * PRIMARY RFC REFERENCES
 *   RFC 9000  QUIC: A UDP-Based Multiplexed and Secure Transport
 *   RFC 9001  Using TLS to Secure QUIC
 *   RFC 9002  QUIC Loss Detection and Congestion Control
 */

#ifndef QLITE_H
#define QLITE_H

/* Platform / Compiler Gaurds */

#if defined(__cplusplus)
extern "C" {
#endif

/* C standard headers */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/* POSIX — needed in implementation but declared here so all TUs agree */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

/* Stream ID 2.1 — 62-bit, lower 2 bits encode initiator + direction */
typedef uint64_t ql_stream_id_t;

/* Packet number 12.3 — 62-bit per-packet-number-space counter */
typedef uint64_t ql_pkt_num_t;

/* Connection ID 5.1 — opaque, 1–20 bytes; len=0 means zero-length CID */
#define QL_CID_MAX_LEN  20
typedef struct {
    uint8_t  data[QL_CID_MAX_LEN];
    uint8_t  len;                    /* 0 = zero-length (5.1) */
} ql_cid_t;

/* Stateless Reset Token 10.3.2 — exactly 16 bytes */
#define QL_RESET_TOKEN_LEN  16
typedef struct {
    uint8_t  data[QL_RESET_TOKEN_LEN];
} ql_reset_token_t;

/* Path validation data 19.17–19.18 — exactly 8 bytes */
#define QL_PATH_DATA_LEN  8
typedef struct {
    uint8_t  data[QL_PATH_DATA_LEN];
} ql_path_data_t;

/*
 * One contiguous ACK range: acknowledges all packets in
 * [largest − (count − 1), largest].
 */
typedef struct {
    ql_pkt_num_t  largest;
    uint64_t      count;    /* number of contiguous packet numbers */
} ql_ack_range_t;

/* 13.2 — ACK tracking */
#define QL_ACK_RANGE_MAX        64    /* max ACK ranges we track in one frame */
#define QL_ACK_DELAY_THRESHOLD  2     /* send ACK after this many ack-eliciting pkts */
#define QL_ACK_TIMEOUT_MS      25     /* max ACK delay when not in threshold path */

/* 
 * Transport ERR codes  20.1
 */
typedef enum {
    QL_ERR_NO_ERROR                  = 0x00,
    QL_ERR_INTERNAL_ERROR            = 0x01,
    QL_ERR_CONNECTION_REFUSED        = 0x02,
    QL_ERR_FLOW_CONTROL_ERROR        = 0x03,
    QL_ERR_STREAM_LIMIT_ERROR        = 0x04,
    QL_ERR_STREAM_STATE_ERROR        = 0x05,
    QL_ERR_FINAL_SIZE_ERROR          = 0x06,
    QL_ERR_FRAME_ENCODING_ERROR      = 0x07,
    QL_ERR_TRANSPORT_PARAMETER_ERROR = 0x08,
    QL_ERR_CONNECTION_ID_LIMIT_ERROR = 0x09,
    QL_ERR_PROTOCOL_VIOLATION        = 0x0A,
    QL_ERR_INVALID_TOKEN             = 0x0B,
    QL_ERR_APPLICATION_ERROR         = 0x0C,
    QL_ERR_CRYPTO_BUFFER_EXCEEDED    = 0x0D,
    QL_ERR_KEY_UPDATE_ERROR          = 0x0E,
    QL_ERR_AEAD_LIMIT_REACHED        = 0x0F,
    QL_ERR_NO_VIABLE_PATH            = 0x10,
    /*
     * 20.1 — TLS alert codes 6 RFC 9001.
     * CRYPTO_ERROR base: 0x0100 + TLS alert value.
     */
    QL_ERR_CRYPTO_ERROR_BASE         = 0x0100,
} ql_transport_error_t;

/* Application-protocol error codes 20.2 — opaque 62-bit integer */
typedef uint64_t ql_app_error_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html?#name-frame-types-and-formats
 */
typedef enum {
    /* 19.1  */ QL_FRAME_PADDING               = 0x00,
    /* 19.2  */ QL_FRAME_PING                  = 0x01,
    /* 19.3  */ QL_FRAME_ACK                   = 0x02,  /* no ECN counts  */
    /* 19.3  */ QL_FRAME_ACK_ECN               = 0x03,  /* with ECN counts */
    /* 19.4  */ QL_FRAME_RESET_STREAM          = 0x04,
    /* 19.5  */ QL_FRAME_STOP_SENDING          = 0x05,
    /* 19.6  */ QL_FRAME_CRYPTO                = 0x06,
    /* 19.7  */ QL_FRAME_NEW_TOKEN             = 0x07,
    /* 19.8 — STREAM flags OR'd into 0x08 */
    /* 19.8  */ QL_FRAME_STREAM                = 0x08,  /* OFF=0,LEN=0,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_FIN            = 0x09,  /* OFF=0,LEN=0,FIN=1 */
    /* 19.8  */ QL_FRAME_STREAM_LEN            = 0x0A,  /* OFF=0,LEN=1,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_LEN_FIN        = 0x0B,  /* OFF=0,LEN=1,FIN=1 */
    /* 19.8  */ QL_FRAME_STREAM_OFF            = 0x0C,  /* OFF=1,LEN=0,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_OFF_FIN        = 0x0D,  /* OFF=1,LEN=0,FIN=1 */
    /* 19.8  */ QL_FRAME_STREAM_OFF_LEN        = 0x0E,  /* OFF=1,LEN=1,FIN=0 */
    /* 19.8  */ QL_FRAME_STREAM_OFF_LEN_FIN    = 0x0F,  /* OFF=1,LEN=1,FIN=1 */
    /* 19.9  */ QL_FRAME_MAX_DATA              = 0x10,
    /* 19.10 */ QL_FRAME_MAX_STREAM_DATA       = 0x11,
    /* 19.11 */ QL_FRAME_MAX_STREAMS_BIDI      = 0x12,
    /* 19.11 */ QL_FRAME_MAX_STREAMS_UNI       = 0x13,
    /* 19.12 */ QL_FRAME_DATA_BLOCKED          = 0x14,
    /* 19.13 */ QL_FRAME_STREAM_DATA_BLOCKED   = 0x15,
    /* 19.14 */ QL_FRAME_STREAMS_BLOCKED_BIDI  = 0x16,
    /* 19.14 */ QL_FRAME_STREAMS_BLOCKED_UNI   = 0x17,
    /* 19.15 */ QL_FRAME_NEW_CONNECTION_ID     = 0x18,
    /* 19.16 */ QL_FRAME_RETIRE_CONNECTION_ID  = 0x19,
    /* 19.17 */ QL_FRAME_PATH_CHALLENGE        = 0x1A,
    /* 19.18 */ QL_FRAME_PATH_RESPONSE         = 0x1B,
    /* 19.19 */ QL_FRAME_CONNECTION_CLOSE      = 0x1C,  /* transport error */
    /* 19.19 */ QL_FRAME_CONNECTION_CLOSE_APP  = 0x1D,  /* app-layer error */
    /* 19.20 */ QL_FRAME_HANDSHAKE_DONE        = 0x1E,
} ql_frame_type_t;

/*
    A PADDING frame (type=0x00) has no semantic value. 
    PADDING frames can be used to increase the size of a packet. 
    Padding can be used to increase an Initial packet to the 
    minimum required size or to provide protection against traffic 
    analysis for protected packets
*/
typedef struct {
    size_t  length;   /* number of zero bytes emitted or consumed */
} ql_frame_padding_t;

/*
    Endpoints can use PING frames (type=0x01) to verify that their 
    peers are still alive or to check reachability to the peer.
*/
typedef struct {
    uint8_t _dummy;
} ql_frame_ping_t;

/* ACK / ACK_ECN 
    Receivers send ACK frames (types 0x02 and 0x03) to inform senders 
    of packets they have received and processed. The ACK frame contains 
    one or more ACK Ranges. ACK Ranges identify acknowledged packets. 
    If the frame type is 0x03, ACK frames also contain the cumulative 
    count of QUIC packets with associated ECN marks received on the 
    connection up until this point. QUIC implementations MUST properly 
    handle both types, and, if they have enabled ECN for packets they 
    send, they SHOULD use the information in the ECN section to manage 
    their congestion state.
*/
typedef struct {
    ql_pkt_num_t   largest_acked;
    uint64_t       ack_delay;          /* in 2^ack_delay_exponent µs units */
    uint64_t       range_count;        /* additional ACK range pairs */
    uint64_t       first_ack_range;    /* acked packets below largest_acked */
    ql_ack_range_t ranges[QL_ACK_RANGE_MAX];
    /* 19.3.2 — ECN counts, present only in ACK_ECN frame */
    uint64_t  ect0_count;
    uint64_t  ect1_count;
    uint64_t  ecn_ce_count;
    bool      has_ecn;
} ql_frame_ack_t;

/*
    An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly 
    terminate the sending part of a stream.
    After sending a RESET_STREAM, an endpoint ceases transmission 
    and retransmission of STREAM frames on the identified stream. 
    A receiver of RESET_STREAM can discard any data that it already 
    received on that stream.
    An endpoint that receives a RESET_STREAM frame for a send-only 
    stream MUST terminate the connection with error STREAM_STATE_ERROR.
*/
typedef struct {
    ql_stream_id_t  stream_id;
    ql_app_error_t  error_code;
    uint64_t        final_size;   /* byte offset of stream end */
} ql_frame_reset_stream_t;

/*
    An endpoint uses a STOP_SENDING frame (type=0x05) to communicate 
    that incoming data is being discarded on receipt per application 
    request. STOP_SENDING requests that a peer cease transmission on 
    a stream.
    A STOP_SENDING frame can be sent for streams in the "Recv" or 
    "Size Known" states; see Section 3.2. Receiving a STOP_SENDING 
    frame for a locally initiated stream that has not yet been created 
    MUST be treated as a connection error of type STREAM_STATE_ERROR. 
    An endpoint that receives a STOP_SENDING frame for a receive-only 
    stream MUST terminate the connection with error STREAM_STATE_ERROR.
*/
typedef struct {
    ql_stream_id_t  stream_id;
    ql_app_error_t  error_code;
} ql_frame_stop_sending_t;

/*
    A CRYPTO frame (type=0x06) is used to transmit cryptographic handshake 
    messages. It can be sent in all packet types except 0-RTT. The CRYPTO 
    frame offers the cryptographic protocol an in-order stream of bytes. 
    CRYPTO frames are functionally identical to STREAM frames, except that 
    they do not bear a stream identifier; they are not flow controlled; 
    and they do not carry markers for optional offset, optional length, 
    and the end of the stream.
*/
typedef struct {
    uint64_t        offset;
    uint64_t        length;
    const uint8_t  *data;   /* points into decode buffer — not owned */
} ql_frame_crypto_t;

/*
    A server sends a NEW_TOKEN frame (type=0x07) to provide the client 
    with a token to send in the header of an Initial packet for a future 
    connection.
*/
typedef struct {
    uint64_t        token_length;
    const uint8_t  *token;  /* points into decode buffer — not owned */
} ql_frame_new_token_t;

/*
    STREAM frames implicitly create a stream and carry stream data. 
    The Type field in the STREAM frame takes the form 0b00001XXX 
    (or the set of values from 0x08 to 0x0f). The three low-order 
    bits of the frame type determine the fields that are present in 
    the frame:
        The OFF bit (0x04) in the frame type is set to indicate that 
    there is an Offset field present. When set to 1, the Offset field 
    is present. When set to 0, the Offset field is absent and the 
    Stream Data starts at an offset of 0 (that is, the frame contains 
    the first bytes of the stream, or the end of a stream that includes 
    no data).
        The LEN bit (0x02) in the frame type is set to indicate that 
    there is a Length field present. If this bit is set to 0, the 
    Length field is absent and the Stream Data field extends to t
    he end of the packet. If this bit is set to 1, the Length field 
    is present.
        The FIN bit (0x01) indicates that the frame
*/
typedef struct {
    ql_stream_id_t  stream_id;
    uint64_t        offset;       /* present only if has_offset; else 0 */
    uint64_t        length;       /* present only if has_length */
    const uint8_t  *data;         /* points into decode buffer — not owned */
    bool            has_offset;   /* OFF bit */
    bool            has_length;   /* LEN bit */
    bool            fin;          /* FIN bit */
} ql_frame_stream_t;


typedef struct {
    uint64_t  maximum_data;
} ql_frame_max_data_t;

typedef struct {
    ql_stream_id_t  stream_id;
    uint64_t        maximum_stream_data;
} ql_frame_max_stream_data_t;

typedef struct {
    uint64_t  maximum_streams;
} ql_frame_max_streams_t;

/*
    A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes 
    to send data but is unable to do so due to connection-level flow control; 
    see Section 4. DATA_BLOCKED frames can be used as input to tuning of 
    flow control algorithms; 
*/
typedef struct {
    uint64_t  data_limit;   /* connection-level limit we're blocked at */
} ql_frame_data_blocked_t;

/*
    A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it 
    wishes to send data but is unable to do so due to stream-level flow 
    control. This frame is analogous to DATA_BLOCKED
*/
typedef struct {
    ql_stream_id_t  stream_id;
    uint64_t        stream_data_limit;
} ql_frame_stream_data_blocked_t;

/*
    A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) 
    when it wishes to open a stream but is unable to do so due to the 
    maximum stream limit set by its peer; A STREAMS_BLOCKED 
    frame of type 0x16 is used to indicate reaching the bidirectional 
    stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to 
    indicate reaching the unidirectional stream limit.
*/
typedef struct {
    uint64_t  stream_limit;
} ql_frame_streams_blocked_t;

/*
    An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide 
    its peer with alternative connection IDs that can be used to break 
    linkability when migrating connections;
*/
typedef struct {
    uint64_t          sequence_num;
    uint64_t          retire_prior_to;
    ql_cid_t          cid;
    ql_reset_token_t  stateless_reset_token;
} ql_frame_new_cid_t;

/*
    An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to 
    indicate that it will no longer use a connection ID that was 
    issued by its peer. This includes the connection ID provided 
    during the handshake. Sending a RETIRE_CONNECTION_ID frame also 
    serves as a request to the peer to send additional connection 
    IDs for future use; New connection IDs can be 
    delivered to a peer using the NEW_CONNECTION_ID frame
*/
typedef struct {
    uint64_t  sequence_num;
} ql_frame_retire_cid_t;

/*
    Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check 
    reachability to the peer and for path validation during 
    connection migration.
*/
typedef struct {
    ql_path_data_t  data;   /* 8 random bytes */
} ql_frame_path_challenge_t;

/*
    A PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE frame.
*/
typedef struct {
    ql_path_data_t  data;   /* verbatim echo of the PATH_CHALLENGE data */
} ql_frame_path_response_t;

/*
    An endpoint sends a CONNECTION_CLOSE frame (type=0x1c or 0x1d) 
    to notify its peer that the connection is being closed. The 
    CONNECTION_CLOSE frame with a type of 0x1c is used to signal 
    errors at only the QUIC layer, or the absence of errors 
    (with the NO_ERROR code). The CONNECTION_CLOSE frame with a 
    type of 0x1d is used to signal an error with the application 
    that uses QUIC.
*/
typedef struct {
    ql_transport_error_t  error_code;      /* transport close: 20.1 code */
    ql_app_error_t        app_error_code;  /* app close: opaque error code */
    ql_frame_type_t       frame_type;      /* causal frame type (0x1C only) */
    uint64_t              reason_length;
    const uint8_t        *reason_phrase;   /* UTF-8, not null-terminated */
    bool                  is_app;          /* true → 0x1D, false → 0x1C */
} ql_frame_conn_close_t;

/*
    The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal 
    confirmation of the handshake to the client.
*/
typedef struct {
    uint8_t _dummy;
} ql_frame_handshake_done_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4-6
 */
typedef struct {
    ql_frame_type_t  type;
    union {
        ql_frame_padding_t              padding;
        ql_frame_ping_t                 ping;
        ql_frame_ack_t                  ack;
        ql_frame_reset_stream_t         reset_stream;
        ql_frame_stop_sending_t         stop_sending;
        ql_frame_crypto_t               crypto;
        ql_frame_new_token_t            new_token;
        ql_frame_stream_t               stream;
        ql_frame_max_data_t             max_data;
        ql_frame_max_stream_data_t      max_stream_data;
        ql_frame_max_streams_t          max_streams;
        ql_frame_data_blocked_t         data_blocked;
        ql_frame_stream_data_blocked_t  stream_data_blocked;
        ql_frame_streams_blocked_t      streams_blocked;
        ql_frame_new_cid_t              new_cid;
        ql_frame_retire_cid_t           retire_cid;
        ql_frame_path_challenge_t       path_challenge;
        ql_frame_path_response_t        path_response;
        ql_frame_conn_close_t           conn_close;
        ql_frame_handshake_done_t       handshake_done;
    } u;
} ql_frame_t;

/*
 * One directional key set for a single encryption level.
 * Holds the AEAD key, the per-packet IV (nonce base), and the
 * header-protection key (hp).
 */
typedef struct {
    uint8_t  key[QL_AEAD_KEY_MAX_LEN];
    uint8_t  iv[QL_AEAD_IV_MAX_LEN];
    uint8_t  hp[QL_HP_KEY_MAX_LEN];
    uint8_t  key_len;
    uint8_t  iv_len;
    uint8_t  hp_len;
    bool     is_set;
} ql_keys_t;

/* Read + write keys for one encryption level */
typedef struct {
    ql_keys_t  read;   /* decryption */
    ql_keys_t  write;  /* encryption */
} ql_key_pair_t;

/*
 * Key update state — RFC 9001 6.
 * We keep both the current and next key phases so we can decrypt
 * packets that arrive using the new phase before we've fully rotated.
 */
typedef struct {
    ql_key_pair_t  current;           /* keys for the active phase */
    ql_key_pair_t  next;              /* keys derived ready for next phase */
    bool           current_phase;     /* 0 or 1 — matches key_phase bit */
    bool           update_pending;    /* we've triggered an update, not sent yet */
    bool           peer_updated;      /* we saw the peer's key_phase flip */
    uint64_t       update_sent_pn;    /* first pkt-num sent with new key */
} ql_key_update_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html?#name-packet-formats
 */
/* Long header (Initial, 0-RTT, Handshake, Retry) 17.2 */
/*
    Long headers are used for packets that are sent prior to the 
    establishment of 1-RTT keys. Once 1-RTT keys are available, 
    a sender switches to sending packets using the short header
*/
typedef struct {
    ql_pkt_type_t  pkt_type;
    uint8_t        first_byte;
    uint32_t       version;
    ql_cid_t       dst_cid;
    ql_cid_t       src_cid;
    /* Initial only 17.2.2 */
    uint8_t        token[QL_TOKEN_MAX_LEN];
    size_t         token_len;
    /* Retry only 17.2.5 — AES-128-GCM tag, 16 bytes */
    uint8_t        retry_integrity_tag[QL_AEAD_TAG_LEN];
    bool           is_retry;
    /* Present in Initial, 0-RTT, Handshake (not Retry, not VN) */
    uint64_t       length;       /* payload length varint */
    ql_pkt_num_t   pkt_num;      /* decoded full packet number */
    uint8_t        pkt_num_len;  /* encoded width: 1–4 bytes */
} ql_long_hdr_t;

/* Short (1-RTT) header 17.3.1 */
typedef struct {
    uint8_t       first_byte;
    ql_cid_t      dst_cid;
    ql_pkt_num_t  pkt_num;
    uint8_t       pkt_num_len;
    bool          spin_bit;   /* 17.4 */
    bool          key_phase;  /* RFC 9001 5.4 */
} ql_short_hdr_t;

/* Unified view after parsing */
typedef struct {
    bool  is_long;
    union {
        ql_long_hdr_t   lhdr;
        ql_short_hdr_t  shdr;
    } h;
    /* Decrypted payload slice within the datagram buffer (AEAD tag removed) */
    const uint8_t  *payload;
    size_t          payload_len;
} ql_pkt_hdr_t;

/* 17.2.1 — Version Negotiation Packet */
typedef struct {
    ql_cid_t  dst_cid;
    ql_cid_t  src_cid;
    uint32_t  versions[QL_MAX_VERSIONS];
    int       version_count;
} ql_ver_neg_pkt_t;

/**
 * PUBLIC API
 */
int  ql_frame_encode(const ql_frame_t *frame, uint8_t *buf, size_t cap);
int  ql_frame_decode(const uint8_t *buf, size_t len, ql_frame_t *out);

int  ql_pkt_encode(const ql_pkt_hdr_t *hdr, const ql_keys_t *key,
                    const uint8_t *payload, size_t payload_len,
                    uint8_t *out, size_t cap);
int  ql_pkt_decode(const uint8_t *buf, size_t len, const ql_keys_t *key,
                    ql_pkt_hdr_t *hdr_out, uint8_t *payload_out, size_t cap);

#if defined(__cplusplus)
} /* extern "C" */
#endif
#endif /* QLITE_H */