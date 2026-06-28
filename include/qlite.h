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
#define _POSIX_C_SOURCE 199309L
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

/* helpers*/
/* Write Varint — encodes val, advances pos, returns error on overflow */
#define WV(val) \
    do { int _n = ql_varint_encode(buf+pos, cap-pos, (uint64_t)(val)); \
         if (_n < 0) return _n; \
         pos += (size_t)_n; \
    } while(0)
/* Write Bytes — copies raw bytes, advances pos, returns error on overflow */
#define WB(ptr, len) \
    do { size_t _l = (size_t)(len); \
         if (pos + _l > cap) return QLITE_ERR_BUF; \
         memcpy(buf + pos, (ptr), _l); \
         pos += _l; \
    } while(0)

#define TP_VARINT(id, val) \
    do { if (tp_write_varint(buf, &pos, cap, (id), (val)) < 0) \
        return QLITE_ERR_BUF; \
    } while(0)
#define TP_BYTES(id, data, len) \
    do { if (tp_write_bytes(buf, &pos, cap, (id), (data), (len)) < 0) return QLITE_ERR_BUF; } while(0)
#define TP_CID(id, cid) \
    do { if (tp_write_cid(buf, &pos, cap, (id), (cid)) < 0) return QLITE_ERR_BUF; } while(0)

#define RV(field)                                                          \
    do {                                                                   \
        ql_varint_t _v;                                                    \
        int _n = ql_varint_decode(buf + pos, len - pos, &_v);             \
        if (_n < 0 || pos + (size_t)_n > len) return QLITE_ERR_BUF;      \
        (field) = (__typeof__(field))_v;                                   \
        pos += (size_t)_n;                                                 \
    } while (0)

#define RB(dst, n)                                                         \
    do {                                                                   \
        size_t _l = (size_t)(n);                                           \
        if (pos + _l > len) return QLITE_ERR_BUF;                         \
        memcpy((dst), buf + pos, _l);                                      \
        pos += _l;                                                         \
    } while (0)


/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
 * QUIC variable-length integer (varint).  Wire encoding uses 2 MSBs of the
 * first byte to signal total byte-width:
 *
 *   prefix 00 → 1 byte  (6-bit value,  max 63)
 *   prefix 01 → 2 bytes (14-bit value, max 16 383)
 *   prefix 10 → 4 bytes (30-bit value, max 1 073 741 823)
 *   prefix 11 → 8 bytes (62-bit value, max 4 611 686 018 427 387 903)
 *
 * 16 Table 1.
 */
typedef uint64_t ql_varint_t;
#define QL_VARINT_MAX      UINT64_C(4611686018427387903)  /* 2^62 − 1  §16 */
#define QL_VARINT_1B_MAX   UINT64_C(63)
#define QL_VARINT_2B_MAX   UINT64_C(16383)
#define QL_VARINT_4B_MAX   UINT64_C(1073741823)

/* Minimum encoded sizes for varints — useful for buffer-size assertions */
#define QL_VARINT_1B_SIZE  1
#define QL_VARINT_2B_SIZE  2
#define QL_VARINT_4B_SIZE  4
#define QL_VARINT_8B_SIZE  8

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

/* 15 — QUIC version identifiers */
#define QL_VERSION_1              UINT32_C(0x00000001)  /* QUIC v1 */
#define QL_VERSION_NEGOTIATION    UINT32_C(0x00000000)  /* Version Negotiation 17.2.1 */
#define QL_VERSION_RESERVED_MASK  UINT32_C(0x0A0A0A0A)  /* 6.3 force version-neg */

/* 14.1 — Datagram / MTU limits */
#define QL_MIN_INITIAL_DATAGRAM_SIZE  1200  /* client Initial MUST be >= 1200 bytes */
#define QL_MIN_UDP_PAYLOAD_SIZE       1200  /* 14.1 path minimum */
#define QL_MAX_UDP_PAYLOAD_DEFAULT    65527 /* 18.2 tp default */
#define QL_PATH_MTU_DEFAULT           1200  /* conservative initial MTU */
#define QL_PATH_MTU_ETHERNET          1472  /* 1500 - 20(IP) - 8(UDP) */

/* 13.2 — ACK tracking */
#define QL_ACK_RANGE_MAX        64    /* max ACK ranges we track in one frame */
#define QL_ACK_DELAY_THRESHOLD  2     /* send ACK after this many ack-eliciting pkts */
#define QL_ACK_TIMEOUT_MS      25     /* max ACK delay when not in threshold path */

/* Key material sizes (RFC 9001) */
#define QL_AEAD_KEY_MAX_LEN   32   /* AES-256-GCM key */
#define QL_AEAD_IV_MAX_LEN    12   /* AEAD nonce / IV */
#define QL_HP_KEY_MAX_LEN     32   /* header-protection key */
#define QL_SECRET_MAX_LEN     48   /* HKDF secret (SHA-384 output size) */

/* 12.1 / RFC 9001 5.3 — AEAD tag is always 16 bytes */
#define QL_AEAD_TAG_LEN  16

/* Server limits */
#define QL_SERVER_MAX_CONNS    1024
#define QL_MAX_CIDS            8      /* connection IDs we issue/track 5.1 */
#define QL_MAX_VERSIONS        16     /* Version Negotiation list */

/* 21.3 — Anti-amplification limit: 3x received bytes before addr validation */
#define QL_AMPLIFICATION_FACTOR  3

/*
 * 8.1 — A Retry token carries:
 *   - the original client address (for anti-spoofing)
 *   - a timestamp (for anti-replay 8.1.4)
 * We store an opaque encrypted blob limited to 256 bytes.
 */
#define QL_TOKEN_MAX_LEN  256

typedef struct {
    uint8_t   data[QL_TOKEN_MAX_LEN];
    size_t    len;
    uint64_t  issued_at_ms;   /* wall-clock when we generated this token */
} ql_token_t;

/*
 * 21.3 — Anti-amplification: server MUST NOT send more than
 * QL_AMPLIFICATION_FACTOR × bytes_received until address is validated.
 */
typedef struct {
    bool      validated;          /* true once address confirmed */
    uint64_t  bytes_received;     /* from unvalidated peer address */
    uint64_t  bytes_sent;         /* to unvalidated peer address */
} ql_addr_valid_t;

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

typedef enum {
    QLITE_OK           =  0,
    QLITE_ERR_AGAIN    = -1,   /* would block — try again */
    QLITE_ERR_BUF      = -2,   /* destination buffer too small */
    QLITE_ERR_PROTO    = -3,   /* protocol violation */
    QLITE_ERR_CRYPTO   = -4,   /* AEAD authentication failure / TLS error */
    QLITE_ERR_STREAM   = -5,   /* invalid stream state transition */
    QLITE_ERR_FC       = -6,   /* flow-control limit exceeded */
    QLITE_ERR_ARGS     = -7,   /* invalid arguments */
    QLITE_ERR_NOMEM    = -8,   /* allocation failure */
    QLITE_ERR_CLOSED   = -9,   /* connection or stream already closed */
    QLITE_ERR_INTERNAL = -10,  /* internal / unexpected error */
    QLITE_ERR_WOULDBLOCK = -11, /* non-blocking socket would block */
} qlite_err_t;

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

/* 19.8 — STREAM frame bit-flags (within 0x08..0x0F) */
#define QL_STREAM_FLAG_FIN  0x01u
#define QL_STREAM_FLAG_LEN  0x02u
#define QL_STREAM_FLAG_OFF  0x04u

/* 18.2 — Transport parameter defaults */
#define QL_DEFAULT_ACK_DELAY_EXP     3    /* 2^3 = 8 µs units */
#define QL_DEFAULT_MAX_ACK_DELAY_MS  25
#define QL_DEFAULT_ACTIVE_CID_LIMIT  2
/* 
 *      TRANSPORT PARAMETERS  7.4 / 18.2
 *      Exchanged inside the TLS handshake ClientHello / EncryptedExtensions.
 */

typedef enum {
    QL_TP_ORIGINAL_DST_CID                   = 0x00,
    QL_TP_MAX_IDLE_TIMEOUT                   = 0x01,  /* varint, ms */
    QL_TP_STATELESS_RESET_TOKEN              = 0x02,  /* 16 bytes */
    QL_TP_MAX_UDP_PAYLOAD_SIZE               = 0x03,  /* varint, >= 1200 */
    QL_TP_INITIAL_MAX_DATA                   = 0x04,
    QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05,
    QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE= 0x06,
    QL_TP_INITIAL_MAX_STREAM_DATA_UNI        = 0x07,
    QL_TP_INITIAL_MAX_STREAMS_BIDI           = 0x08,
    QL_TP_INITIAL_MAX_STREAMS_UNI            = 0x09,
    QL_TP_ACK_DELAY_EXPONENT                 = 0x0A,  /* default 3 */
    QL_TP_MAX_ACK_DELAY                      = 0x0B,  /* varint, ms, default 25 */
    QL_TP_DISABLE_ACTIVE_MIGRATION           = 0x0C,  /* empty presence = true */
    QL_TP_PREFERRED_ADDRESS                  = 0x0D,  /* server only */
    QL_TP_ACTIVE_CONNECTION_ID_LIMIT         = 0x0E,  /* varint, >= 2 */
    QL_TP_INITIAL_SOURCE_CID                 = 0x0F,
    QL_TP_RETRY_SOURCE_CID                   = 0x10,
} ql_tp_id_t;

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
typedef enum {
    QL_PKT_VERSION_NEGOTIATION = 0,  /* §17.2.1 — special, no type bits */
    QL_PKT_INITIAL             = 1,  /* §17.2.2 — long header, type 0x00 */
    QL_PKT_0RTT                = 2,  /* §17.2.3 — long header, type 0x01 */
    QL_PKT_HANDSHAKE           = 3,  /* §17.2.4 — long header, type 0x02 */
    QL_PKT_RETRY               = 4,  /* §17.2.5 — long header, type 0x03 */
    QL_PKT_1RTT                = 5,  /* §17.3.1 — short header */
} ql_pkt_type_t;
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
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#name-servers-preferred-address
 */
/* 9.6.1 / 18.2 — server's preferred address */
typedef struct {
    uint8_t           ipv4[4];
    uint16_t          ipv4_port;
    uint8_t           ipv6[16];
    uint16_t          ipv6_port;
    ql_cid_t          cid;
    ql_reset_token_t  reset_token;
} ql_preferred_addr_t;

/**
 * @link: https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-definit
 */
/* Full set of negotiated transport parameters for one peer */
typedef struct {
    uint64_t  max_idle_timeout_ms;                   /* 0 = disabled */
    uint64_t  max_udp_payload_size;                  /* default 65527 */
    uint64_t  initial_max_data;
    uint64_t  initial_max_stream_data_bidi_local;
    uint64_t  initial_max_stream_data_bidi_remote;
    uint64_t  initial_max_stream_data_uni;
    uint64_t  initial_max_streams_bidi;
    uint64_t  initial_max_streams_uni;
    uint64_t  ack_delay_exponent;                    /* default 3 */
    uint64_t  max_ack_delay_ms;                      /* default 25 */
    uint64_t  active_cid_limit;                      /* >= 2 */
    bool      disable_active_migration;

    ql_cid_t  original_dst_cid;
    ql_cid_t  initial_src_cid;
    ql_cid_t  retry_src_cid;
    bool      has_retry_src_cid;

    bool              has_stateless_reset_token;
    ql_reset_token_t  stateless_reset_token;

    bool                has_preferred_addr;
    ql_preferred_addr_t preferred_addr;
} ql_transport_params_t;
/**
 * PUBLIC API
 */
int  ql_varint_encoded_len(ql_varint_t val){
    if (val <= 63)
        return 1;

    if (val <= 16383)
        return 2;

    if (val <= 1073741823ULL)
        return 4;

    if (val <= 4611686018427387903ULL)
        return 8;

    return -1; /* invalid QUIC varint */
}       /* returns 1/2/4/8 */
/*
    we use the first two MSB to represent the length of the integer
    2MSB	Length	Usable Bits	Range
    00	       1	 6	    0-63
    01	       2	 14	    0-16383
    10	       4	 30	    0-1073741823
    11	       8	 62	    0-4611686018427387903
*/
int  ql_varint_encode(uint8_t *buf, size_t cap, ql_varint_t val){
    int len = ql_varint_encoded_len(val);
    
    if (cap < (size_t)len) return -1;
    switch (len) {
    case 1:
        buf[0] = (uint8_t)val;
        break;

    case 2:
        buf[0] = 0x40 | ((val >> 8) & 0x3F);
        buf[1] = (uint8_t)(val & 0xFF);
        break;

    case 4:
        buf[0] = 0x80 | ((val >> 24) & 0x3F);
        for (int i = 1; i < 4; i++) {
            buf[i] = (uint8_t)((val >> (24 - 8 * i)) & 0xFF);
        }
        break;

    case 8:
        buf[0] = 0xC0 | ((val >> 56) & 0x3F);
        for (int i = 1; i < 8; i++) {
            buf[i] = (uint8_t)((val >> (56 - 8 * i)) & 0xFF);
        }
        break;
    }

    return len;
}
int  ql_varint_decode(const uint8_t *buf, size_t len, ql_varint_t *out){
    if (!buf || !out || len == 0)
        return -1;

    uint8_t first = buf[0];
    uint8_t prefix = first >> 6;
    size_t vlen = 1u << prefix;

    if (len < vlen)
        return -1;

    ql_varint_t v = first & 0x3F;

    for (size_t i = 1; i < vlen; i++) {
        v = (v << 8) | buf[i];
    }

    *out = v;
    return (int)vlen;
}

/**
 * Helpers
 */
/* Helper: write a varint-valued TP field */
static int tp_write_varint(uint8_t *buf, size_t *pos, size_t cap,
                             ql_tp_id_t id, uint64_t val)
{
    int id_n  = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)id);
    if (id_n < 0) return id_n;
    *pos += (size_t)id_n;

    /* Compute value encoding to know length */
    uint8_t tmp[8];
    int val_n = ql_varint_encode(tmp, sizeof(tmp), val);
    if (val_n < 0) return val_n;

    int len_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)val_n);
    if (len_n < 0) return len_n;
    *pos += (size_t)len_n;

    if (*pos + (size_t)val_n > cap) return QLITE_ERR_BUF;
    memcpy(buf + *pos, tmp, (size_t)val_n);
    *pos += (size_t)val_n;
    return 0;
}

/* Helper: write a raw-bytes TP field */
static int tp_write_bytes(uint8_t *buf, size_t *pos, size_t cap,
                            ql_tp_id_t id, const uint8_t *data, size_t data_len)
{
    int id_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)id);
    if (id_n < 0) return id_n;
    *pos += (size_t)id_n;

    int len_n = ql_varint_encode(buf + *pos, cap - *pos, (uint64_t)data_len);
    if (len_n < 0) return len_n;
    *pos += (size_t)len_n;

    if (*pos + data_len > cap) return QLITE_ERR_BUF;
    memcpy(buf + *pos, data, data_len);
    *pos += data_len;
    return 0;
}

/* Helper: write a CID-valued TP */
static int tp_write_cid(uint8_t *buf, size_t *pos, size_t cap,
                          ql_tp_id_t id, const ql_cid_t *cid)
{
    return tp_write_bytes(buf, pos, cap, id, cid->data, cid->len);
}

/*
 * ql_now_ms — monotonic clock in milliseconds.
 * Uses CLOCK_MONOTONIC to avoid wall-clock jumps.
 */
uint64_t ql_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

// /* Write n bytes of val into buf in big-endian order. */
// static void ql__write_be(uint8_t *buf, uint64_t val, int n) {
//     for (int i = n - 1; i >= 0; i--) {
//         buf[i] = (uint8_t)(val & 0xFF);
//         val >>= 8;
//     }
// }

/* Bounds-checked varint read from buf[pos..len], advance pos. */
static int ql__read_varint(const uint8_t *buf, size_t *pos, size_t len, ql_varint_t *out) {
    if (*pos >= len) return QLITE_ERR_BUF;
    int n = ql_varint_decode(buf + *pos, len - *pos, out);
    if (n < 0) return n;
    *pos += (size_t)n;
    return n;
}

int  ql_pkt_num_encode(uint8_t *buf, ql_pkt_num_t full_pn,ql_pkt_num_t largest_acked){
    uint64_t n_unacked;
    int pn_len;

    if(full_pn <= largest_acked) n_unacked = 1;
    else n_unacked = full_pn - largest_acked;

    if (n_unacked < (1ULL << 7)) pn_len = 1;
    else if (n_unacked < (1ULL << 15)) pn_len = 2;
    else if (n_unacked < (1ULL << 23)) pn_len = 3;
    else pn_len = 4;

    for(int i = 0; i< pn_len; i++)
        buf[pn_len - 1 -i] = (uint8_t)(full_pn >> (i*8)); 

    return pn_len;
}

ql_pkt_num_t ql_pkt_num_decode(uint64_t truncated_pn, int pn_nbits,ql_pkt_num_t largest_pn){
    /* Next packet number we expect. */
    ql_pkt_num_t expected_pn = largest_pn + 1;

    /* Packet number reconstruction window. */
    ql_pkt_num_t pn_win  = (ql_pkt_num_t)1 << pn_nbits;
    ql_pkt_num_t pn_hwin = pn_win / 2;
    ql_pkt_num_t pn_mask = pn_win - 1;

    /* Reconstruct using expected packet number's upper bits. */
    ql_pkt_num_t candidate_pn =
        (expected_pn & ~pn_mask) | truncated_pn;

    /* Candidate is too far behind. */
    if (candidate_pn + pn_hwin <= expected_pn &&
        candidate_pn < ((1ULL << 62) - pn_win))
    {
        candidate_pn += pn_win;
    }
    /* Candidate is too far ahead. */
    else if (candidate_pn > expected_pn + pn_hwin &&
             candidate_pn >= pn_win)
    {
        candidate_pn -= pn_win;
    }

    return candidate_pn;
}

int  ql_frame_encode(const ql_frame_t *frame, uint8_t *buf, size_t cap){
    size_t pos = 0; // this is the cursor in buffer

    switch(frame->type){
        case QL_FRAME_PADDING:{
            size_t pad = frame->u.padding.length;
            if(pos + pad > cap) return QLITE_ERR_BUF;
            memset(buf + pos, 0x00, pad);
            pos += pad;
            return (int)pos;
        }
        case QL_FRAME_PING:{
            WV(0x01);
            return (int)pos;
        }
        case QL_FRAME_ACK:
        case QL_FRAME_ACK_ECN: {
            const ql_frame_ack_t *f = &frame->u.ack;
            WV(frame->type);           /* 0x02 or 0x03 */
            WV(f->largest_acked);
            WV(f->ack_delay);
            WV(f->range_count);
            WV(f->first_ack_range);

            /* §19.3.1 — each extra range is a (Gap, ACK Range Length) pair */
            for (uint64_t i = 0; i < f->range_count && i < QL_ACK_RANGE_MAX; i++) {
                /* Gap = number of unacked packets between this range and the previous.
                * On the wire: Gap is (actual_gap - 1), ACK Range is (count - 1)     */
                WV(f->ranges[i].largest);   /* gap value already computed by caller   */
                WV(f->ranges[i].count - 1); /* count - 1 per §19.3.1                  */
            }

            /* ECN counts only present in ACK_ECN (0x03) */
            if (f->has_ecn) {
                WV(f->ect0_count);
                WV(f->ect1_count);
                WV(f->ecn_ce_count);
            }
            return (int)pos;
        }
        case QL_FRAME_RESET_STREAM:{
            WV(0x04);
            WV(frame->u.reset_stream.stream_id);
            WV(frame->u.reset_stream.error_code);
            WV(frame->u.reset_stream.final_size);
            return (int)pos;
        }
        case QL_FRAME_STOP_SENDING:{
            WV(0x05);
            WV(frame->u.stop_sending.stream_id);
            WV(frame->u.stop_sending.error_code);
            return (int)pos;
        }
        case QL_FRAME_CRYPTO:{
            WV(0x06);
            WV(frame->u.crypto.offset);
            WV(frame->u.crypto.length);
            WB(frame->u.crypto.data, frame->u.crypto.length);
            return (int)pos;
        }
        case QL_FRAME_NEW_TOKEN:{
            WV(0x07);
            WV(frame->u.new_token.token_length);
            WB(frame->u.new_token.token, frame->u.new_token.token_length);
            return (int)pos;
        }
        /* all 8 STREAM variants fall through to same logic */
        case QL_FRAME_STREAM: case QL_FRAME_STREAM_FIN:
        case QL_FRAME_STREAM_LEN: case QL_FRAME_STREAM_LEN_FIN:
        case QL_FRAME_STREAM_OFF: case QL_FRAME_STREAM_OFF_FIN:
        case QL_FRAME_STREAM_OFF_LEN: case QL_FRAME_STREAM_OFF_LEN_FIN: {
            const ql_frame_stream_t *f = &frame->u.stream;
            uint8_t type = 0x08
                | (f->fin        ? 0x01 : 0)
                | (f->has_length ? 0x02 : 0)
                | (f->has_offset ? 0x04 : 0);
            WV(type); WV(f->stream_id);
            if (f->has_offset) WV(f->offset);
            if (f->has_length) WV(f->length);
            WB(f->data, f->length);
            return (int)pos;
        }
        case QL_FRAME_MAX_DATA:
        WV(0x10); WV(frame->u.max_data.maximum_data);
        return (int)pos;

        case QL_FRAME_MAX_STREAM_DATA:
            WV(0x11); WV(frame->u.max_stream_data.stream_id);
            WV(frame->u.max_stream_data.maximum_stream_data);
            return (int)pos;

        case QL_FRAME_MAX_STREAMS_BIDI:
        case QL_FRAME_MAX_STREAMS_UNI:
            WV(frame->type); WV(frame->u.max_streams.maximum_streams);
            return (int)pos;

        case QL_FRAME_DATA_BLOCKED:
            WV(0x14); WV(frame->u.data_blocked.data_limit);
            return (int)pos;

        case QL_FRAME_STREAM_DATA_BLOCKED:
            WV(0x15); WV(frame->u.stream_data_blocked.stream_id);
            WV(frame->u.stream_data_blocked.stream_data_limit);
            return (int)pos;

        case QL_FRAME_STREAMS_BLOCKED_BIDI:
        case QL_FRAME_STREAMS_BLOCKED_UNI:
            WV(frame->type); WV(frame->u.streams_blocked.stream_limit);
            return (int)pos;

        case QL_FRAME_NEW_CONNECTION_ID: {
            const ql_frame_new_cid_t *f = &frame->u.new_cid;
            WV(0x18); WV(f->sequence_num); WV(f->retire_prior_to);
            /* cid_len is a plain uint8 on the wire, NOT a varint */
            WB(&f->cid.len, 1);
            WB(f->cid.data, f->cid.len);
            WB(f->stateless_reset_token.data, QL_RESET_TOKEN_LEN);
            return (int)pos;
        }

        case QL_FRAME_RETIRE_CONNECTION_ID:
            WV(0x19); WV(frame->u.retire_cid.sequence_num);
            return (int)pos;

        case QL_FRAME_PATH_CHALLENGE:
            /* data is 8 raw bytes, NOT a varint */
            WV(0x1A); WB(frame->u.path_challenge.data.data, QL_PATH_DATA_LEN);
            return (int)pos;

        case QL_FRAME_PATH_RESPONSE:
            WV(0x1B); WB(frame->u.path_response.data.data, QL_PATH_DATA_LEN);
            return (int)pos;

        case QL_FRAME_CONNECTION_CLOSE: {
            const ql_frame_conn_close_t *f = &frame->u.conn_close;
            WV(0x1C); WV(f->error_code); WV(f->frame_type);
            WV(f->reason_length); WB(f->reason_phrase, f->reason_length);
            return (int)pos;
        }
        case QL_FRAME_CONNECTION_CLOSE_APP: {
            const ql_frame_conn_close_t *f = &frame->u.conn_close;
            /* 0x1D has no frame_type field */
            WV(0x1D); WV(f->app_error_code);
            WV(f->reason_length); WB(f->reason_phrase, f->reason_length);
            return (int)pos;
        }

        case QL_FRAME_HANDSHAKE_DONE:
            WV(0x1E);
            return (int)pos;

        default:
            return QLITE_ERR_PROTO;
    }
}

int  ql_frame_decode(const uint8_t *buf, size_t len, ql_frame_t *out){
    if(!buf || !out || len == 0) return QLITE_ERR_ARGS;
    size_t pos = 0;

    // step 1: read the type varint — tells us which frame this is
    ql_varint_t type_vi;
    int n = ql_varint_decode(buf, len, &type_vi);
    if (n < 0) return n;
    pos += n;

    memset(out, 0, sizeof(*out));
    out->type = (ql_frame_type_t)type_vi;

    switch (out->type) {
    case QL_FRAME_PADDING:{
        size_t count = 1;
        while(pos < len && buf[pos] == 0x00) { pos++; count++;}
        out->u.padding.length = count;
        return (int)pos;
    }

    case QL_FRAME_PING:
        return (int)pos;

    case QL_FRAME_ACK:
    case QL_FRAME_ACK_ECN:{
        ql_frame_ack_t *a = &out->u.ack;
        a->has_ecn = (out->type == QL_FRAME_ACK_ECN);

        RV(a->largest_acked);
        RV(a->ack_delay);
        RV(a->range_count);
        RV(a->first_ack_range);

        ql_pkt_num_t prev_sml = a->largest_acked - a->first_ack_range;
        uint64_t n_ranges = a->range_count < QL_ACK_RANGE_MAX ? a->range_count : QL_ACK_RANGE_MAX;

        for(uint64_t i = 0; i < n_ranges; i++){
            ql_varint_t gap, range_len;
            RV(gap);
            RV(range_len);

            ql_pkt_num_t this_largest = prev_sml - gap - 2;
            a->ranges[i].largest = this_largest;
            a->ranges[i].count   = range_len + 1;
            prev_sml = this_largest - range_len; /* smallest of this range */
        }

        if(a->has_ecn){
            RV(a->ect0_count);
            RV(a->ect1_count);
            RV(a->ecn_ce_count);
        }
        return (int)pos;
    }

    case QL_FRAME_RESET_STREAM:{
        ql_frame_reset_stream_t *f = &out->u.reset_stream;
        RV(f->stream_id);
        RV(f->error_code);
        RV(f->final_size);
        return (int)pos;
    }

    case QL_FRAME_STOP_SENDING: {
        ql_frame_stop_sending_t *f = &out->u.stop_sending;
        RV(f->stream_id);
        RV(f->error_code);
        return (int)pos;
    }

     case QL_FRAME_CRYPTO: {
        ql_frame_crypto_t *f = &out->u.crypto;
        RV(f->offset);
        RV(f->length);
        if (pos + (size_t)f->length > len) return QLITE_ERR_BUF;
        f->data = buf + pos;          /* zero-copy: points into caller's buf */
        pos += (size_t)f->length;
        return (int)pos;
    }

    case QL_FRAME_NEW_TOKEN: {
        ql_frame_new_token_t *f = &out->u.new_token;
        RV(f->token_length);
        if (pos + (size_t)f->token_length > len) return QLITE_ERR_BUF;
        f->token = buf + pos;         /* zero-copy */
        pos += (size_t)f->token_length;
        return (int)pos;
    }

    case QL_FRAME_STREAM:
    case QL_FRAME_STREAM_FIN:
    case QL_FRAME_STREAM_LEN:
    case QL_FRAME_STREAM_LEN_FIN:
    case QL_FRAME_STREAM_OFF:
    case QL_FRAME_STREAM_OFF_FIN:
    case QL_FRAME_STREAM_OFF_LEN:
    case QL_FRAME_STREAM_OFF_LEN_FIN: {
        ql_frame_stream_t *f = &out->u.stream;
        uint8_t flags  = (uint8_t)out->type & 0x07u;
        f->fin         = (flags & QL_STREAM_FLAG_FIN) != 0;
        f->has_length  = (flags & QL_STREAM_FLAG_LEN) != 0;
        f->has_offset  = (flags & QL_STREAM_FLAG_OFF) != 0;

        RV(f->stream_id);

        if (f->has_offset) RV(f->offset);  /* else offset = 0 (implicit) */

        if (f->has_length) {
            RV(f->length);
            if (pos + (size_t)f->length > len) return QLITE_ERR_BUF;
            f->data = buf + pos;      /* zero-copy */
            pos += (size_t)f->length;
        } else {
            /* No LEN bit: data runs to end of the enclosing packet §19.8 */
            f->length = (uint64_t)(len - pos);
            f->data   = buf + pos;
            pos       = len;
        }
        return (int)pos;
    }

    case QL_FRAME_MAX_DATA:
        RV(out->u.max_data.maximum_data);
        return (int)pos;

    case QL_FRAME_MAX_STREAM_DATA: {
        ql_frame_max_stream_data_t *f = &out->u.max_stream_data;
        RV(f->stream_id);
        RV(f->maximum_stream_data);
        return (int)pos;
    }

    case QL_FRAME_MAX_STREAMS_BIDI:
    case QL_FRAME_MAX_STREAMS_UNI:
        RV(out->u.max_streams.maximum_streams);
        return (int)pos;

    case QL_FRAME_DATA_BLOCKED:
        RV(out->u.data_blocked.data_limit);
        return (int)pos;

    case QL_FRAME_STREAM_DATA_BLOCKED: {
        ql_frame_stream_data_blocked_t *f = &out->u.stream_data_blocked;
        RV(f->stream_id);
        RV(f->stream_data_limit);
        return (int)pos;
    }

    case QL_FRAME_STREAMS_BLOCKED_BIDI:
    case QL_FRAME_STREAMS_BLOCKED_UNI:
        RV(out->u.streams_blocked.stream_limit);
        return (int)pos;

    case QL_FRAME_NEW_CONNECTION_ID: {
        ql_frame_new_cid_t *f = &out->u.new_cid;
        RV(f->sequence_num);
        RV(f->retire_prior_to);
        /* CID length is a plain uint8_t on the wire, NOT a varint §19.15 */
        if (pos >= len) return QLITE_ERR_BUF;
        f->cid.len = buf[pos++];
        if (f->cid.len > QL_CID_MAX_LEN) return QLITE_ERR_PROTO;
        RB(f->cid.data, f->cid.len);
        /* Stateless Reset Token: always exactly 16 bytes §19.15 */
        RB(f->stateless_reset_token.data, QL_RESET_TOKEN_LEN);
        return (int)pos;
    }

    case QL_FRAME_RETIRE_CONNECTION_ID:
        RV(out->u.retire_cid.sequence_num);
        return (int)pos;

    case QL_FRAME_PATH_CHALLENGE:
        RB(out->u.path_challenge.data.data, QL_PATH_DATA_LEN);
        return (int)pos;

    case QL_FRAME_PATH_RESPONSE:
        RB(out->u.path_response.data.data, QL_PATH_DATA_LEN);
        return (int)pos;

    case QL_FRAME_CONNECTION_CLOSE:
    case QL_FRAME_CONNECTION_CLOSE_APP: {
        ql_frame_conn_close_t *f = &out->u.conn_close;
        f->is_app = (out->type == QL_FRAME_CONNECTION_CLOSE_APP);

        if (!f->is_app) {
            RV(f->error_code);
            RV(f->frame_type);
        } else {
            RV(f->app_error_code);
        }
        RV(f->reason_length);
        if (pos + (size_t)f->reason_length > len) return QLITE_ERR_BUF;
        f->reason_phrase = buf + pos;  /* zero-copy */
        pos += (size_t)f->reason_length;
        return (int)pos;
    }
    
    case QL_FRAME_HANDSHAKE_DONE:
        return (int)pos;

    default:
        return QLITE_ERR_PROTO;
    }
}

/*
 * ql_udp_socket — creates a non-blocking UDP socket bound to bind_addr:port.
 *
 * bind_addr may be NULL or "" to bind to INADDR_ANY / in6addr_any.
 * port = 0 lets the OS assign an ephemeral port.
 *
 * Returns fd >= 0 on success, or QLITE_ERR_INTERNAL on failure
 * (check errno for the OS reason).
 *
 * Steps:
 *   1. getaddrinfo to resolve bind_addr (supports IPv4 and IPv6)
 *   2. socket(AF_INET/6, SOCK_DGRAM, IPPROTO_UDP)
 *   3. SO_REUSEADDR
 *   4. O_NONBLOCK
 *   5. bind()
 */
int  ql_udp_socket(const char *bind_addr, uint16_t port){
    int fd = -1;
    int one = 1;
    int flags;

    /*
        try ipv6 first (dual-stack on linux handles ipv4 too)
        fall back to ipv4 if ipv6 is not available
    */
   fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
   if(fd >=0){
    /* allow ipv4 client on the ipv6*/
    int ipv6_only = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only));
    
    struct sockaddr_in6 addr6;
    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(port);

    if(bind_addr && bind_addr[0]){
        if(inet_pton(AF_INET6, bind_addr, &addr6.sin6_addr) != 1){
            close(fd);
            fd = -1;
            goto try_ipv4;
        }
    }else{
        addr6.sin6_addr = in6addr_any;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    flags = fctnl(fd, F_GETFL, 0);
    if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0){
            close(fd);
            fd = -1;
    }else{
        return fd;
    }
   }

try_ipv4:
   fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return QLITE_ERR_INTERNAL;

    struct sockaddr_in addr4;
    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    addr4.sin_port   = htons(port);

    if (bind_addr && bind_addr[0]) {
        if (inet_pton(AF_INET, bind_addr, &addr4.sin_addr) != 1) {
            close(fd);
            return QLITE_ERR_INTERNAL;
        }
    } else {
        addr4.sin_addr.s_addr = INADDR_ANY;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        bind(fd, (struct sockaddr *)&addr4, sizeof(addr4)) != 0) {
        close(fd);
        return QLITE_ERR_INTERNAL;
    }

    return fd;
}

/*
 * ql_udp_send — sends one UDP datagram.
 *
 * Returns bytes sent (>= 0), QLITE_ERR_WOULDBLOCK if the socket would
 * block, or QLITE_ERR_INTERNAL on a hard error.
 *
 * 14.1: if sendmsg returns EMSGSIZE the caller should lower the path MTU
 * and re-fragment — we surface this as QLITE_ERR_BUF so the caller can
 * detect it.
 */
int  ql_udp_send(int fd, const struct sockaddr *addr, socklen_t addrlen,
                  const uint8_t *buf, size_t len)
{
    ssize_t sent = sendto(fd, buf, len, 0, addr, addrlen);
    if(sent >= 0) return (int)sent;

    if(errno == EAGAIN || errno == EWOULDBLOCK) return QLITE_ERR_WOULDBLOCK;
    if(errno == EMSGSIZE) return QLITE_ERR_BUF;
    return QLITE_ERR_INTERNAL;
}

/*
 * ql_udp_recv — receives one UDP datagram.
 *
 * Returns bytes received (>= 0), QLITE_ERR_WOULDBLOCK if no data ready,
 * or QLITE_ERR_INTERNAL on error.
 *
 * src and srclen are populated with the sender's address (may be NULL).
 */
int  ql_udp_recv(int fd, uint8_t *buf, size_t cap,
                  struct sockaddr_storage *src, socklen_t *srclen)
{
    socklen_t addrlen = src ? sizeof(*src) : 0;
    ssize_t n = recvfrom(fd, buf, cap, 0,
                            src ? (struct sockaddr *)src : NULL,
                            src ? &addrlen : NULL);
                            
    if(n>=0){
        if(srclen) *srclen = addrlen;
        return (int)n;
    }
    if(errno == EAGAIN || errno == EWOULDBLOCK) return QLITE_ERR_WOULDBLOCK;
    return QLITE_ERR_INTERNAL;
}

int  ql_pkt_encode(const ql_pkt_hdr_t *hdr, const ql_keys_t *key,
                    const uint8_t *payload, size_t payload_len,
                    uint8_t *out, size_t cap);
int  ql_pkt_decode(const uint8_t *buf, size_t len, const ql_keys_t *key,
                    ql_pkt_hdr_t *hdr_out, uint8_t *payload_out, size_t cap);

/* Transport-parameter encode/decode 18 */
int ql_tp_encode(const ql_transport_params_t *tp, uint8_t *buf, size_t cap) {
    if (!tp || !buf) return QLITE_ERR_ARGS;
    size_t pos = 0;

    if (tp->max_idle_timeout_ms)
        TP_VARINT(QL_TP_MAX_IDLE_TIMEOUT, tp->max_idle_timeout_ms);

    if (tp->max_udp_payload_size && tp->max_udp_payload_size != QL_MAX_UDP_PAYLOAD_DEFAULT)
        TP_VARINT(QL_TP_MAX_UDP_PAYLOAD_SIZE, tp->max_udp_payload_size);

    if (tp->initial_max_data)
        TP_VARINT(QL_TP_INITIAL_MAX_DATA, tp->initial_max_data);

    if (tp->initial_max_stream_data_bidi_local)
        TP_VARINT(QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, tp->initial_max_stream_data_bidi_local);

    if (tp->initial_max_stream_data_bidi_remote)
        TP_VARINT(QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, tp->initial_max_stream_data_bidi_remote);

    if (tp->initial_max_stream_data_uni)
        TP_VARINT(QL_TP_INITIAL_MAX_STREAM_DATA_UNI, tp->initial_max_stream_data_uni);

    if (tp->initial_max_streams_bidi)
        TP_VARINT(QL_TP_INITIAL_MAX_STREAMS_BIDI, tp->initial_max_streams_bidi);

    if (tp->initial_max_streams_uni)
        TP_VARINT(QL_TP_INITIAL_MAX_STREAMS_UNI, tp->initial_max_streams_uni);

    if (tp->ack_delay_exponent != 0 && tp->ack_delay_exponent != QL_DEFAULT_ACK_DELAY_EXP)
        TP_VARINT(QL_TP_ACK_DELAY_EXPONENT, tp->ack_delay_exponent);

    if (tp->max_ack_delay_ms != 0 && tp->max_ack_delay_ms != QL_DEFAULT_MAX_ACK_DELAY_MS)
        TP_VARINT(QL_TP_MAX_ACK_DELAY, tp->max_ack_delay_ms);

    if (tp->active_cid_limit != 0 && tp->active_cid_limit != QL_DEFAULT_ACTIVE_CID_LIMIT)
        TP_VARINT(QL_TP_ACTIVE_CONNECTION_ID_LIMIT, tp->active_cid_limit);

    if (tp->disable_active_migration) {
        /* Empty value — just id + length=0 */
        int n = ql_varint_encode(buf + pos, cap - pos, QL_TP_DISABLE_ACTIVE_MIGRATION);
        if (n < 0 || pos + (size_t)n + 1 > cap) return QLITE_ERR_BUF;
        pos += (size_t)n;
        buf[pos++] = 0x00;  /* length = 0 */
    }

    if (tp->has_stateless_reset_token)
        TP_BYTES(QL_TP_STATELESS_RESET_TOKEN,
                 tp->stateless_reset_token.data, QL_RESET_TOKEN_LEN);

    if (tp->original_dst_cid.len)
        TP_CID(QL_TP_ORIGINAL_DST_CID, &tp->original_dst_cid);

    if (tp->initial_src_cid.len)
        TP_CID(QL_TP_INITIAL_SOURCE_CID, &tp->initial_src_cid);

    if (tp->has_retry_src_cid && tp->retry_src_cid.len)
        TP_CID(QL_TP_RETRY_SOURCE_CID, &tp->retry_src_cid);

    return (int)pos;
}

int ql_tp_decode(const uint8_t *buf, size_t len, ql_transport_params_t *out) {
    if (!buf || !out) return QLITE_ERR_ARGS;
    memset(out, 0, sizeof(*out));

    /* Apply RFC defaults */
    out->max_udp_payload_size = QL_MAX_UDP_PAYLOAD_DEFAULT;
    out->ack_delay_exponent   = QL_DEFAULT_ACK_DELAY_EXP;
    out->max_ack_delay_ms     = QL_DEFAULT_MAX_ACK_DELAY_MS;
    out->active_cid_limit     = QL_DEFAULT_ACTIVE_CID_LIMIT;

    size_t pos = 0;
    while (pos < len) {
        ql_varint_t id, tp_len;
        if (ql__read_varint(buf, &pos, len, &id)     < 0) return QLITE_ERR_PROTO;
        if (ql__read_varint(buf, &pos, len, &tp_len) < 0) return QLITE_ERR_PROTO;

        size_t val_end = pos + (size_t)tp_len;
        if (val_end > len) return QLITE_ERR_PROTO;

        ql_varint_t v;

        switch ((ql_tp_id_t)id) {
            case QL_TP_MAX_IDLE_TIMEOUT:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->max_idle_timeout_ms = v;
                break;
            case QL_TP_MAX_UDP_PAYLOAD_SIZE:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                if (v < QL_MIN_UDP_PAYLOAD_SIZE) return QLITE_ERR_PROTO;
                out->max_udp_payload_size = v;
                break;
            case QL_TP_INITIAL_MAX_DATA:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->initial_max_data = v;
                break;
            case QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->initial_max_stream_data_bidi_local = v;
                break;
            case QL_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->initial_max_stream_data_bidi_remote = v;
                break;
            case QL_TP_INITIAL_MAX_STREAM_DATA_UNI:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->initial_max_stream_data_uni = v;
                break;
            case QL_TP_INITIAL_MAX_STREAMS_BIDI:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->initial_max_streams_bidi = v;
                break;
            case QL_TP_INITIAL_MAX_STREAMS_UNI:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                out->initial_max_streams_uni = v;
                break;
            case QL_TP_ACK_DELAY_EXPONENT:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                if (v > 20) return QLITE_ERR_PROTO; /* §18.2: MUST be <= 20 */
                out->ack_delay_exponent = v;
                break;
            case QL_TP_MAX_ACK_DELAY:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                if (v >= (UINT64_C(1) << 14)) return QLITE_ERR_PROTO; /* §18.2 */
                out->max_ack_delay_ms = v;
                break;
            case QL_TP_ACTIVE_CONNECTION_ID_LIMIT:
                if (ql_varint_decode(buf + pos, tp_len, &v) < 0) return QLITE_ERR_PROTO;
                if (v < 2) return QLITE_ERR_PROTO; /* §18.2: MUST be >= 2 */
                out->active_cid_limit = v;
                break;
            case QL_TP_DISABLE_ACTIVE_MIGRATION:
                out->disable_active_migration = true;
                break;
            case QL_TP_STATELESS_RESET_TOKEN:
                if (tp_len != QL_RESET_TOKEN_LEN) return QLITE_ERR_PROTO;
                memcpy(out->stateless_reset_token.data, buf + pos, QL_RESET_TOKEN_LEN);
                out->has_stateless_reset_token = true;
                break;
            case QL_TP_ORIGINAL_DST_CID:
                if (tp_len > QL_CID_MAX_LEN) return QLITE_ERR_PROTO;
                out->original_dst_cid.len = (uint8_t)tp_len;
                memcpy(out->original_dst_cid.data, buf + pos, tp_len);
                break;
            case QL_TP_INITIAL_SOURCE_CID:
                if (tp_len > QL_CID_MAX_LEN) return QLITE_ERR_PROTO;
                out->initial_src_cid.len = (uint8_t)tp_len;
                memcpy(out->initial_src_cid.data, buf + pos, tp_len);
                break;
            case QL_TP_RETRY_SOURCE_CID:
                if (tp_len > QL_CID_MAX_LEN) return QLITE_ERR_PROTO;
                out->retry_src_cid.len = (uint8_t)tp_len;
                memcpy(out->retry_src_cid.data, buf + pos, tp_len);
                out->has_retry_src_cid = true;
                break;
            default:
                /* §7.4.2 — unknown TP IDs MUST be ignored */
                break;
        }
        pos = val_end;
    }
    return (int)pos;
}

#if defined(__cplusplus)
} /* extern "C" */
#endif
#endif /* QLITE_H */