#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "frames.test.h"
#include "variant.test.h"
#include "tp.test.h"
#include "udp.test.h"
#include "crypto.test.h"

int ql_tests_run = 0;


int main(void){
    /* frames test*/
    RUN_TEST(test_frame_ping_roundtrip);
    RUN_TEST(test_frame_padding_roundtrip);
    RUN_TEST(test_frame_reset_stream_roundtrip);
    RUN_TEST(test_frame_stop_sending_roundtrip);
    RUN_TEST(test_frame_crypto_roundtrip);
    RUN_TEST(test_frame_stream_with_all_flags);
    RUN_TEST(test_frame_stream_no_offset_no_length);
    RUN_TEST(test_frame_max_data_roundtrip);
    RUN_TEST(test_frame_max_stream_data_roundtrip);
    RUN_TEST(test_frame_max_streams_bidi_roundtrip);
    RUN_TEST(test_frame_data_blocked_roundtrip);
    RUN_TEST(test_frame_stream_data_blocked_roundtrip);
    RUN_TEST(test_frame_new_connection_id_roundtrip);
    RUN_TEST(test_frame_retire_connection_id_roundtrip);
    RUN_TEST(test_frame_path_challenge_roundtrip);
    RUN_TEST(test_frame_path_response_roundtrip);
    RUN_TEST(test_frame_connection_close_transport_roundtrip);
    RUN_TEST(test_frame_connection_close_app_roundtrip);
    RUN_TEST(test_frame_handshake_done_roundtrip);
    RUN_TEST(test_frame_ack_no_ranges_roundtrip);
    RUN_TEST(test_frame_ack_with_ranges_roundtrip);
    RUN_TEST(test_frame_decode_buf_too_small);
    RUN_TEST(test_frame_decode_unknown_type);

    /* variants test*/
    RUN_TEST(test_encode_rfc_examples);
    RUN_TEST(test_decode_rfc_examples);
    RUN_TEST(test_boundary_values);
    RUN_TEST(test_random_roundtrip);
    RUN_TEST(test_decode_errors);
    RUN_TEST(test_pkt_num_encode_decode);
    RUN_TEST(test_pkt_num_decode_wrap);

    /* tp enc/dec*/
    RUN_TEST(test_tp_roundtrip_basic);
    RUN_TEST(test_tp_defaults_after_decode);
    RUN_TEST(test_tp_disable_migration);
    RUN_TEST(test_tp_stateless_reset_token);
    RUN_TEST(test_tp_cid_fields);
    RUN_TEST(test_tp_buf_too_small);
    RUN_TEST(test_tp_invalid_payload_size);

    /* udp socket/send/recv */
    RUN_TEST(test_udp_socket_bind_any_ephemeral_port);
    RUN_TEST(test_udp_socket_bind_specific_loopback);
    RUN_TEST(test_udp_socket_is_nonblocking);
    RUN_TEST(test_udp_socket_rejects_bad_address);
    RUN_TEST(test_udp_socket_two_sockets_get_distinct_ports);

    RUN_TEST(test_udp_recv_returns_again_when_empty);
    /** @todo we need a null arg handler*/
    // RUN_TEST(test_udp_recv_rejects_null_args);
    // RUN_TEST(test_udp_send_rejects_null_buf);
    RUN_TEST(test_udp_send_rejects_zero_len);
    RUN_TEST(test_udp_send_returns_full_length_on_success);
    RUN_TEST(test_udp_send_recv_roundtrip);
    RUN_TEST(test_udp_recv_reports_correct_source_address);
    RUN_TEST(test_udp_recv_again_after_drain);
    RUN_TEST(test_now_ms_is_nonzero);
    RUN_TEST(test_now_ms_is_monotonic_nondecreasing);
    RUN_TEST(test_now_ms_advances_after_sleep);

    /* crypto - aead & header_pkt*/
    /* AEAD */
    RUN_TEST(test_aead_seal_basic);
    RUN_TEST(test_aead_seal_open_roundtrip);
    RUN_TEST(test_aead_pkt_num_uniqueness);
    RUN_TEST(test_aead_tampered_ciphertext_rejected);
    RUN_TEST(test_aead_tampered_tag_rejected);
    RUN_TEST(test_aead_tampered_aad_rejected);
    RUN_TEST(test_aead_wrong_pkt_num_rejected);
    RUN_TEST(test_aead_empty_plaintext);
    RUN_TEST(test_aead_buf_too_small_seal);
    RUN_TEST(test_aead_buf_too_small_open);
    RUN_TEST(test_aead_null_key_rejected);
    RUN_TEST(test_aead_key_not_set_rejected);
    RUN_TEST(test_aead_256_roundtrip);
    RUN_TEST(test_aead_rfc9001_vectors);
    /* Header Protection */
    RUN_TEST(test_hp_protect_remove_roundtrip_long);
    RUN_TEST(test_hp_protect_remove_roundtrip_short);
    RUN_TEST(test_hp_idempotent_double_remove);
    RUN_TEST(test_hp_different_samples_different_masks);
    RUN_TEST(test_hp_null_args_rejected);
    RUN_TEST(test_hp_rfc9001_vectors);

    ql_test_summary();
    return 0;
}