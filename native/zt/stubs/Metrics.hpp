// Replacement for node/Metrics.hpp. Force-included with -include so that the
// real header, guarded by METRICS_H_, expands to nothing. Every metric is a
// no-op; nothing is allocated or registered.
#ifndef METRICS_H_
#define METRICS_H_
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
// The real prometheus headers drag these in and some core files rely on it.
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

namespace prometheus {
template <typename T> struct Histogram {
	void Observe(T) {}
};
template <typename H> struct CustomFamily {
	H& Add(const std::map<std::string, std::string>&, const std::vector<uint64_t>&) { static H h; return h; }
};
namespace simpleapi {
struct counter_metric_t {
	counter_metric_t& operator++() { return *this; }
	counter_metric_t operator++(int) { return *this; }
	counter_metric_t& operator--() { return *this; }
	counter_metric_t operator--(int) { return *this; }
	counter_metric_t& operator+=(uint64_t) { return *this; }
	counter_metric_t& operator-=(uint64_t) { return *this; }
	counter_metric_t& operator=(uint64_t) { return *this; }
	uint64_t value() const { return 0; }
};
typedef counter_metric_t gauge_metric_t;
struct counter_family_t {
	counter_metric_t Add(const std::map<std::string, std::string>&) { return counter_metric_t(); }
};
typedef counter_family_t gauge_family_t;
struct Registry {};
inline std::shared_ptr<Registry> registry_ptr;
}	// namespace simpleapi
}	// namespace prometheus

namespace ZeroTier {
namespace Metrics {
inline prometheus::simpleapi::counter_family_t packets;
inline prometheus::simpleapi::counter_metric_t pkt_nop_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_in;
inline prometheus::simpleapi::counter_metric_t pkt_ack_in;
inline prometheus::simpleapi::counter_metric_t pkt_qos_in;
inline prometheus::simpleapi::counter_metric_t pkt_hello_in;
inline prometheus::simpleapi::counter_metric_t pkt_ok_in;
inline prometheus::simpleapi::counter_metric_t pkt_whois_in;
inline prometheus::simpleapi::counter_metric_t pkt_rendezvous_in;
inline prometheus::simpleapi::counter_metric_t pkt_frame_in;
inline prometheus::simpleapi::counter_metric_t pkt_ext_frame_in;
inline prometheus::simpleapi::counter_metric_t pkt_echo_in;
inline prometheus::simpleapi::counter_metric_t pkt_multicast_like_in;
inline prometheus::simpleapi::counter_metric_t pkt_network_credentials_in;
inline prometheus::simpleapi::counter_metric_t pkt_network_config_request_in;
inline prometheus::simpleapi::counter_metric_t pkt_network_config_in;
inline prometheus::simpleapi::counter_metric_t pkt_multicast_gather_in;
inline prometheus::simpleapi::counter_metric_t pkt_multicast_frame_in;
inline prometheus::simpleapi::counter_metric_t pkt_push_direct_paths_in;
inline prometheus::simpleapi::counter_metric_t pkt_user_message_in;
inline prometheus::simpleapi::counter_metric_t pkt_remote_trace_in;
inline prometheus::simpleapi::counter_metric_t pkt_path_negotiation_request_in;
inline prometheus::simpleapi::counter_metric_t pkt_nop_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_out;
inline prometheus::simpleapi::counter_metric_t pkt_ack_out;
inline prometheus::simpleapi::counter_metric_t pkt_qos_out;
inline prometheus::simpleapi::counter_metric_t pkt_hello_out;
inline prometheus::simpleapi::counter_metric_t pkt_ok_out;
inline prometheus::simpleapi::counter_metric_t pkt_whois_out;
inline prometheus::simpleapi::counter_metric_t pkt_rendezvous_out;
inline prometheus::simpleapi::counter_metric_t pkt_frame_out;
inline prometheus::simpleapi::counter_metric_t pkt_ext_frame_out;
inline prometheus::simpleapi::counter_metric_t pkt_echo_out;
inline prometheus::simpleapi::counter_metric_t pkt_multicast_like_out;
inline prometheus::simpleapi::counter_metric_t pkt_network_credentials_out;
inline prometheus::simpleapi::counter_metric_t pkt_network_config_request_out;
inline prometheus::simpleapi::counter_metric_t pkt_network_config_out;
inline prometheus::simpleapi::counter_metric_t pkt_multicast_gather_out;
inline prometheus::simpleapi::counter_metric_t pkt_multicast_frame_out;
inline prometheus::simpleapi::counter_metric_t pkt_push_direct_paths_out;
inline prometheus::simpleapi::counter_metric_t pkt_user_message_out;
inline prometheus::simpleapi::counter_metric_t pkt_remote_trace_out;
inline prometheus::simpleapi::counter_metric_t pkt_path_negotiation_request_out;
inline prometheus::simpleapi::counter_family_t packet_errors;
inline prometheus::simpleapi::counter_metric_t pkt_error_obj_not_found_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_unsupported_op_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_identity_collision_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_need_membership_cert_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_network_access_denied_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_unwanted_multicast_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_authentication_required_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_internal_server_error_in;
inline prometheus::simpleapi::counter_metric_t pkt_error_obj_not_found_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_unsupported_op_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_identity_collision_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_need_membership_cert_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_network_access_denied_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_unwanted_multicast_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_authentication_required_out;
inline prometheus::simpleapi::counter_metric_t pkt_error_internal_server_error_out;
inline prometheus::simpleapi::counter_family_t data;
inline prometheus::simpleapi::counter_metric_t udp_send;
inline prometheus::simpleapi::counter_metric_t udp_recv;
inline prometheus::simpleapi::counter_metric_t tcp_send;
inline prometheus::simpleapi::counter_metric_t tcp_recv;
inline prometheus::simpleapi::gauge_metric_t network_num_joined;
inline prometheus::simpleapi::gauge_family_t network_num_multicast_groups;
inline prometheus::simpleapi::counter_family_t network_packets;
inline prometheus::CustomFamily<prometheus::Histogram<uint64_t> > peer_latency;
inline prometheus::simpleapi::gauge_family_t peer_path_count;
inline prometheus::simpleapi::counter_family_t peer_packets;
inline prometheus::simpleapi::counter_family_t peer_packet_errors;
inline prometheus::simpleapi::gauge_metric_t network_count;
inline prometheus::simpleapi::gauge_metric_t member_count;
inline prometheus::simpleapi::counter_metric_t network_changes;
inline prometheus::simpleapi::counter_metric_t member_changes;
inline prometheus::simpleapi::counter_metric_t member_auths;
inline prometheus::simpleapi::counter_metric_t member_deauths;
inline prometheus::simpleapi::gauge_metric_t network_config_request_queue_size;
inline prometheus::simpleapi::counter_metric_t sso_expiration_checks;
inline prometheus::simpleapi::counter_metric_t sso_member_deauth;
inline prometheus::simpleapi::counter_metric_t network_config_request;
inline prometheus::simpleapi::gauge_metric_t network_config_request_threads;
inline prometheus::simpleapi::counter_metric_t db_get_network;
inline prometheus::simpleapi::counter_metric_t db_get_network_and_member;
inline prometheus::simpleapi::counter_metric_t db_get_network_and_member_and_summary;
inline prometheus::simpleapi::counter_metric_t db_get_member_list;
inline prometheus::simpleapi::counter_metric_t db_get_network_list;
inline prometheus::simpleapi::counter_metric_t db_member_change;
inline prometheus::simpleapi::counter_metric_t db_network_change;
inline prometheus::simpleapi::counter_metric_t pgsql_mem_notification;
inline prometheus::simpleapi::counter_metric_t pgsql_net_notification;
inline prometheus::simpleapi::counter_metric_t pgsql_node_checkin;
inline prometheus::simpleapi::counter_metric_t pgsql_commit_ticks;
inline prometheus::simpleapi::counter_metric_t db_get_sso_info;
inline prometheus::simpleapi::counter_metric_t redis_mem_notification;
inline prometheus::simpleapi::counter_metric_t redis_net_notification;
inline prometheus::simpleapi::counter_metric_t redis_node_checkin;
inline prometheus::simpleapi::counter_metric_t conn_counter;
inline prometheus::simpleapi::counter_metric_t max_pool_size;
inline prometheus::simpleapi::counter_metric_t min_pool_size;
inline prometheus::simpleapi::gauge_metric_t pool_avail;
inline prometheus::simpleapi::gauge_metric_t pool_in_use;
inline prometheus::simpleapi::counter_metric_t pool_errors;
}	// namespace Metrics
}	// namespace ZeroTier
#endif	// METRICS_H_
