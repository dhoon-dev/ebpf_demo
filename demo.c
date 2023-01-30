// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define UID_OWNER_MAP_SIZE 2000u
static const u8 BPF_PERMISSION_INTERNET = 1u;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UID_OWNER_MAP_SIZE);
    __type(key, u32);
    __type(value, u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} uid_permission_map SEC(".maps");

SEC("cgroup/sock_create")
int inet_socket_create(struct bpf_sock *sk) {
    u64 gid_uid = bpf_get_current_uid_gid();

    u32 uid = gid_uid & 0xffffffff;
    u8 *permissions = bpf_map_lookup_elem(&uid_permission_map, &uid);

    if (permissions == NULL) {
        return 1;
    }

    return (*permissions & BPF_PERMISSION_INTERNET) == BPF_PERMISSION_INTERNET;
}
