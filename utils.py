def get_protocol_name(proto_number):
    """Return protocol name for a given protocol number."""
    protocol_mapping = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        8: "EGP",
        9: "IGP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        88: "EIGRP",
        89: "OSPF",
        115: "L2TP",
    }
    return protocol_mapping.get(proto_number, f"Unknown ({proto_number})") 