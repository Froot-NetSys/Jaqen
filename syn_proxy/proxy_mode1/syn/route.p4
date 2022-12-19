action route_to_out() {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, DDOS_OUT_PORT);
}

table route {
    reads {
        ig_intr_md.ingress_port: exact;
    }
    actions {
        route_to_out;
    }
    default_action: route_to_out;
}
