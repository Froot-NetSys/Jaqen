#include <tofino/constants.p4>
#include <tofino/intrinsic_metadata.p4>
#include <tofino/primitives.p4>
#include <tofino/stateful_alu_blackbox.p4>


// cabernet testbed 
//#define CLIENT_PORT 4
//#define CLIENT_DPID 0x04000000
//#define ATTACKER_PORT_A 28
//#define ATTACKER_DPID 0x1C000000
//#define ATTACKER_PORT_B 36
//#define ATTACKER_B_DPID 0x24000000
//#define SERVER_PORT 12


// lucid testbed 
#define CLIENT_PORT 130
#define CLIENT_DPID 0x82000000
#define ATTACKER_PORT_A 136
#define ATTACKER_A_DPID 0x88000000
#define ATTACKER_PORT_B 136
#define ATTACKER_B_DPID 0x88000000
#define SERVER_PORT 128

// poor man's testbed 
//#define CLIENT_PORT 0x00
//#define SERVER_PORT 0x01

#include "headers.p4"
#include "parsers.p4"
#include "syn/syn_auth.p4"
//#include "syn/route.p4"

table drop_table {
	actions { do_drop; }
	default_action: do_drop;
	size: 1; 
}

action do_drop() {
	drop(); 
}

/* //Clean this up later 

table route_to_table {
	actions { route_to_table; }
	default_action: route_to;
	size: 1; 
	
}

action route_to ( bit<9> port ) {
	//ig_intr_tm_md.ucast_egress_port=port;
	modify_field(ig_intr_md_for_tm.ucast_egress_port, port); 
	modify_field(hdr.ethernet.srcAddr, 1); 
	modify_field(hdr.ethernet.dstAddr, (bit<48>) port); 
}

*/ 


table route_to_client_table {
	actions { route_to_client; }
	default_action: route_to_client; 
	size: 1; 
}

action route_to_client () {
        modify_field(ig_intr_md_for_tm.ucast_egress_port, CLIENT_PORT);
	modify_field(ethernet.srcAddr, 0x000000000001);
	
	//hardcoded for cabernet testbed
	//modify_field(ethernet.dstAddr, 0x000000000004);
	//hardcoded for lucid testbed
	modify_field(ethernet.dstAddr, 0x000000000082);
} 
table route_to_attacker_a_table {
	actions { route_to_attacker_a; }
	default_action: route_to_attacker_a; 
	size: 1; 
}

action route_to_attacker_a () { 
        modify_field(ig_intr_md_for_tm.ucast_egress_port, ATTACKER_PORT_A);
	modify_field(ethernet.srcAddr, 0x000000000001);
	
	//hardcoded for cabernet testbed
	//modify_field(ethernet.dstAddr, 0x00000000001C);
	//hardcoded for lucid testbed
	modify_field(ethernet.dstAddr, 0x000000000088);
} 
table route_to_attacker_b_table {
	actions { route_to_attacker_b; }
	default_action: route_to_attacker_b; 
	size: 1; 
}

action route_to_attacker_b () {
        modify_field(ig_intr_md_for_tm.ucast_egress_port, ATTACKER_PORT_B);
	modify_field(ethernet.srcAddr, 0x000000000001);
	//hardcoded for cabernet testbed
	//modify_field(ethernet.dstAddr, 0x000000000024);
	//hardcoded for lucid testbed
	modify_field(ethernet.dstAddr, 0x000000000088);
} 
table route_to_server_table {
	actions { route_to_server; }
	default_action: route_to_server; 
	size: 1; 
} 
action route_to_server () {
	modify_field(ig_intr_md_for_tm.ucast_egress_port, SERVER_PORT); 
	modify_field(ethernet.srcAddr, 0x000000000001);
	
	//hardcoded for cabernet testbed
	//modify_field(ethernet.dstAddr, 0x00000000000C);
	//hardcoded for lucid testbed
	modify_field(ethernet.dstAddr, 0x000000000080);
}
control ingress {

    if ( ig_intr_md.ingress_port != SERVER_PORT ) {
        process_syn_authentication();

        if ( sa_metadata.syn_or_rst == 1 && sa_metadata.in_bf == 0 && ig_intr_md.ingress_port == CLIENT_PORT) {  // send crafted SYN-ACK packet back to client 
  		apply(route_to_client_table); 
	}
        else if ( sa_metadata.syn_or_rst == 1 && sa_metadata.in_bf == 0 && ig_intr_md.ingress_port == ATTACKER_PORT_A) {  // send crafted SYN-ACK packet back to attacker 
  		apply(route_to_attacker_a_table); 
	}
        else if ( sa_metadata.syn_or_rst == 1 && sa_metadata.in_bf == 0 && ig_intr_md.ingress_port == ATTACKER_PORT_B) {  // send crafted SYN-ACK packet back to attacker 
  		apply(route_to_attacker_b_table); 
	}
        else if ( sa_metadata.syn_or_rst == 1 && sa_metadata.in_bf == 0) {  // send crafted SYN-ACK packet back to any other attackers 
  		apply(route_to_attacker_a_table); 
	}
	else if ( sa_metadata.syn_or_rst == 1 && sa_metadata.in_bf == 1 ) {
		apply(route_to_server_table); 
	}
	else if ( sa_metadata.return_rst == 1 ) { //send RST packet back to client 
		apply(route_to_client_table); 
	} 
	else if (sa_metadata.forward == 1) { // forward all other packets to server  
		apply(route_to_server_table); 
	}
    }
    else { //from server, forward to client  
   	if( (ipv4.dstAddr & 0xFF000000) == CLIENT_DPID) { // forward to client 	
		apply(route_to_client_table); 
	}
	else if( (ipv4.dstAddr & 0xFF000000) == ATTACKER_A_DPID) { // forward to attacker a
		apply(route_to_attacker_a_table); 
	}
	else { // forward to attacker b
		apply(route_to_attacker_b_table); 
	}
	
    }

}

control egress {
}
