/* BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2016-2017 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/
/*
 * TCP SYN authentication for DOS attack mitigation
 *
 */

#define TCP_SEQNUM_WIDTH 32
#define SA_WHITELIST_HASH_WIDTH 16
#define SA_WHITE_LIST_SIZE      65536


/************************************************
 * Syn Auth metadata
 ***********************************************/
header_type sa_metadata_t {
   fields {
        forward : 1; 
        add_to_whitelist : 1; 
        return_rst : 1; 
        syn_or_rst : 2; // syn: 1,  rst: 2, other: 0
        nonce1 : 32;
        nonce2 : 32;
        nonce3 : 32;
        nonce4 : 32;
        read_nonce : 1;
        rcv_cookie : 32;
        cookie1 : 32;
        cookie2 : 32;
        cookie3 : 32;
        cookie4 : 32;
        cookie_match : 1;
        temp16b_1 : 16;
        temp16b_2 : 16;
        temp32b_1 : 32;
        temp32b_2 : 32;
        temp32b_3 : 32;
        temp48b_1 : 48;
        temp48b_2 : 48;
        in_whitelist_bf1 : 1;
        in_whitelist_bf2 : 1;
        in_whitelist_bf3 : 1;
        in_whitelist_bf4 : 1;
        in_whitelist_bf5 : 1;
        in_whitelist_bf6 : 1;
        in_whitelist_bf7 : 1;
        in_whitelist_bf8 : 1;
   	in_bf : 1; 
	tcp_len: 16; 
	tmp_iphdr_len: 16; 
    }
}

metadata sa_metadata_t sa_metadata;

/************************************************
 * Nonce computation logic
 ***********************************************/
 /* Maintain nonces that are incremented periodically
    by a pktgen packet. We maintain 4 nonces as a moving
    window of consecutive values. Any incoming syn cookie
    is checked against cookies computed with all 4 nonces
    and verified that one of them matches before adding the
    connection into the whitelist */
register sa_nonce_reg1 {
    width : 32;
    //static : nonce1_table;
    instance_count : 1;
}

register sa_nonce_reg2 {
    width : 32;
    //static : nonce2_table;
    instance_count : 1;
}

register sa_nonce_reg3 {
    width : 32;
    //static : nonce3_table
    instance_count : 1;
}

register sa_nonce_reg4 {
    width : 32;
    //static : nonce4_table
    instance_count : 1;
}

register tcp_flow_reg {
    width : 32;
    instance_count : 1;
}


register enable_syn_auth {
    width : 1;
    instance_count : 1;
}



blackbox stateful_alu sa_nonce_alu1{
    reg: sa_nonce_reg1;

    condition_lo : sa_metadata.read_nonce == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 0;

    output_value : alu_lo;
    output_dst : sa_metadata.nonce1;
}

blackbox stateful_alu sa_nonce_alu2{
    reg: sa_nonce_reg2;

    condition_lo : sa_metadata.read_nonce == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 0;

    output_value : alu_lo;
    output_dst : sa_metadata.nonce2;
}

blackbox stateful_alu sa_nonce_alu3{
    reg: sa_nonce_reg3;

    condition_lo : sa_metadata.read_nonce == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 0;

    output_value : alu_lo;
    output_dst : sa_metadata.nonce3;
}

blackbox stateful_alu sa_nonce_alu4{
    reg: sa_nonce_reg4;

    condition_lo : sa_metadata.read_nonce == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : 0;

    output_value : alu_lo;
    output_dst : sa_metadata.nonce4;
}

action get_nonce1() {
    sa_nonce_alu1.execute_stateful_alu(0);
}

action get_nonce2() {
    sa_nonce_alu2.execute_stateful_alu(0);
}

action get_nonce3() {
    sa_nonce_alu3.execute_stateful_alu(0);
}

action get_nonce4() {
    sa_nonce_alu4.execute_stateful_alu(0);
}

table nonce1_table {
    actions { get_nonce1; }
    default_action: get_nonce1; 
    size: 1;
}

table nonce2_table {
    actions { get_nonce2; }
    default_action: get_nonce2; 
    size: 1;
}

table nonce3_table {
    actions { get_nonce3; }
    default_action: get_nonce3; 
    size: 1;
}

table nonce4_table {
    actions { get_nonce4; }
    default_action: get_nonce4; 
    size: 1;
}


/************************************************
 * Syn cookie computation logic
 ***********************************************/

field_list syn_cookie_seed_fl1 {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort; 
    tcp.dstPort;
    ipv4.protocol;
    sa_metadata.nonce1;
}

field_list_calculation syn_cookie_hash_flc1 {
    input {
        syn_cookie_seed_fl1;
    }
    algorithm : crc32;
    output_width : TCP_SEQNUM_WIDTH;
}

field_list syn_cookie_seed_fl2 {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
    sa_metadata.nonce2;
}

field_list_calculation syn_cookie_hash_flc2 {
    input {
        syn_cookie_seed_fl2;
    }
    algorithm : crc32;
    output_width : TCP_SEQNUM_WIDTH;
}

field_list syn_cookie_seed_fl3 {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
    sa_metadata.nonce3;
}

field_list_calculation syn_cookie_hash_flc3 {
    input {
        syn_cookie_seed_fl3;
    }
    algorithm : crc32;
    output_width : TCP_SEQNUM_WIDTH;
}

field_list syn_cookie_seed_fl4 {
    ipv4.srcAddr;
    ipv4.dstAddr;
    tcp.srcPort;
    tcp.dstPort;
    sa_metadata.nonce4;
}

field_list_calculation syn_cookie_hash_flc4 {
    input {
        syn_cookie_seed_fl4;
    }
    algorithm : crc32;
    output_width : TCP_SEQNUM_WIDTH;
}

table compute_syn_cookie_table1 {
    actions { compute_syn_cookie1; }
    default_action: compute_syn_cookie1; 
    size: 1;
}

table compute_syn_cookie_table2 {
    actions { compute_syn_cookie2; }
    default_action: compute_syn_cookie2; 
    size: 1;
}

table compute_syn_cookie_table3 {
    actions { compute_syn_cookie3; }
    default_action: compute_syn_cookie3; 
    size: 1;
}

table compute_syn_cookie_table4 {
    actions { compute_syn_cookie4; }
    default_action: compute_syn_cookie4; 
    size: 1;
}

action compute_syn_cookie1() {
    modify_field_with_hash_based_offset( sa_metadata.cookie1, 0, syn_cookie_hash_flc1, 4294967296 );
}

action compute_syn_cookie2() {
    modify_field_with_hash_based_offset( sa_metadata.cookie2, 0, syn_cookie_hash_flc2, 4294967296 );
}

action compute_syn_cookie3() {
    modify_field_with_hash_based_offset( sa_metadata.cookie3, 0, syn_cookie_hash_flc3, 4294967296 );
}

action compute_syn_cookie4() {
    modify_field_with_hash_based_offset( sa_metadata.cookie4, 0, syn_cookie_hash_flc4, 4294967296 );
}

table get_rcv_cookie_table {
    actions { get_rcv_cookie; }
    default_action: get_rcv_cookie; 
    size: 1;
}

action get_rcv_cookie() { // rcv_cookie=(ackNo-1)
    subtract( sa_metadata.rcv_cookie, tcp.ackNo, 1 );
}

table verify_syn_cookie_table {
    actions { verify_syn_cookie; }
    default_action: verify_syn_cookie; 
    size: 1;
}

action verify_syn_cookie() { // check cookie val on rcv_cookie=(ackNo-1), not seqNo
    subtract( sa_metadata.cookie1, sa_metadata.rcv_cookie, sa_metadata.cookie1 );
    subtract( sa_metadata.cookie2, sa_metadata.rcv_cookie, sa_metadata.cookie2 );
    //subtract( sa_metadata.cookie3, sa_metadata.rcv_cookie, sa_metadata.cookie3 );
    //subtract( sa_metadata.cookie4, sa_metadata.rcv_cookie, sa_metadata.cookie4 );
}

table cookie_match_table {
    actions { set_cookie_match; }
    default_action: set_cookie_match; 
    size: 1;
}

action set_cookie_match() {
    modify_field( sa_metadata.cookie_match, 1 );
}

table generate_syn_ack_table {
    actions { generate_syn_cookie; }
    default_action: generate_syn_cookie; 
    size: 1;
}

action generate_syn_cookie() {
    modify_field_with_hash_based_offset( sa_metadata.temp32b_3, 0x0, syn_cookie_hash_flc1, 4294967296 );
}

table set_not_in_bf_table {
    actions { set_not_in_bf; }
    default_action: set_not_in_bf; 
    size: 1; 
}

action set_not_in_bf (){
    sa_metadata.in_bf=0; 
}
table set_in_bf_table {
    actions { set_in_bf; }
    default_action: set_in_bf; 
    size: 1; 
}

action set_in_bf (){
    sa_metadata.in_bf=1; 
}
table add_to_whitelist_table {
    actions { add_to_whitelist; }
    default_action: add_to_whitelist; 
    size: 1; 
}

action add_to_whitelist (){
    sa_metadata.add_to_whitelist=1; 
}
/************************************************
 * Bloom filter (whitelist) logic.
 * Replicated per hash function
 ***********************************************/

register sa_bloom_filter_whitelist_reg1 {
    width : 8;
    static : sa_bloom_filter_whitelist_1;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg2 {
    width : 8;
    static : sa_bloom_filter_whitelist_2;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg3 {
    width : 8;
    static : sa_bloom_filter_whitelist_3;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg4 {
    width : 8;
    static : sa_bloom_filter_whitelist_4;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg5 {
    width : 8;
    static : sa_bloom_filter_whitelist_5;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg6 {
    width : 8;
    static : sa_bloom_filter_whitelist_6;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg7 {
    width : 8;
    static : sa_bloom_filter_whitelist_7;
    instance_count : SA_WHITE_LIST_SIZE;
}

register sa_bloom_filter_whitelist_reg8 {
    width : 8;
    static : sa_bloom_filter_whitelist_8;
    instance_count : SA_WHITE_LIST_SIZE;
}


field_list sa_hash_fields_1 {
    8w123; 
    ipv4.srcAddr;
    8w45; 
    ipv4.dstAddr;
    8w67; 
    tcp.srcPort;  
    8w89; 
    tcp.dstPort;
    ipv4.srcAddr;
}

field_list sa_hash_fields_2 {
    ipv4.dstAddr;
    6w16; 
    tcp.srcPort;  
    6w47; 
    ipv4.srcAddr;
    6w61; 
    tcp.dstPort;
    6w38; 
    ipv4.srcAddr;
}
field_list sa_hash_fields_3 {
    ipv4.srcAddr;
    8w45; 
    ipv4.dstAddr;
    8w67; 
    tcp.srcPort;  
    tcp.dstPort;
    ipv4.srcAddr;
}

field_list sa_hash_fields_4 {
    ipv4.dstAddr;
    6w16; 
    tcp.srcPort;  
    ipv4.srcAddr;
    tcp.dstPort;
    6w38; 
    ipv4.srcAddr;
}

field_list_calculation sa_hash_1 {
    input { sa_hash_fields_1; }
    algorithm : crc_32_lsb;
    output_width : SA_WHITELIST_HASH_WIDTH; }

field_list_calculation sa_hash_2 {
    input { sa_hash_fields_2; }
    algorithm : crc_32;
    output_width : SA_WHITELIST_HASH_WIDTH; }

field_list_calculation sa_hash_3 {
    input { sa_hash_fields_3; }
    algorithm : crc_16;
    output_width : SA_WHITELIST_HASH_WIDTH; }

field_list_calculation sa_hash_4 {
    input { sa_hash_fields_4; }
    algorithm : crc_16_dnp;
    output_width : SA_WHITELIST_HASH_WIDTH; }

blackbox stateful_alu sa_bloom_filter_alu_1{
    reg: sa_bloom_filter_whitelist_reg1;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf1;

}

blackbox stateful_alu sa_bloom_filter_alu_2{
    reg: sa_bloom_filter_whitelist_reg2;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf2;
}

blackbox stateful_alu sa_bloom_filter_alu_3{
    reg: sa_bloom_filter_whitelist_reg3;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf3;
}

blackbox stateful_alu sa_bloom_filter_alu_4{
    reg: sa_bloom_filter_whitelist_reg4;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf4;
}


blackbox stateful_alu sa_bloom_filter_alu_5{
    reg: sa_bloom_filter_whitelist_reg5;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf5;

}

blackbox stateful_alu sa_bloom_filter_alu_6{
    reg: sa_bloom_filter_whitelist_reg6;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf6;
}

blackbox stateful_alu sa_bloom_filter_alu_7{
    reg: sa_bloom_filter_whitelist_reg7;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf7;
}

blackbox stateful_alu sa_bloom_filter_alu_8{
    reg: sa_bloom_filter_whitelist_reg8;

    condition_lo : sa_metadata.syn_or_rst == 1;
    condition_hi : sa_metadata.add_to_whitelist == 1;

    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo;
    update_lo_2_predicate : condition_hi;
    update_lo_2_value : 1;

    output_value : alu_lo;
    output_dst : sa_metadata.in_whitelist_bf8;
}


/*  actions to execute the filters */
action check_sa_bloom_filter_1() {
    sa_bloom_filter_alu_1.execute_stateful_alu_from_hash(sa_hash_1);
}

action check_sa_bloom_filter_2() {
    sa_bloom_filter_alu_2.execute_stateful_alu_from_hash(sa_hash_2);
}

action check_sa_bloom_filter_3() {
    sa_bloom_filter_alu_3.execute_stateful_alu_from_hash(sa_hash_3);
}

action check_sa_bloom_filter_4() {
    sa_bloom_filter_alu_4.execute_stateful_alu_from_hash(sa_hash_4);
}


action check_sa_bloom_filter_5() {
    sa_bloom_filter_alu_5.execute_stateful_alu_from_hash(sa_hash_1);
}

action check_sa_bloom_filter_6() {
    sa_bloom_filter_alu_6.execute_stateful_alu_from_hash(sa_hash_2);
}

action check_sa_bloom_filter_7() {
    sa_bloom_filter_alu_7.execute_stateful_alu_from_hash(sa_hash_3);
}

action check_sa_bloom_filter_8() {
    sa_bloom_filter_alu_8.execute_stateful_alu_from_hash(sa_hash_4);
}

/* separate tables to run the bloom filters. */
table sa_bloom_filter_whitelist_1 {
    actions { check_sa_bloom_filter_1; }
    default_action: check_sa_bloom_filter_1; 
    size: 1;
}

table sa_bloom_filter_whitelist_2 {
    actions { check_sa_bloom_filter_2; }
    default_action: check_sa_bloom_filter_2; 
    size: 1;
}

table sa_bloom_filter_whitelist_3 {
    actions { check_sa_bloom_filter_3; }
    default_action: check_sa_bloom_filter_3; 
    size: 1;
}

table sa_bloom_filter_whitelist_4 {
    actions { check_sa_bloom_filter_4; }
    default_action: check_sa_bloom_filter_4; 
    size: 1;
}

table sa_bloom_filter_whitelist_5 {
    actions { check_sa_bloom_filter_5; }
    default_action: check_sa_bloom_filter_5; 
    size: 1;
}

table sa_bloom_filter_whitelist_6 {
    actions { check_sa_bloom_filter_6; }
    default_action: check_sa_bloom_filter_6; 
    size: 1;
}

table sa_bloom_filter_whitelist_7 {
    actions { check_sa_bloom_filter_7; }
    default_action: check_sa_bloom_filter_7; 
    size: 1;
}

table sa_bloom_filter_whitelist_8 {
    actions { check_sa_bloom_filter_8; }
    default_action: check_sa_bloom_filter_8; 
    size: 1;
}


/***** CHECKSUM LOGIC *****/
/* Might not need this, don't have these tables called currently. */ 
field_list copy_addr_1 {
	sa_metadata.tmp_iphdr_len;  
}

field_list_calculation copy_addr_1_calc {
	input {
	   copy_addr_1; 
	}
	algorithm: identity_lsb; 
	output_width: 16; 
}

action calc_tcp_len_1() {
	//sa_metadata.tmp_iphdr_len = 4*ipv4.ihl;
	shift_left(sa_metadata.tmp_iphdr_len, ipv4.ihl, 2); 
}

table calc_tcp_len_table_1 {
	actions { calc_tcp_len_1; }
	default_action: calc_tcp_len_1; 
	size: 1; 
}

action calc_tcp_len_2 () {
	modify_field_with_hash_based_offset(sa_metadata.tmp_iphdr_len,0,copy_addr_1_calc,1<<16); 
}

table calc_tcp_len_table_2 {
	actions { calc_tcp_len_2; }
	default_action: calc_tcp_len_2; 
	size: 1; 
}

action calc_tcp_len_3() {
	//sa_metadata.tcp_len = ipv4.totalLen - sa_metadata.tmp_iphdr_len; 
	subtract(sa_metadata.tcp_len, ipv4.totalLen, sa_metadata.tmp_iphdr_len); 
}

table calc_tcp_len_table_3 {
	actions { calc_tcp_len_3; }
	default_action: calc_tcp_len_3; 
	size: 1; 
}

/************************************************
 * Top level table for checking TCP packet type
 ***********************************************/
/*
table syn_auth_table {
    reads {
        ipv4.protocol : exact;
        tcp.ctrl : exact; // tcp syn or rst
        // Can we chack for pktgen packets here itself?
    }
    actions {
        receive_other;           //other packets
        receive_syn;             //incoming syn
        receive_rst;
        //receive_ack;             //incoming ack
    }
    size : 2;
}
*/

table do_drop_table {
    actions { my_do_drop; } 
    default_action: my_do_drop; 
    size: 1; 
} 
table receive_other_non_tcp_table {
    actions { receive_other_non_tcp; }
    default_action: receive_other_non_tcp; 
    size: 1;
}
table receive_other_tcp_table {
    actions { receive_other_tcp; }
    default_action: receive_other_tcp; 
    size: 1;
}
table receive_syn_table {
    actions { receive_syn; }
    default_action: receive_syn; 
    size: 1;
}
table receive_rst_table {
    actions { receive_rst; }
    default_action: receive_rst; 
    size: 1;
}
table forward_table {
    actions { forward; }
    default_action: forward; 
    size: 1;
}

action receive_syn() {
    modify_field( sa_metadata.syn_or_rst, 1 );
    modify_field( sa_metadata.read_nonce, 1 );       
}

// action receive_ack() {
//     modify_field( sa_metadata.syn_or_ack, 2 );
//     modify_field( sa_metadata.read_nonce, 1 );
// }

action receive_rst() {
    modify_field( sa_metadata.syn_or_rst, 2 );
    modify_field( sa_metadata.read_nonce, 1 );
}

action receive_other_tcp() {
    modify_field( sa_metadata.syn_or_rst, 0 );
}
action receive_other_non_tcp() {
    modify_field( sa_metadata.forward, 1 );
}
action forward() {
    modify_field( sa_metadata.forward, 1 );
}

action my_do_drop() {
    drop(); 
}

/************************************************
 * Logic to send RST packet
 ***********************************************/

table generate_rst_packet_table {
     actions { generate_rst_packet; }
     default_action: generate_rst_packet; 
     size: 1;
 }

action generate_rst_packet() {
     
    modify_field( sa_metadata.return_rst, 1 );
    modify_field( sa_metadata.temp32b_3, tcp.ackNo); // copy ackNo to seqNo, in swap_addresses_table
    add( tcp.ackNo, tcp.seqNo, 1);
    modify_field( tcp.ctrl, 4 ); // RST
    
    // copy tcp port numbers
    modify_field( sa_metadata.temp16b_1, tcp.srcPort );
    modify_field( sa_metadata.temp16b_2, tcp.dstPort );

    // copy IP addresses
    modify_field( sa_metadata.temp32b_1, ipv4.srcAddr );
    modify_field( sa_metadata.temp32b_2, ipv4.dstAddr );
    
    // copy MAC addresses
    modify_field( sa_metadata.temp48b_1, ethernet.srcAddr );
    modify_field( sa_metadata.temp48b_2, ethernet.dstAddr );

 }

 table swap_addresses_table {
     actions { swap_addresses; }
     default_action: swap_addresses; 
     size: 1;
 }

/************************************************
 * Logic to send SYN+ACK packet with syn cookie
 ***********************************************/

table generate_temp_meta_table {
    actions { generate_temp_meta; }
    default_action: generate_temp_meta; 
    size: 1;
}

action generate_temp_meta() {
    add(tcp.ackNo, tcp.seqNo, 1); // properly crafted SYN-ACK seq. no 
    modify_field( tcp.ctrl, 18 ); // SYN-ACK packet
    add_to_field(tcp.checksum,-0x11);

    // copy tcp port numbers
    modify_field( sa_metadata.temp16b_1, tcp.srcPort );
    modify_field( sa_metadata.temp16b_2, tcp.dstPort );

    // copy IP addresses
    modify_field( sa_metadata.temp32b_1, ipv4.srcAddr );
    modify_field( sa_metadata.temp32b_2, ipv4.dstAddr );
    
    // copy MAC addresses
    modify_field( sa_metadata.temp48b_1, ethernet.srcAddr );
    modify_field( sa_metadata.temp48b_2, ethernet.dstAddr );
}

table generate_send_ack_table {
    actions { swap_addresses; }
    default_action: swap_addresses; 
    size: 1;
}

//swap the addresses and ports for src and dst
action swap_addresses() {

    modify_field( tcp.seqNo, sa_metadata.temp32b_3 ); //copy cookie to seqNo
    //modify_field( tcp.ackNo, sa_metadata.temp32b_3 ); //copy cookie to ackNo

    modify_field( tcp.srcPort, sa_metadata.temp16b_2 );
    modify_field( tcp.dstPort, sa_metadata.temp16b_1 );
    //modify_field( tcp.dstPort, sa_metadata.temp16b_1 );
    //modify_field( tcp.srcPort, sa_metadata.temp16b_2 );
    
    
    modify_field( ipv4.srcAddr, sa_metadata.temp32b_2 );
    modify_field( ipv4.dstAddr, sa_metadata.temp32b_1 );
    //modify_field( ipv4.srcAddr, sa_metadata.temp32b_2 );
    //modify_field( ipv4.dstAddr, sa_metadata.temp32b_1 );
    
    modify_field( ethernet.srcAddr, sa_metadata.temp48b_2 );
    modify_field( ethernet.dstAddr, sa_metadata.temp48b_1 );
}

/* Might not need this. 
blackbox stateful_alu enable_syn_auth{
    reg: enable_syn_auth;
    initial_register_lo_value : 0;

    output_value : register_lo;
    output_dst : detection_md.enable_syn_auth;
}

action enable_syn_auth(){
    enable_syn_auth.execute_stateful_alu(0);
}

table enable_syn_auth{
    actions{
        enable_syn_auth;
    }
    default_action: enable_syn_auth;
    size: 1;
}
*/ 


/* Control flow for SYN authentication*/
control process_syn_authentication {
    
    if ( ipv4.protocol == 0x06 ) { // TCP = 0x06 
         if ( tcp.ctrl == 0b000100) { // RST  
            apply ( receive_rst_table );
        }   
        else if (tcp.ctrl == 0b000010 ) { // SYN 
            apply ( receive_syn_table );
        } 
	else{
		apply ( receive_other_tcp_table ); 
	}    
    } else{
        apply( receive_other_non_tcp_table ); //forward all non-tcp packets 
    }
    apply( nonce1_table );
    apply( nonce2_table );

/* For non-SYN packets, perform cookie check 
- if packet is not in whitelist and passes cookie check, set variable to (later) add to whitelist and send RST 
- if packet is not in whitelist and does not pass cookie check, set var to cookie_check not passed to later drop 
- if packet is in whitelist, forward later  
*/ 
	
    if ( sa_metadata.syn_or_rst == 0 ) {
	// packet is not in whitelist 
        if ( sa_metadata.in_whitelist_bf1 != 1 or 
                sa_metadata.in_whitelist_bf2 != 1 or 
                sa_metadata.in_whitelist_bf3 != 1 or 
                sa_metadata.in_whitelist_bf4 != 1 ) {
		
	// cookie check 
        	apply ( get_rcv_cookie_table ); 
		apply( compute_syn_cookie_table1 );
        	apply( compute_syn_cookie_table2 );
        	//apply( compute_syn_cookie_table3 );
        	//apply( compute_syn_cookie_table4 );
        	apply( verify_syn_cookie_table );

        	if ( sa_metadata.cookie1 == 0 ) {
            		apply( cookie_match_table ); //matched the cookie
        	}else if (sa_metadata.cookie2 == 0)
        	{
            		apply( cookie_match_table );
        	}
		
		// passes cookie check 
		if ( sa_metadata.cookie_match == 1 ) {
		    // set variable to later add to whitelist 
		    apply( add_to_whitelist_table ); 
		}
		//don't need this, just check cookie_match var later. 
		/*else { // does not pass cookie check 
		    apply( do_drop_table );  
		} */
	}

	// packet was in whitelist, forward 
	/*else {
		apply ( forward_table ); 
	}*/ 

    } // close non-SYN packets 
    

	//Check all packets against whitelist, implicitly add to whitelist if previously passed cookie check 
        apply( sa_bloom_filter_whitelist_1 );
        apply( sa_bloom_filter_whitelist_2 );
        apply( sa_bloom_filter_whitelist_3 );
        apply( sa_bloom_filter_whitelist_4 );

        apply( sa_bloom_filter_whitelist_5 );
        apply( sa_bloom_filter_whitelist_6 );
        apply( sa_bloom_filter_whitelist_7 );
        apply( sa_bloom_filter_whitelist_8 );
        
/* For non-SYN packets that passed cookie check recently: 
	- add to whitelist and return RST packet to client. 
   For non-SYN packets that did not pass cookie check recently: 
   	- if in whitelist, forward to server. 
   	- if not in whitelist, drop. 
   For SYN packets in whitelist, forward to server, else generate SYN-ACK with cookie to client.
*/
	
    if ( sa_metadata.syn_or_rst == 0 and sa_metadata.add_to_whitelist == 1) { 
	// generate RST packet back to client 
        apply( generate_rst_packet_table );
        apply( swap_addresses_table );
    }
    else if( sa_metadata.syn_or_rst == 1 or (sa_metadata.syn_or_rst == 0 and sa_metadata.add_to_whitelist != 1)){ 
        if ( sa_metadata.in_whitelist_bf1 != 1 or 
                sa_metadata.in_whitelist_bf2 != 1 or 
                sa_metadata.in_whitelist_bf3 != 1 or 
                sa_metadata.in_whitelist_bf4 != 1 ) {
		if( sa_metadata.syn_or_rst == 1 ){
	    		apply( set_not_in_bf_table );             
           		 apply( generate_syn_ack_table );
           		 apply( generate_temp_meta_table ); 
           		 apply( generate_send_ack_table );
        	}
		else { // was not in whitelist, was not a SYN packet, and did not pass cookie check 	
		    apply( do_drop_table );  
		} 
	}
	else {
	    apply( set_in_bf_table ); // send SYN packet to server 
	    apply( forward_table ); // send non-SYN packet to server 
	}

    }

  
}
