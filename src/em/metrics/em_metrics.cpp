/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "em_metrics.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "util.h"
#include "em.h"
#include "em_cmd_exec.h"

int em_metrics_t::handle_ap_metrics_tlv(unsigned char *buff)
{
    em_ap_metric_t *ap_metrics;
    dm_bss_t *bss;
    dm_radio_t *radio;
    //dm_ap_mld_t *m_ap_mld; TODO wifi 6.0
    dm_easy_mesh_t *dm;

    dm = get_data_model();
    
    ap_metrics = (em_ap_metric_t *)buff;

    bss = dm->find_bss_by_bssid(ap_metrics->ap_mac);

    if (bss != NULL)
    {
        radio = dm->get_radio(bss->m_bss_info.ruid.mac);
        radio->m_radio_info.utilization = ap_metrics->channel_util;
        bss->m_bss_info.numberofsta = ap_metrics->num_sta;
        if(ap_metrics->est_service_params_BE_bit)
        {
            strcpy(bss->m_bss_info.est_svc_params_be, ap_metrics->est_service_params_BE);
        }
        if(ap_metrics->est_service_params_BK_bit)
        {
            strcpy(bss->m_bss_info.est_svc_params_bk, ap_metrics->est_service_params_BK);
        }
        if(ap_metrics->est_service_params_VO_bit)
        {
            strcpy(bss->m_bss_info.est_svc_params_vo, ap_metrics->est_service_params_VO);
        }
        if(ap_metrics->est_service_params_VI_bit)
        {
            strcpy(bss->m_bss_info.est_svc_params_vi, ap_metrics->est_service_params_VI);
        }
        //QUESTION: there is type difference between metrics struct and info class, unsigned char vs em_string_t (table of chars [16])?
    }

    return 0;
}

int em_metrics_t::handle_ap_ext_metrics_tlv(unsigned char *buff)
{
    em_ap_ext_metric_t *ap_ext_metrics;
    dm_bss_t *bss;
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    ap_ext_metrics = (em_ap_ext_metric_t *)buff;

    bss = dm->find_bss_by_bssid(ap_ext_metrics->bssid);

    if(bss !=NULL)
    {
        bss->m_bss_info.unicast_bytes_sent = ap_ext_metrics->uni_bytes_sent;
        bss->m_bss_info.unicast_bytes_rcvd = ap_ext_metrics->uni_bytes_recv;
        bss->m_bss_info.multicast_bytes_sent = ap_ext_metrics->multi_bytes_sent;
        bss->m_bss_info.multicast_bytes_rcvd = ap_ext_metrics->multi_bytes_recv;
        bss->m_bss_info.broadcast_bytes_sent = ap_ext_metrics->bcast_bytes_sent;
        bss->m_bss_info.broadcast_bytes_rcvd = ap_ext_metrics->bcast_bytes_recv;
        //QUESTION: Should these be added to bss_info?
    }

    return 0;
}

int em_metrics_t::handle_radio_metrics_tlv(unsigned char *buff)
{
    em_radio_metric_t *radio_metrics;
    dm_radio_t *radio;
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    radio_metrics = (em_radio_metric_t *)buff;

    radio = dm->get_radio(radio_metrics->ruid);
    if(radio != NULL)
    {
        radio->m_radio_info.noise = radio_metrics->noise;
        /*radio->m_radio_info.transmit = radio_metrics->transmit;
        radio->m_radio_info.recv_self = radio_metrics->recv_self;
        radio->m_radio_info.recv_other = radio_metrics->recv_other;*/
        //QUESTION: should these be added to radio_info?
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_traffic_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_traffic_sts_t *assoc_sta_traffic_sts;
    dm_sta_t *sta;
    dm_easy_mesh_t  *dm;
    
    dm = get_data_model();

    assoc_sta_traffic_sts = (em_assoc_sta_traffic_sts_t *)buff;

    sta = dm->get_first_sta(assoc_sta_traffic_sts->sta_mac_addr);
    if(sta !=NULL)
    {
        sta->m_sta_info.bytes_tx = assoc_sta_traffic_sts->bytes_sent;
        sta->m_sta_info.bytes_rx = assoc_sta_traffic_sts->bytes_recv;
        sta->m_sta_info.pkts_tx = assoc_sta_traffic_sts->packets_sent;
        sta->m_sta_info.pkts_rx = assoc_sta_traffic_sts->packets_recv;
        sta->m_sta_info.errors_tx = assoc_sta_traffic_sts->tx_packets_errors;
        sta->m_sta_info.errors_rx = assoc_sta_traffic_sts->rx_packets_errors;
        sta->m_sta_info.retrans_count = assoc_sta_traffic_sts->retrans_count;
    }

    return 0;
}

int em_metrics_t::handle_assoc_wifi6_sta_sts_rprt_tlv(unsigned char *buff)
{
    em_assoc_wifi6_sta_sts_t *assoc_wifi6_sta_sts;
    em_assoc_wifi6_sta_t *assoc_wifi6_sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;
    dm_sta_t *sta;

    dm = get_data_model();

    assoc_wifi6_sta_sts = (em_assoc_wifi6_sta_sts_t *)buff;
    sta = dm->get_first_sta(assoc_wifi6_sta_sts->sta_mac_addr);
    if(sta != NULL)
    {
        for(i = 0; i < assoc_wifi6_sta_sts->n; i++)
        {
            assoc_wifi6_sta = &assoc_wifi6_sta_sts->assoc_wifi6_sta[i];
            //QUESTION: where is TID and queue size
        }
    }

    return 0;
}

int em_metrics_t::handle_ap_metrics_query_tlv(unsigned char *buff,  bssid_t *bssid_to_report, unsigned int *num_bssid)
{
    em_ap_metrics_query_t *ap_metrics_query_t;
    bssid_t *bssid;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    ap_metrics_query_t = (em_ap_metrics_query_t*)buff;

    for (i = 0; i < ap_metrics_query_t->num_bssids; i++)
    {
        bssid = &ap_metrics_query_t->bssid[i];
        memcpy(bssid_to_report[i], bssid, sizeof(bssid_t));
        *num_bssid =  *num_bssid + 1;
    }
    return 0;
}

int em_metrics_t::handle_radio_identifier_tlv(unsigned char *buff, em_radio_id_t *radios_to_report)
{
    em_radio_id_t *radio_id_t;

    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    radio_id_t = (em_radio_id_t*)buff;

    memcpy(radios_to_report, radio_id_t, sizeof(bssid_t));

    return 0;
}

int em_metrics_t::handle_ap_metrics_query_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    bssid_t bssid_to_report[EM_MAX_BSSS];
    unsigned int num_bssid =0;
    em_radio_id_t radios_to_report[EM_MAX_BANDS];
    unsigned int num_radio = 0;
    int tmp_len;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    mac_addr_str_t bss_str,radio_str;

    if (em_msg_t(em_msg_type_ap_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:AP link Metrics query message validation failed\n");
        return -1;
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_metrics_query) {
            handle_ap_metrics_query_tlv(tlv->value, bssid_to_report, &num_bssid);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    bssid_t *radio = radios_to_report;
    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_radio_id) {
            handle_radio_identifier_tlv(tlv->value, radio);
            radio++;
            num_radio++;
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    dm_easy_mesh_t::macbytes_to_string(bssid_to_report[0], bss_str);
    dm_easy_mesh_t::macbytes_to_string(radios_to_report[0], radio_str);
    printf("num_bssid: %d, num_radio: %d\n",num_bssid, num_radio);
    printf("%s  %s\n",bss_str, radio_str);

    send_ap_metrics_response_msg(bssid_to_report, num_bssid, radios_to_report, num_radio);
    set_state(em_state_agent_configured);

    return 0;
}

int em_metrics_t::handle_ap_metrics_resp_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tmp_len, ret = 0;
    mac_address_t 	ap_mac;
    dm_easy_mesh_t  *dm;
    unsigned int db_cfg_type;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t ap_mac_str, bssid_str, radio_mac_str;
    em_long_string_t	key;
    em_bss_info_t bss_info;

    dm = get_data_model();

    if (em_msg_t(em_msg_type_ap_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: AP link metrics response msg validation failed\n", __func__, __LINE__);
        //return -1;
    }
    
    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_metrics) {
        handle_ap_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_ap_ext_metric) {
            handle_ap_ext_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_radio_metric) {
            handle_radio_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_traffic_sts) {
            handle_assoc_sta_traffic_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
            handle_assoc_sta_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_wifi6_sta_rprt) {
            handle_assoc_wifi6_sta_sts_rprt_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    db_cfg_type = dm->get_db_cfg_type();
    dm->set_db_cfg_type(db_cfg_type | db_cfg_type_ap_metrics_update);
    set_state(em_state_ctrl_configured);

    return 0;

}

int em_metrics_t::send_ap_metrics_query_msg()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_ap_metrics_query;
    int len = 0;
    unsigned int i = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    dm_easy_mesh_t *dm;
    short sz = 0;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //One AP Metric query TLV (see section 17.2.21)
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_ap_metrics_query;
    sz = create_ap_metrics_query_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //zero or more AP Radio Identifier TLVs (see section 17.2.3)
    for (i = 0; i < dm->m_num_radios; i++)
    {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_radio_id;
        sz = create_ap_radio_identifier_tlv(tlv->value, dm->m_radio[i].get_radio_info()->id.mac); 
        tlv->len = htons(sz);

        tmp += (sizeof(em_tlv_t) + sz);
        len += (sizeof(em_tlv_t) + sz);
    }

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_ap_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("AP Metrics Query msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: AP Mterics Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: AP Mterics Query send success\n", __func__, __LINE__);
    return len;
}

int em_metrics_t::send_ap_metrics_response_msg(bssid_t *bssid_to_report, unsigned int num_bssid, em_radio_id_t *radios_to_report, unsigned int num_radio)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_ap_metrics_rsp;
    unsigned int it;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    short msg_id = em_msg_type_ap_metrics_rsp;
    

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //One or more AP metrics TLV 17.2.22
    for (it = 0; it < num_bssid; it++)
    {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_ap_metrics;
        sz = create_ap_metrics_tlv(tlv->value, bssid_to_report[it]);
        tlv->len =  htons(sz);

        tmp += (sizeof(em_tlv_t) + sz);
        len += (sizeof(em_tlv_t) + sz);
    }


    //One or more AP Ext Metrics TLV 17.2.61
    for (it = 0; it < num_bssid; it++)
    {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_ap_ext_metric;
        sz = create_ap_ext_metrics_tlv(tlv->value, bssid_to_report[it]);
        tlv->len =  htons(sz);

        tmp += (sizeof(em_tlv_t) + sz);
        len += (sizeof(em_tlv_t) + sz);
    }


    //zero or more Radio Metrics TLV 17.2.60
    for (it = 0; it < num_radio; it++)
    {
        tlv = (em_tlv_t *)tmp;
        tlv->type = em_tlv_type_radio_metric;
        sz = create_radio_metrics_tlv(tlv->value,radios_to_report[it]);
        tlv->len =  htons(sz);

        tmp += (sizeof(em_tlv_t) + sz);
        len += (sizeof(em_tlv_t) + sz);
    }

/*
    //zero or more Assoc STA Traffic Stats TLV 17.2.35
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    sz = create_assoc_sta_traffic_metrics_tlv(tlv->value,...);//QUESTION: determine station? from bss_info?
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //zero or more Assoc STA Link Metrics TLV 17.2.24
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    sz = create_assoc_sta_link_metrics_tlv(tlv->value,...);//as above
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //zero or more Assoc STA Link Metrics TLV 17.2.24
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value,...);//as above
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);
*/
    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_ap_metrics_rsp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: AP Link Metrics validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: AP Link Metrics  send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("%s:%d: AP Link Metrics sent successfully\n", __func__, __LINE__);

    return len;
}

int em_metrics_t::handle_assoc_sta_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_link_metrics_t	*sta_metrics;
    em_assoc_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = (em_assoc_sta_link_metrics_t *)buff;

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics	= &sta_metrics->assoc_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.est_dl_rate = metrics->est_mac_data_rate_dl;
        sta->m_sta_info.est_ul_rate = metrics->est_mac_data_rate_ul;
        sta->m_sta_info.rcpi = metrics->rcpi;
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_ext_link_metrics_t	*sta_metrics;
    em_assoc_ext_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = (em_assoc_sta_ext_link_metrics_t *)buff;

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics	= &sta_metrics->assoc_ext_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.last_dl_rate = metrics->last_data_dl_rate;
        sta->m_sta_info.last_ul_rate = metrics->last_data_ul_rate;
        sta->m_sta_info.util_rx = metrics->util_receive;
        sta->m_sta_info.util_tx = metrics->util_transmit;
    }

    return 0;
}

int em_metrics_t::handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff)
{
    em_assoc_sta_vendor_link_metrics_t *sta_metrics;
    em_assoc_vendor_link_metrics_t *metrics;
    dm_sta_t *sta;
    unsigned int i;
    dm_easy_mesh_t  *dm;

    dm = get_data_model();

    sta_metrics = (em_assoc_sta_vendor_link_metrics_t *)buff;

    for (i = 0; i < sta_metrics->num_bssids; i++) {
        metrics = &sta_metrics->assoc_vendor_link_metrics[i];
        sta = dm->find_sta(sta_metrics->sta_mac, metrics->bssid);
        if (sta == NULL) {
            continue;
        }

        sta->m_sta_info.pkts_rx = metrics->packets_received;
        sta->m_sta_info.pkts_tx = metrics->packets_sent;
        sta->m_sta_info.bytes_rx = metrics->bytes_received;
        sta->m_sta_info.bytes_tx = metrics->bytes_sent;
    }

    return 0;
}


int em_metrics_t::handle_associated_sta_link_metrics_query(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d:Assoc STA Link Metrics query message validation failed\n");
        return -1;
    }

    cmdu = (em_cmdu_t *)(buff + sizeof(em_raw_hdr_t));
    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    memcpy(sta, tlv->value, sizeof(mac_address_t));

    send_associated_link_metrics_response(sta);
    set_state(em_state_agent_configured);

    return 0;
}

int em_metrics_t::handle_associated_sta_link_metrics_resp(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv;
    int tmp_len, ret = 0;
    mac_address_t 	sta_mac;
    dm_easy_mesh_t  *dm;
    unsigned int db_cfg_type;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    mac_addr_str_t sta_mac_str, bssid_str, radio_mac_str;
    em_long_string_t	key;
    em_sta_info_t sta_info;

    dm = get_data_model();

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_rsp, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: associated sta link metrics response msg validation failed\n", __func__, __LINE__);
        //return -1;
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_link_metric) {
            handle_assoc_sta_link_metrics_tlv(tlv->value);
        }
        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_error_code) {
            if (tlv->value[0] == 0x01) {
                memcpy(sta_mac, &tlv->value[1], sizeof(mac_address_t));
            } else if (tlv->value[0] == 0x02) {
                memcpy(sta_mac, &tlv->value[1], sizeof(mac_address_t));
            }
            break;
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_assoc_sta_ext_link_metric) {
            handle_assoc_sta_ext_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }

    tlv =  (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tmp_len = len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_vendor_sta_metrics) {
            handle_assoc_sta_vendor_link_metrics_tlv(tlv->value);
        }

        tmp_len -= (sizeof(em_tlv_t) + htons(tlv->len));
        tlv = (em_tlv_t *)((unsigned char *)tlv + sizeof(em_tlv_t) + htons(tlv->len));
    }
    db_cfg_type = dm->get_db_cfg_type();
    dm->set_db_cfg_type(db_cfg_type | db_cfg_type_sta_metrics_update);
    set_state(em_state_ctrl_configured);

    return 0;
}

int em_metrics_t::send_associated_sta_link_metrics_msg(mac_address_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_assoc_sta_link_metrics_query;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    dm_easy_mesh_t *dm;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // One STA MAC Address Type TLV (see section 17.2.23).
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_sta_mac_addr;
    memcpy(tlv->value, sta_mac, sizeof(mac_address_t));
    tlv->len = htons(sizeof(mac_address_t));

    tmp += (sizeof (em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof (em_tlv_t) + sizeof(mac_address_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Associated STA Link Metrics Query msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Associated STA Link Metrics Query send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Associated STA Link Metrics Query send success\n", __func__, __LINE__);
    return len;
}

int em_metrics_t::send_all_associated_sta_link_metrics_msg()
{
    dm_easy_mesh_t *dm;
    dm_sta_t *sta;

    dm = get_data_model();
    sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_map);
    while (sta != NULL) {
        if (sta->m_sta_info.associated == true) {
            send_associated_sta_link_metrics_msg(sta->m_sta_info.id);
        }
        sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_map, sta);
    }
}

int em_metrics_t::send_associated_link_metrics_response(mac_address_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_assoc_sta_link_metrics_rsp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    mac_addr_str_t mac_str;
    bool sta_found = false;
    dm_sta_t *sta;

    sta = (dm_sta_t *)hash_map_get_first(dm->m_sta_map);
    while(sta != NULL) {
        if (memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0) {
            sta_found = true;
            break;
        }
        sta = (dm_sta_t *)hash_map_get_next(dm->m_sta_map, sta);
    }

    if (sta == NULL) {
        //TODO: Have to fix Failed TLV while sending empty frame with error code
        return -1;
    }

    short msg_id = em_msg_type_assoc_sta_link_metrics_rsp;

    dm_easy_mesh_t::macbytes_to_string(sta_mac, mac_str);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //Assoc sta link metrics 17.2.24
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    sz = create_assoc_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //Error code  TLV 17.2.36
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, sta_mac, sta_found);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //assoc ext link metrics 17.2.62
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //assoc vendor link metrics
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_vendor_sta_metrics;
    sz = create_assoc_vendor_sta_link_metrics_tlv(tlv->value, sta_mac, sta);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_assoc_sta_link_metrics_rsp, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: Associated STA Link Metrics validation failed for %s\n", __func__, __LINE__, mac_str);
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Associated STA Link Metrics  send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }
    printf("%s:%d: Associated STA Link Metrics for sta %s sent successfully\n", __func__, __LINE__, mac_str);

    return len;
}

short em_metrics_t::create_ap_metrics_query_tlv(unsigned char *buff)
{
    short len = 0;
    unsigned int i;
    em_ap_metrics_query_t *ap_metrics_query;
    bssid_t *bssid;
    dm_easy_mesh_t *dm;

    ap_metrics_query =  (em_ap_metrics_query_t *)buff;
    bssid = ap_metrics_query->bssid;

    len += sizeof(em_ap_metrics_query_t);

    dm = get_data_model();

    ap_metrics_query->num_bssids = dm->m_num_bss;

    for(i = 0; i < ap_metrics_query->num_bssids; i++)
    {
        memcpy(bssid, &dm->m_bss[i].get_bss_info()->bssid.mac, sizeof(bssid_t));
        len += sizeof(bssid_t);
        bssid++;
    }
    return len;
}

short em_metrics_t::create_ap_radio_identifier_tlv(unsigned char *buff, em_radio_id_t radio_mac)
{
    short len = 0;
    em_radio_id_t  *ruid;
    
    ruid = (em_radio_id_t *)buff;
    
    memcpy(ruid, radio_mac,sizeof(em_radio_id_t));
    len += sizeof(em_radio_id_t);

    return len;
}

short em_metrics_t::create_ap_metrics_tlv(unsigned char *buff, bssid_t bssid)
{
    short len = 0;
    dm_bss_t *bss = NULL;
    dm_radio_t *radio = NULL;
    dm_easy_mesh_t *dm;

    em_ap_metric_t *ap_metric = (em_ap_metric_t *)buff;

    dm = get_data_model();
    bss = dm->find_bss_by_bssid(bssid);

    if(bss != NULL){

        radio = dm->get_radio(bss->get_bss_info()->ruid.mac);

        memcpy(ap_metric->ap_mac, bss->get_bss_info()->bssid.mac, sizeof(ap_metric->ap_mac));
        len += sizeof(ap_metric->ap_mac);

        ap_metric->channel_util = radio->get_radio_info()->utilization; // QUESTION: Why there is type difference between info struct and metrics struct for utilization?
        len += sizeof(ap_metric->channel_util);

        ap_metric->num_sta = bss->get_bss_info()->numberofsta; //QUESTION: again type difference, spec for metrics TLV indicate type of two octets, int by default for this project is 4?
        len += sizeof(ap_metric->num_sta);
        
        ap_metric->est_service_params_BE_bit = 1; 
        ap_metric->est_service_params_BK_bit = 1;
        ap_metric->est_service_params_VI_bit = 1;
        ap_metric->est_service_params_VO_bit = 1;
        //QUESTION how to establish presence of est_srvc bits? just check if bss_info est_svc has relevant data?
        len += sizeof(char);

        strncpy(ap_metric->est_service_params_BE, bss->get_bss_info()->est_svc_params_be,3); 
        len += sizeof(ap_metric->est_service_params_BE);
        strncpy(ap_metric->est_service_params_BK, bss->get_bss_info()->est_svc_params_bk,3);
        len += sizeof(ap_metric->est_service_params_BK);
        strncpy(ap_metric->est_service_params_VI, bss->get_bss_info()->est_svc_params_vi,3); 
        len += sizeof(ap_metric->est_service_params_VI);
        strncpy(ap_metric->est_service_params_VO, bss->get_bss_info()->est_svc_params_vo,3);
        len += sizeof(ap_metric->est_service_params_VO);
        //QUESTION: Type difference as in handle function, which type is valid, three octets unsigned char or em_string_t?
    
    }else{
        memcpy(&ap_metric->ap_mac, &bssid, sizeof(ap_metric->ap_mac));
        len += sizeof(ap_metric->ap_mac);

        ap_metric->channel_util = 0;//QUESTION: should I fill fields with 0 in case of NULL bss?
        len += sizeof(ap_metric->channel_util);
        len += sizeof(ap_metric->num_sta);
        len += sizeof(char);
        len += sizeof(ap_metric->est_service_params_BE);
        len += sizeof(ap_metric->est_service_params_BK);
        len += sizeof(ap_metric->est_service_params_VI);
        len += sizeof(ap_metric->est_service_params_VO);
    }
  
    return len;
}

short em_metrics_t::create_ap_ext_metrics_tlv(unsigned char *buff, bssid_t bssid)
{
    short len = 0;
    dm_bss_t *bss = NULL;
    dm_easy_mesh_t *dm;

    em_ap_ext_metric_t *ap_ext_metric = (em_ap_ext_metric_t *)buff;

    dm = get_data_model();
    bss = dm->find_bss_by_bssid(bssid);

    if(bss != NULL){

        memcpy(ap_ext_metric->bssid, bss->get_bss_info()->bssid.mac, sizeof(ap_ext_metric->bssid));
        len += sizeof(ap_ext_metric->bssid);

        ap_ext_metric->uni_bytes_sent = bss->get_bss_info()->unicast_bytes_sent;
        len += sizeof(ap_ext_metric->uni_bytes_sent);

        ap_ext_metric->uni_bytes_recv = bss->get_bss_info()->unicast_bytes_rcvd;
        len += sizeof(ap_ext_metric->uni_bytes_recv);

        ap_ext_metric->multi_bytes_sent = bss->get_bss_info()->multicast_bytes_sent;
        len += sizeof(ap_ext_metric->multi_bytes_sent);

        ap_ext_metric->multi_bytes_recv = bss->get_bss_info()->multicast_bytes_rcvd;
        len += sizeof(ap_ext_metric->multi_bytes_sent);

        ap_ext_metric->bcast_bytes_sent = bss->get_bss_info()->broadcast_bytes_sent;
        len += sizeof(ap_ext_metric->bcast_bytes_sent);

        ap_ext_metric->bcast_bytes_recv = bss->get_bss_info()->broadcast_bytes_rcvd;
        len += sizeof(ap_ext_metric->bcast_bytes_recv);
        
        //QUESTION: as in structure question, should these fields be added to bss as its presence is indicated in spec?

    }else{

        memcpy(ap_ext_metric->bssid, bss->get_bss_info()->bssid.mac, sizeof(ap_ext_metric->bssid));
        len += sizeof(ap_ext_metric->bssid);

        ap_ext_metric->uni_bytes_sent = 0;
        len += sizeof(ap_ext_metric->uni_bytes_sent);

        ap_ext_metric->uni_bytes_recv = 0;
        len += sizeof(ap_ext_metric->uni_bytes_recv);
        
        ap_ext_metric->multi_bytes_sent = 0;
        len += sizeof(ap_ext_metric->multi_bytes_sent);

        ap_ext_metric->multi_bytes_recv = 0;
        len += sizeof(ap_ext_metric->multi_bytes_recv);

        ap_ext_metric->bcast_bytes_sent = 0;
        len += sizeof(ap_ext_metric->bcast_bytes_sent);

        ap_ext_metric->bcast_bytes_recv = 0;
        len += sizeof(ap_ext_metric->bcast_bytes_recv);
        
    }

    return len;
}

short em_metrics_t::create_radio_metrics_tlv(unsigned char *buff, mac_address_t ruid)
{
    short len = 0;
    dm_radio_t *radio = NULL;
    dm_easy_mesh_t *dm;

    em_radio_metric_t *radio_metric = (em_radio_metric_t *)buff;

    dm = get_data_model();
    radio = dm->get_radio(ruid);

    if(radio != NULL){

        memcpy(radio_metric->ruid, radio->get_radio_info()->id.mac, sizeof(radio_metric->ruid));
        len += sizeof(radio_metric->ruid);

        radio_metric->noise = radio->get_radio_info()->noise; //QUESTION: why char vs int type difference?
        len += sizeof(radio_metric->noise);

        radio_metric->transmit = radio->get_radio_info()->transmit;
        len += sizeof(radio_metric->transmit);

        radio_metric->recv_self = radio->get_radio_info()->recv_self;
        len += sizeof(radio_metric->recv_self);

        radio_metric->recv_other = radio->get_radio_info()->recv_other;
        len += sizeof(radio_metric->recv_other);

    }else{
        memcpy(radio_metric->ruid, ruid, sizeof(radio_metric->ruid));
        len += sizeof(radio_metric->ruid);

        radio_metric->noise = 0; //QUESTION: why char vs int type difference?
        len += sizeof(radio_metric->noise);

        radio_metric->transmit = 0;
        len += sizeof(radio_metric->transmit);

        radio_metric->recv_self = 0;
        len += sizeof(radio_metric->recv_self);

        radio_metric->recv_other = 0;
        len += sizeof(radio_metric->recv_other);
    }
    
    return len;
}

/*short em_metrics_t::create_assoc_sta_traffic_metrics_tlv(unsigned char *buff, mac_address_t sta_mac)
{
    short len = 0;
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t *dm;

    em_assoc_sta_traffic_sts_t *assoc_sta_traffic_stats = (em_assoc_sta_traffic_sts_t *)buff;
    dm = get_data_model();
    sta = dm->get_first_sta(sta_mac);

    if(sta != NULL){
        memcpy(&assoc_sta_traffic_stats->sta_mac_addr, &sta->get_sta_info()->id, sizeof(assoc_sta_traffic_stats->sta_mac_addr));
        len += sizeof(assoc_sta_traffic_stats->sta_mac_addr);

        assoc_sta_traffic_stats->bytes_sent = sta->get_sta_info()->bytes_tx;
        len += sizeof(assoc_sta_traffic_stats->bytes_sent);

        assoc_sta_traffic_stats->bytes_recv = sta->get_sta_info()->bytes_rx;
        len += sizeof(assoc_sta_traffic_stats->bytes_recv);

        assoc_sta_traffic_stats->packets_sent = sta->get_sta_info()->pkts_tx;
        len += sizeof(assoc_sta_traffic_stats->packets_sent);

        assoc_sta_traffic_stats->packets_recv = sta->get_sta_info()->pkts_rx;
        len += sizeof(assoc_sta_traffic_stats->packets_recv); 

        assoc_sta_traffic_stats->tx_packets_errors = sta->get_sta_info()->errors_tx;
        len += sizeof(assoc_sta_traffic_stats->tx_packets_errors);   

        assoc_sta_traffic_stats->rx_packets_errors = sta->get_sta_info()->errors_rx;
        len += sizeof(assoc_sta_traffic_stats->rx_packets_errors);  

        assoc_sta_traffic_stats->retrans_count = sta->get_sta_info()->retrans_count;
        len += sizeof(assoc_sta_traffic_stats->retrans_count);                    

    }else{
        memcpy(&assoc_sta_traffic_stats->sta_mac_addr, &sta_mac, sizeof(assoc_sta_traffic_stats->sta_mac_addr));
        len += sizeof(assoc_sta_traffic_stats->sta_mac_addr);

        assoc_sta_traffic_stats->bytes_sent = 0;
        len += sizeof(assoc_sta_traffic_stats->bytes_sent);

        assoc_sta_traffic_stats->bytes_recv = 0;
        len += sizeof(assoc_sta_traffic_stats->bytes_recv);

        assoc_sta_traffic_stats->packets_sent = 0;
        len += sizeof(assoc_sta_traffic_stats->packets_sent);

        assoc_sta_traffic_stats->packets_recv = 0;
        len += sizeof(assoc_sta_traffic_stats->packets_recv); 

        assoc_sta_traffic_stats->tx_packets_errors = 0;
        len += sizeof(assoc_sta_traffic_stats->tx_packets_errors);   

        assoc_sta_traffic_stats->rx_packets_errors = 0;
        len += sizeof(assoc_sta_traffic_stats->rx_packets_errors);  

        assoc_sta_traffic_stats->retrans_count = 0;
        len += sizeof(assoc_sta_traffic_stats->retrans_count); 
    }

    return len;
}

short em_metrics_t::create_assoc_wifi6_sta_sts_rprt_tlv(unsigned char *buff, mac_address_t sta_mac)
{
    short len = 0;
    unsigned int i;
    dm_sta_t *sta = NULL;
    dm_easy_mesh_t *dm;

    em_assoc_wifi6_sta_sts_t *assoc_wifi6_sta_sts = (em_assoc_wifi6_sta_sts_t *)buff;
    dm = get_data_model();

    sta = dm->get_first_sta(sta_mac);

    if(sta != NULL){

        for(i = 0; i < )
        {

        }

    }else{

    }

}*/
//QUESTION: should the TIDs and number of them be specified in radio_info_t structure?

short em_metrics_t::create_assoc_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    //TODO: Cleanup hard-coded data
    short len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_link_metrics_t *assoc_sta_metrics = (em_assoc_sta_link_metrics_t*) buff;
    em_assoc_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return len;
    }
    else {
        metrics	= &assoc_sta_metrics->assoc_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(&assoc_sta_metrics->sta_mac, &sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = num_bssids;
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(&metrics->bssid, &sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->time_delta_ms = 10;//TODO: Pending proper update
            len += sizeof(metrics->time_delta_ms);

            metrics->est_mac_data_rate_dl = sta->m_sta_info.last_dl_rate;
            len += sizeof(metrics->est_mac_data_rate_dl);

            metrics->est_mac_data_rate_ul = sta->m_sta_info.last_ul_rate;
            len += sizeof(metrics->est_mac_data_rate_ul);

            metrics->rcpi = 1;//TODO: Pending proper update
            len += sizeof(metrics->rcpi);
        }
    }
    return len;
}

short em_metrics_t::create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    //TODO: Cleanup hard-coded data
    short len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_ext_link_metrics_t *assoc_sta_metrics = (em_assoc_sta_ext_link_metrics_t*) buff;
    em_assoc_ext_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return len;
    }
    else {
        metrics	= &assoc_sta_metrics->assoc_ext_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(metrics->bssid, sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->last_data_dl_rate = sta->m_sta_info.last_dl_rate;
            len += sizeof(metrics->last_data_dl_rate);

            metrics->last_data_ul_rate = sta->m_sta_info.last_ul_rate;
            len += sizeof(metrics->last_data_ul_rate);

            metrics->util_receive = sta->m_sta_info.util_rx;
            len += sizeof(metrics->util_receive);

            metrics->util_transmit = sta->m_sta_info.util_tx;
            len += sizeof(metrics->util_transmit);
        }
    }
    return len;
}

short em_metrics_t::create_assoc_vendor_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta)
{
    short len = 0;
    dm_easy_mesh_t *dm;
    int num_bssids = 0;
    em_assoc_sta_vendor_link_metrics_t *assoc_sta_metrics = (em_assoc_sta_vendor_link_metrics_t*) buff;
    em_assoc_vendor_link_metrics_t *metrics;

    dm = get_data_model();
    num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);

    if (sta == NULL) {
        memcpy(&assoc_sta_metrics->sta_mac, &sta_mac, sizeof(assoc_sta_metrics->sta_mac));
        len += sizeof(assoc_sta_metrics->sta_mac);

        assoc_sta_metrics->num_bssids = 0;
        len += sizeof(assoc_sta_metrics->num_bssids);
        return len;
    }
    else {
        metrics = &assoc_sta_metrics->assoc_vendor_link_metrics[0];
        if ((memcmp(sta->m_sta_info.id, sta_mac, sizeof(mac_address_t)) == 0)) {
            memcpy(assoc_sta_metrics->sta_mac, sta->m_sta_info.id, sizeof(assoc_sta_metrics->sta_mac));
            len += sizeof(assoc_sta_metrics->sta_mac);

            assoc_sta_metrics->num_bssids = dm->get_num_bss_for_associated_sta(sta_mac);
            len += sizeof(assoc_sta_metrics->num_bssids);

            memcpy(metrics->bssid, sta->m_sta_info.bssid, sizeof(metrics->bssid));
            len += sizeof(metrics->bssid);

            metrics->packets_received = sta->m_sta_info.pkts_rx;
            len += sizeof(metrics->packets_received);

            metrics->packets_sent = sta->m_sta_info.pkts_tx;
            len += sizeof(metrics->packets_sent);

            metrics->bytes_received = sta->m_sta_info.bytes_rx;
            len += sizeof(metrics->bytes_received);

            metrics->bytes_sent = sta->m_sta_info.bytes_tx;
            len += sizeof(metrics->bytes_sent);
        }
    }
    return len;
}

short em_metrics_t::create_error_code_tlv(unsigned char *buff, mac_address_t sta, bool sta_found)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char reason = 0;

    /* if(sta_found == false)
    {
        reason = 0x02;
    } */

    memcpy(tmp, &reason, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    memcpy(tmp, sta, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    return len;
}

void em_metrics_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    tlvs = data + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    tlvs_len = len - (sizeof(em_raw_hdr_t) - sizeof(em_cmdu_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_ap_metrics_rsp:
            handle_ap_metrics_resp_msg(data, len);
            break;

        case em_msg_type_ap_metrics_query:
            handle_ap_metrics_query_msg(data, len);
            break;

        case em_msg_type_assoc_sta_link_metrics_rsp:
            handle_associated_sta_link_metrics_resp(data, len);
            break;

        case em_msg_type_assoc_sta_link_metrics_query:
            handle_associated_sta_link_metrics_query(data, len);
            break;

        default:
            break;
    }
}

void em_metrics_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_sta_link_metrics_pending:
            send_all_associated_sta_link_metrics_msg();
            break;
        
        case em_state_ctrl_ap_metrics_pending:
            send_ap_metrics_query_msg();
            break;

    }
}

em_metrics_t::em_metrics_t()
{

}

em_metrics_t::~em_metrics_t()
{

}
