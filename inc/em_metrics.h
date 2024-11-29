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

#ifndef EM_METRICS_H
#define EM_METRICS_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class em_metrics_t {

    virtual dm_easy_mesh_t *get_data_model() = 0;
    virtual em_state_t get_state() = 0;
    virtual void set_state(em_state_t state) = 0;
    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    virtual em_profile_type_t get_profile_type() = 0;

    int send_ap_metrics_query_msg();
    int handle_ap_metrics_query_msg(unsigned char *buff, unsigned int len);

    int send_ap_metrics_response_msg(bssid_t *bssid_to_report, unsigned int num_bssid, em_radio_id_t *radios_to_report, unsigned int num_radio);
    int handle_ap_metrics_resp_msg(unsigned char *buff, unsigned int len);

    int handle_ap_metrics_query_tlv(unsigned char *buff, bssid_t *bssid_to_report, unsigned int *num_bssid);
    int handle_radio_identifier_tlv(unsigned char *buff, em_radio_id_t *radios_to_report);


    int handle_ap_metrics_tlv(unsigned char *buff);
    int handle_ap_ext_metrics_tlv(unsigned char *buff);
    int handle_radio_metrics_tlv(unsigned char *buff);
    int handle_assoc_sta_traffic_metrics_tlv(unsigned char *buff);
    int handle_assoc_wifi6_sta_sts_rprt_tlv(unsigned char *buff);
    //int handle_affil_ap_metrics_tlv(unsigned char *buff); TODO wifi 6.0
    //int handle_affil_sta_metrics_tlv(unsigned char *buff); TODO wifi 6.0

    short create_ap_metrics_query_tlv(unsigned char *buff);
    short create_ap_radio_identifier_tlv(unsigned char *buff, em_radio_id_t radio_mac);

    short create_ap_metrics_tlv(unsigned char *buff, bssid_t bssid);
    short create_ap_ext_metrics_tlv(unsigned char *buff, bssid_t bssid);
    short create_radio_metrics_tlv(unsigned char *buff, mac_address_t ruid);
    //short create_assoc_sta_traffic_metrics_tlv(unsigned char *buff, mac_address_t sta_mac);
    //short create_assoc_wifi6_sta_sts_rprt_tlv(unsigned char *buff, mac_address_t sta_mac);
    //short create_affil_ap_metrics_tlv(unsigned char *buff, mac_address_t ap_mac); TODO wifi 6.0
    //short create_affil_sta_metrics_tlv(unsigned char *buff, mac_address_t ap_mac); TODO wifi 6.0

    int send_all_associated_sta_link_metrics_msg();
    int send_associated_sta_link_metrics_msg(mac_address_t sta_mac);
    int send_associated_link_metrics_response(mac_address_t sta_mac);

    int handle_associated_sta_link_metrics_query(unsigned char *buff, unsigned int len);
    int handle_associated_sta_link_metrics_resp(unsigned char *buff, unsigned int len);
    int handle_assoc_sta_link_metrics_tlv(unsigned char *buff);
    int handle_assoc_sta_ext_link_metrics_tlv(unsigned char *buff);
    int handle_assoc_sta_vendor_link_metrics_tlv(unsigned char *buff);

    short create_assoc_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta);
    short create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta);
    short create_error_code_tlv(unsigned char *buff, mac_address_t sta, bool sta_found);
    short create_assoc_vendor_sta_link_metrics_tlv(unsigned char *buff, mac_address_t sta_mac, const dm_sta_t *const sta);

public:
    void    process_msg(unsigned char *data, unsigned int len);
    void    process_ctrl_state();

    em_metrics_t();
    ~em_metrics_t();
};

#endif
