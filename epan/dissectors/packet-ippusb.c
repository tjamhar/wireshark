/* packet-ippusb.c
 * Routines for IPPUSB packet disassembly
 *
 * Jamie Hare <jamienh@umich.edu>
 *
 * PROTONAME: Internet Printing Protocol Over USB 
 * PROTOSHORTNAME: IPPUSB
 * PROTOABBREV: ippusb
 * 
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include "packet-http.h"
#include "packet-usb.h"
#include <stdio.h>

void proto_register_ippusb(void);
void proto_reg_handoff_ippusb(void);

static int proto_ippusb = -1;

static int
dissect_ippusb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    //skip to http header info
    //put dummy info in for http dissector

    proto_tree  *ippusb_tree;
    proto_item  *ti;
    int         offset     = 0;
    http_message_info_t *message_info = (http_message_info_t *)data;
    gboolean    is_request;
    guint16     operation_status;
    const gchar *status_type;
    guint32	request_id;
    conversation_t *conversation;

    //offset +=

    //if (tvb_offset_exists(tvb, offset)) {
        //call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, ipp_tree);
    //}
    return tvb_captured_length(tvb);
}

void
proto_register_ippusb(void)
{
    //static hf_register_info hf[] = {
     // /* Generated from convert_proto_tree_add_text.pl */
   // };

   // static gint *ett[] = {
   //     &ett_ippusb,
   //     &ett_ippusb_as,
   //     &ett_ippusb_attr,
   //     &ett_ippusb_member
   // };

    proto_ippusb = proto_register_protocol("Internet Printing Protocol Over USB", "IPPUSB", "ippusb");

    //proto_register_field_array(proto_ippusb, hf, array_length(hf));
    //proto_register_subtree_array(ett, array_length(ett));
}

 void
proto_reg_handoff_ippusb(void)
{
    dissector_handle_t ippusb_handle;

    /*
     * Register ourselves as running atop HTTP and using port 631.
     */
    ippusb_handle = create_dissector_handle(dissect_ippusb, proto_ippusb);
    dissector_add_uint("usb.bulk", IF_CLASS_PRINTER, ippusb_handle);
}