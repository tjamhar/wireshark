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

#define HTTP 0
#define IPP 1

void proto_register_ippusb(void);
void proto_reg_handoff_ippusb(void);

static int proto_ippusb = -1;
static gint ett_ippusb = -1;
static gint ett_ippusb_as = -1;
static gint ett_ippusb_attr = -1;
static gint ett_ippusb_member = -1;

static dissector_table_t ippusb_dissector_table;

static int
dissect_ippusb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    //skip to http header info
    //put dummy info in for http dissector
    proto_tree  *ippusb_tree;
    proto_item  *ti;
    int offset = 0;
    int ret;
    int first_linelen;
    const guchar *first_line;
    gint next_offset;

    ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
    ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

    first_linelen = tvb_find_line_end(tvb, offset,  tvb_ensure_captured_length_remaining(tvb, offset), &next_offset, TRUE);
    first_line = tvb_get_ptr(tvb, offset, first_linelen);

    //check if there is a http header to parse before ipp
    if (is_http_header(first_linelen, first_line)) {        
        ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, tvb, pinfo, tree, TRUE, data);
    }
    else {
        ret = dissector_try_uint_new(ippusb_dissector_table, IPP, tvb, pinfo, tree, TRUE, data);
    }

    if (ret) {
            return tvb_captured_length(tvb);
    }
    else {
        return 0;
    }
}

bool is_http_header(int first_linelen, const guchar *first_line){
    if ((first_linelen >= 5 && strncmp(firstline, "HTTP/", 5) == 0) ||
		(first_linelen >= 3 && strncmp(firstline, "ICY", 3) == 0) ||
        (first_linelen >= 3 && strncmp(firstline, "GET", 3) == 0) ||
		(first_linelen >= 3 && strncmp(firstline, "PUT", 3) == 0) ||
        (first_linelen >= 4 && strncmp(firstline, "COPY", 4) == 0) ||
		(first_linelen >= 4 && strncmp(firstline, "HEAD", 4) == 0) ||
		(first_linelen >= 4 && strncmp(firstline, "LOCK", 4) == 0) ||
		(first_linelen >= 4 && strncmp(firstline, "MOVE", 4) == 0) ||
		(first_linelen >= 4 && strncmp(firstline, "POLL", 4) == 0) ||
		(first_linelen >= 4 && strncmp(firstline, "POST", 4) == 0) ||
        (first_linelen >= 5 && strncmp(firstline, "BCOPY", 5) == 0) ||
		(first_linelen >= 5 && strncmp(firstline, "BMOVE", 5) == 0) ||
		(first_linelen >= 5 && strncmp(firstline, "MKCOL", 5) == 0) ||
		(first_linelen >= 5 && strncmp(firstline, "TRACE", 5) == 0) ||
		(first_linelen >= 5 && strncmp(firstline, "PATCH", 5) == 0) ||  
		(first_linelen >= 5 && strncmp(firstline, "LABEL", 5) == 0) ||  
		(first_linelen >= 5 && strncmp(firstline, "MERGE", 5) == 0) ||
        (first_linelen >= 6 && strncmp(firstline, "DELETE", 6) == 0) ||
		(first_linelen >= 6 && strncmp(firstline, "SEARCH", 6) == 0) ||
		(first_linelen >= 6 && strncmp(firstline, "UNLOCK", 6) == 0) ||
		(first_linelen >= 6 && strncmp(firstline, "REPORT", 6) == 0) || 
		(first_linelen >= 6 && strncmp(firstline, "UPDATE", 6) == 0)) {
            
        return true;
    }
    else {
        return false
    }
}

void
proto_register_ippusb(void)
{

   static gint *ett[] = {
        &ett_ippusb,
        &ett_ippusb_as,
        &ett_ippusb_attr,
        &ett_ippusb_member
    };

    proto_ippusb = proto_register_protocol("Internet Printing Protocol Over USB", "IPPUSB", "ippusb");

    ippusb_dissector_table = register_dissector_table("ippusb", "IPP Over USB", proto_ippusb, FT_UINT8, BASE_DEC);

    proto_register_subtree_array(ett, array_length(ett));
}

 void
proto_reg_handoff_ippusb(void)
{
    dissector_handle_t ippusb_handle;

    /*
     * Register ourselves under usb bulk 
     * IPP packets could come from a variety of usb class types
     */
    ippusb_handle = create_dissector_handle(dissect_ippusb, proto_ippusb);
    dissector_add_uint("usb.bulk", IF_CLASS_UNKNOWN, ippusb_handle);
    dissector_add_uint("usb.bulk", IF_CLASS_VENDOR_SPECIFIC, ippusb_handle);
}