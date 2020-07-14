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
#include <reassemble.h>
#include <packet-http.h>
#include <packet-usb.h>
#include <stdio.h>

#define HTTP 0

void proto_register_ippusb(void);
void proto_reg_handoff_ippusb(void);
static int is_http_header(int first_linelen, const guchar *first_line);

/* Reassemble by default */
static gboolean global_ippusb_reassemble = TRUE;
static guint32 ippusb_last_pdu = -1;

static int proto_ippusb = -1;
static gint ett_ippusb = -1;
static gint ett_ippusb_as = -1;
static gint ett_ippusb_attr = -1;
static gint ett_ippusb_member = -1;
static gint ett_ippusb_fragment= -1;
static gint ett_ippusb_fragments = -1;

/* For reassembly */
static gint hf_ippusb_fragments = -1;
static gint hf_ippusb_fragment = -1;
static gint hf_ippusb_fragment_overlap = -1;
static gint hf_ippusb_fragment_overlap_conflict = -1;
static gint hf_ippusb_fragment_multiple_tails = -1;
static gint hf_ippusb_fragment_too_long_fragment = -1;
static gint hf_ippusb_fragment_error = -1;
static gint hf_ippusb_fragment_count = -1;
static gint hf_ippusb_reassembled_in = -1;
static gint hf_ippusb_reassembled_length = -1;
static gint hf_ippusb_reassembled_data = -1;

static const fragment_items ippusb_frag_items = {
  &ett_ippusb_fragment,
  &ett_ippusb_fragments,
  &hf_ippusb_fragments,
  &hf_ippusb_fragment,
  &hf_ippusb_fragment_overlap,
  &hf_ippusb_fragment_overlap_conflict,
  &hf_ippusb_fragment_multiple_tails,
  &hf_ippusb_fragment_too_long_fragment,
  &hf_ippusb_fragment_error,
  &hf_ippusb_fragment_count,
  &hf_ippusb_reassembled_in,
  &hf_ippusb_reassembled_length,
  &hf_ippusb_reassembled_data,
  "IPPUSB fragments"
};

struct ippusb_multisegment_pdu {
	guint32 nxtpdu;
	guint32 first_frame;
	guint32 last_frame;
    guint32 running_size;
    gboolean finished;
    guint32 flags;
};

struct ippusb_multisegment_pdu *
pdu_store(packet_info *pinfo, wmem_tree_t *multisegment_pdus)
{
    struct ippusb_multisegment_pdu *msp;

    msp=wmem_new(wmem_file_scope(), struct ippusb_multisegment_pdu);
    msp->first_frame=pinfo->num;
    msp->last_frame=pinfo->num;
    msp->finished = FALSE;
    msp->flags=0;
    wmem_tree_insert32(multisegment_pdus, pinfo->num, (void *)msp);

    return msp;
}

struct ippusb_analysis {

	wmem_tree_t *multisegment_pdus;

};

static struct ippusb_analysis *
init_ippusb_conversation_data()
{
    struct ippusb_analysis *ippusbd;

    /* Initialize the tcp protocol data structure to add to the tcp conversation */
    ippusbd=wmem_new0(wmem_file_scope(), struct ippusb_analysis);

    ippusbd->multisegment_pdus=wmem_tree_new(wmem_file_scope());

    return ippusbd;
}

struct ippusb_analysis *
get_ippusb_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    struct ippusb_analysis *ippusbd;

    if(conv==NULL ) {
        conv = find_or_create_conversation(pinfo);
    }

    ippusbd=(struct ippusb_analysis *)conversation_get_proto_data(conv, proto_ippusb);

    if (!ippusbd) {
        ippusbd = init_ippusb_conversation_data();
        conversation_add_proto_data(conv, proto_ippusb, ippusbd);
    }

    if (!ippusbd) {
      return NULL;
    }

    return ippusbd;
}


static gpointer ippusb_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data)
{
    return (gpointer)data;
}

static gpointer ippusb_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data)
{
    return (gpointer)data;
}

static void ippusb_free_temporary_key(gpointer ptr _U_) { }

static void ippusb_free_persistent_key(gpointer ptr _U_) { }

reassembly_table_functions ippusb_reassembly_table_functions =
{
    g_direct_hash,
    g_direct_equal,
    ippusb_temporary_key,
    ippusb_persistent_key,
    ippusb_free_temporary_key,
    ippusb_free_persistent_key
};

static dissector_table_t ippusb_dissector_table;
static reassembly_table ippusb_reassembly_table;

/* Main dissector function */
static int
dissect_ippusb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{

    gint reported_length = tvb_reported_length(tvb);
    if (tvb_reported_length(tvb) <= 8) {
        return 0;
    }

    proto_tree  *ippusb_tree;
    proto_item  *ti;
    gint offset = 0;
    gint ret;
    gint first_linelen;
    const guchar *first_line;
    gint next_offset;
    guint8 first;
    guint8 last;
    struct ippusb_analysis *ippusbd = NULL;
    conversation_t *conv = NULL;

    struct ippusb_multisegment_pdu *new_msp = NULL;
    struct ippusb_multisegment_pdu *current_msp = NULL;
    struct ippusb_multisegment_pdu *previous_msp = NULL;

    if((conv = find_conversation_pinfo(pinfo, 0)) != NULL) {
        /* Update how far the conversation reaches */
        if (pinfo->num > conv->last_frame) {
            conv->last_frame = pinfo->num;
        }
    }
    else {
        conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, ENDPOINT_TCP,
                     pinfo->srcport, pinfo->destport, 0);
    }

    ippusbd = get_ippusb_conversation_data(conv,pinfo);

    first_linelen = tvb_find_line_end(tvb, offset,  tvb_ensure_captured_length_remaining(tvb, offset), &next_offset, TRUE);
    first_line = tvb_get_ptr(tvb, offset, first_linelen);

    //get first and last byte of packet
    first = tvb_get_bits8(tvb, 0, 8);
    last = (tvb_get_guint8(tvb, reported_length - 1));

    if (is_http_header(first_linelen, first_line) && last == 0x03) {

        //an indiviual ippusb packet with http header
        ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
        ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

        if (ippusb_last_pdu >= 0 && !pinfo->fd->visited) {
            ippusb_last_pdu = -1;
        }

        ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, tvb, pinfo, tree, TRUE, data);
    }
    else if (!pinfo->fd->visited) {

         //first time this packet is ever seen

        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;

        ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
        ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);


        if(is_http_header(first_linelen, first_line)){

            if (ippusb_last_pdu >= 0) {
                ippusb_last_pdu = -1;
            }

            new_msp = pdu_store(pinfo, ippusbd->multisegment_pdus);
            new_msp->running_size = reported_length;

            fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                        GUINT_TO_POINTER(new_msp->first_frame), 0, reported_length, TRUE);
            ippusb_last_pdu = pinfo->num;
        }
        else{

            previous_msp = (struct ippusb_multisegment_pdu *)wmem_tree_lookup32_le(ippusbd->multisegment_pdus, ippusb_last_pdu);

            if(previous_msp){
                previous_msp->nxtpdu = pinfo->num;
                new_msp = pdu_store(pinfo, ippusbd->multisegment_pdus);
                new_msp->first_frame = previous_msp->first_frame;
                new_msp->running_size = previous_msp->running_size + reported_length;

                if(last != 0x03) {
                    fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                        GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, reported_length, TRUE);
                    ippusb_last_pdu = pinfo->num;
                }
                else {
                    new_msp->finished = TRUE;

                    fragment_head * head = fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                                        GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, reported_length, FALSE);
                    tvbuff_t *processedTvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                    pinfo->can_desegment = 0;

                    ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processedTvb, pinfo, tree, TRUE, data);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "  Reassembled Data");
                    ippusb_last_pdu = -1;

                }
            }
        }

        pinfo->fragmented = save_fragmented;
    }
    else {

        //not the first time this is seen

        gboolean save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        current_msp = (struct ippusb_multisegment_pdu *)wmem_tree_lookup32_le(ippusbd->multisegment_pdus, pinfo->num);

        if (current_msp && current_msp->nxtpdu == 0 && !current_msp->finished) {
             ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
            ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

            fragment_head * head = fragment_get_reassembled_id(&ippusb_reassembly_table, pinfo, current_msp->first_frame);

            if (head) {
            tvbuff_t *processedTvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

            pinfo->can_desegment = 0;

            ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processedTvb, pinfo, tree, TRUE, data);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  Reassembled Data with Error");
            }

        }
        else if (current_msp && last == 0x03) {

            ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
            ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

            fragment_head * head = fragment_get_reassembled_id(&ippusb_reassembly_table, pinfo, current_msp->first_frame);

            tvbuff_t *processedTvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

            pinfo->can_desegment = 0;

            ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processedTvb, pinfo, tree, TRUE, data);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  Reassembled Data");

        }

        pinfo->fragmented = save_fragmented;
    }

    if (ret) {
        return tvb_captured_length(tvb);
    }
    else {
        return 0;
    }
}

static int
is_http_header(int first_linelen, const guchar *first_line) {
    if ((first_linelen >= 5 && strncmp(first_line, "HTTP/", 5) == 0) ||
        (first_linelen >= 3 && strncmp(first_line, "ICY", 3) == 0) ||
        (first_linelen >= 3 && strncmp(first_line, "GET", 3) == 0) ||
        (first_linelen >= 3 && strncmp(first_line, "PUT", 3) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "COPY", 4) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "HEAD", 4) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "LOCK", 4) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "MOVE", 4) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "POLL", 4) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "POST", 4) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "BCOPY", 5) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "BMOVE", 5) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "MKCOL", 5) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "TRACE", 5) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "PATCH", 5) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "LABEL", 5) == 0) ||
        (first_linelen >= 5 && strncmp(first_line, "MERGE", 5) == 0) ||
        (first_linelen >= 6 && strncmp(first_line, "DELETE", 6) == 0) ||
        (first_linelen >= 6 && strncmp(first_line, "SEARCH", 6) == 0) ||
        (first_linelen >= 6 && strncmp(first_line, "UNLOCK", 6) == 0) ||
        (first_linelen >= 6 && strncmp(first_line, "REPORT", 6) == 0) ||
        (first_linelen >= 6 && strncmp(first_line, "UPDATE", 6) == 0)) {

        return TRUE;
    }
    else {
        return FALSE;
    }
}

static void
ippusb_init(void)
{
    ippusb_last_pdu = 0;
}

void
proto_register_ippusb(void)
{

     static hf_register_info hf[] = {

        /* Reassembly */
        { &hf_ippusb_fragment,
            { "Fragment", "ippusb.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ippusb_fragments,
            { "Fragments", "ippusb.fragments", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ippusb_fragment_overlap,
            { "Fragment overlap", "ippusb.fragment.overlap", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
        { &hf_ippusb_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "ippusb.fragment.overlap.conflict",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_ippusb_fragment_multiple_tails,
            { "Multiple tail fragments found", "ippusb.fragment.multipletails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_ippusb_fragment_too_long_fragment,
            { "Fragment too long", "ippusb.fragment.toolongfragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},
        { &hf_ippusb_fragment_error,
            { "Defragmentation error", "ippusb.fragment.error", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_ippusb_fragment_count,
            { "Fragment count", "ippusb.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_ippusb_reassembled_in,
            { "Reassembled payload in frame", "ippusb.reassembled_in", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "This payload packet is reassembled in this frame", HFILL }},
        { &hf_ippusb_reassembled_length,
            { "Reassembled payload length", "ippusb.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x0, "The total length of the reassembled payload", HFILL }},
        { &hf_ippusb_reassembled_data,
            { "Reassembled data", "ippusb.reassembled.data", FT_BYTES, BASE_NONE,
            NULL, 0x0, "The reassembled payload", HFILL }},
        };

   static gint *ett[] = {
        &ett_ippusb,
        &ett_ippusb_as,
        &ett_ippusb_attr,
        &ett_ippusb_member,
        &ett_ippusb_fragments,
        &ett_ippusb_fragment
    };

    proto_ippusb = proto_register_protocol("Internet Printing Protocol Over USB", "IPPUSB", "ippusb");

    ippusb_dissector_table = register_dissector_table("ippusb", "IPP Over USB", proto_ippusb, FT_UINT8, BASE_DEC);

    proto_register_field_array(proto_ippusb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(ippusb_init);
    reassembly_table_register(&ippusb_reassembly_table, &ippusb_reassembly_table_functions);
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
    dissector_add_uint("usb.bulk", IF_CLASS_PRINTER, ippusb_handle);
}