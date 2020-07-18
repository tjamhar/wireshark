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
#define IPP 1

#define TAG_END_OF_ATTRIBUTES 0x03

#define CHUNK_LENGTH_MAX 8

#define NUM_OF_BITS 8

#define LENGTH_OF_RETURN_NEWLINE 2

static const guint8 CHUNKED_END[] = { 0x0d, 0x0a };
static tvbuff_t *chunked_end_tvb = NULL;

void proto_register_ippusb(void);
void proto_reg_handoff_ippusb(void);
static gint is_http_header(gint first_linelen, const guchar *first_line);

static gint proto_ippusb = -1;
static gint ett_ippusb = -1;
static gint ett_ippusb_as = -1;
static gint ett_ippusb_attr = -1;
static gint ett_ippusb_member = -1;
static gint ett_ippusb_fragment= -1;
static gint ett_ippusb_fragments = -1;

/* For reassembly */
static guint32 ippusb_last_pdu = -1;

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

/* Reassemble by default */
static gboolean global_ippusb_reassemble = TRUE;

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
    guint nxtpdu;
	guint32 first_frame;
	guint32 last_frame;
    guint32 running_size;
    gboolean finished;
    gboolean reassembled;
    gboolean is_chunked;
    guint32 http_ipp_split;

    guint32 flags;
    #define MSP_FLAGS_REASSEMBLE_ENTIRE_SEGMENT	0x00000001
    #define MSP_FLAGS_GOT_ALL_SEGMENTS		0x00000002
    #define MSP_FLAGS_MISSING_FIRST_SEGMENT     0x00000004
};

struct ippusb_multisegment_pdu *
pdu_store(packet_info *pinfo, wmem_tree_t *multisegment_pdus, guint32 previous_first_frame, guint32 previous_is_chunked, guint32 previous_http_ipp_split)
{
    struct ippusb_multisegment_pdu *msp;

    msp = wmem_new(wmem_file_scope(), struct ippusb_multisegment_pdu);
    msp->first_frame = previous_first_frame;
    msp->last_frame = pinfo->num;
    msp->finished = FALSE;
    msp->reassembled = FALSE;
    msp->is_chunked = previous_is_chunked;
    msp->http_ipp_split = previous_http_ipp_split;
    msp->flags = 0;
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

    ippusbd = wmem_new0(wmem_file_scope(), struct ippusb_analysis);

    ippusbd->multisegment_pdus=wmem_tree_new(wmem_file_scope());

    return ippusbd;
}

struct ippusb_analysis *
get_ippusb_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    struct ippusb_analysis *ippusbd;

    if(conv == NULL ) {
        conv = find_or_create_conversation(pinfo);
    }

    ippusbd = (struct ippusb_analysis *)conversation_get_proto_data(conv, proto_ippusb);

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
    proto_tree *ippusb_tree;
    proto_item *ti;
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

    gint reported_length = tvb_reported_length(tvb);

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

    ippusbd = get_ippusb_conversation_data(conv, pinfo);

    first_linelen = tvb_find_line_end(tvb, offset, tvb_ensure_captured_length_remaining(tvb, offset), &next_offset, TRUE);
    first_line = tvb_get_ptr(tvb, offset, first_linelen);

    /* Get first and last byte of segment */
    first = tvb_get_bits8(tvb, 0, NUM_OF_BITS);
    last = (tvb_get_guint8(tvb, reported_length - 1));

    if (is_http_header(first_linelen, first_line) && last == TAG_END_OF_ATTRIBUTES) {

        /* An indiviual ippusb packet with http header */
        ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
        ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

        if (ippusb_last_pdu >= 0 && !pinfo->fd->visited) {
            ippusb_last_pdu = -1;
        }

        ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, tvb, pinfo, tree, TRUE, data);
    }
    else if (global_ippusb_reassemble) {
        /* If reassembly is wanted */

        if (!pinfo->fd->visited) {
            /* First time this segment is ever seen */

            gboolean save_fragmented = pinfo->fragmented;
            pinfo->fragmented = TRUE;

            ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
            ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

            if (is_http_header(first_linelen, first_line)) {
                /* The start of a new packet that will need to be reassembled */

                new_msp = pdu_store(pinfo, ippusbd->multisegment_pdus, pinfo->num, FALSE, -1);
                new_msp->running_size = reported_length;

                fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), 0, reported_length, TRUE);
                ippusb_last_pdu = pinfo->num;
            }
            else {

                previous_msp = (struct ippusb_multisegment_pdu *)wmem_tree_lookup32_le(ippusbd->multisegment_pdus, ippusb_last_pdu);

                if (previous_msp) {
                    previous_msp->nxtpdu = pinfo->num;
                    new_msp = pdu_store(pinfo, ippusbd->multisegment_pdus, previous_msp->first_frame, previous_msp->is_chunked, previous_msp->http_ipp_split);
                    new_msp->running_size = previous_msp->running_size + reported_length;

                    if(last != TAG_END_OF_ATTRIBUTES) {
                        if(reported_length <= CHUNK_LENGTH_MAX){
                            /* This segment has the size of the next packet as a part
                             * of the  HTTP 1.1 chunked tranfer encoding */

                            new_msp->running_size -= reported_length;
                            new_msp->is_chunked = TRUE;

                            if(new_msp->http_ipp_split < 0){
                                new_msp->running_size += sizeof(CHUNKED_END);
                                new_msp->http_ipp_split = new_msp->running_size;

                                fragment_add_check(&ippusb_reassembly_table, chunked_end_tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, sizeof(CHUNKED_END), TRUE);
                            }
                            else {
                                return reported_length;
                            }
                        }
                        else {
                            if(new_msp->http_ipp_split >= 0) {
                                /* This segment contains part of the ipp information and the return and newline needs to be removed */

                                new_msp->running_size -= LENGTH_OF_RETURN_NEWLINE;
                                fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, reported_length - LENGTH_OF_RETURN_NEWLINE, TRUE);
                            }
                            else {
                                fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, reported_length, TRUE);
                            }
                        }


                        ippusb_last_pdu = pinfo->num;
                    }
                    else {
                        /* This segment contains the end of ipp information */

                        new_msp->finished = TRUE;

                        fragment_head *head = fragment_add_check(&ippusb_reassembly_table, tvb, offset, pinfo, new_msp->first_frame,
                                                            GUINT_TO_POINTER(new_msp->first_frame), previous_msp->running_size, reported_length, FALSE);
                        tvbuff_t *processedTvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                        new_msp->reassembled = TRUE;
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
            /* Not the first time this segment is seen */

            if (reported_length <= CHUNK_LENGTH_MAX) {
                return reported_length;
            }

            gboolean save_fragmented = pinfo->fragmented;
            pinfo->fragmented = TRUE;
            current_msp = (struct ippusb_multisegment_pdu *)wmem_tree_lookup32_le(ippusbd->multisegment_pdus, pinfo->num);

            if (current_msp && !current_msp->finished && current_msp->nxtpdu == 0) {
                /* This is a packet that was not completed with an IPP end-of-attributes tag and assembly will be attempted */

                ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
                ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);
                fragment_head * head;

                col_append_fstr(pinfo->cinfo, COL_INFO, "Reassembled Data with Error");

                if (!current_msp->reassembled) {
                    /* The first time this segment is passed over after the initial round
                     * it will be added to the pdu and reassembled */

                    pinfo->fd->visited = FALSE;

                    head = fragment_add_check(&ippusb_reassembly_table, tvb, 0, pinfo, current_msp->first_frame,
                                                            GUINT_TO_POINTER(current_msp->first_frame), current_msp->running_size - reported_length, reported_length, FALSE);
                    pinfo->fd->visited = TRUE;

                    current_msp->reassembled = TRUE;
                }
                else {
                    head = fragment_get_reassembled_id(&ippusb_reassembly_table, pinfo, current_msp->first_frame);
                }

                if (head) {
                    tvbuff_t *processed_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                    pinfo->can_desegment = 0;

                    if (current_msp->is_chunked && current_msp->http_ipp_split >= 0) {
                        /* The packet was chunked and the error occured after the http ipp split */

                        tvbuff_t *http_tvb = tvb_new_subset_length(processed_tvb, 0, current_msp->http_ipp_split);
                        tvbuff_t *ipp_tvb = tvb_new_subset_remaining(processed_tvb, current_msp->http_ipp_split);

                        dissector_try_uint_new(ippusb_dissector_table, HTTP, http_tvb, pinfo, tree, TRUE, data);
                        ret = dissector_try_uint_new(ippusb_dissector_table, IPP, ipp_tvb, pinfo, tree, TRUE, data);
                    }
                    else {
                        /* The packet was chunked and the error occured before the http ipp split
                         * or the packet was not chunked */

                        ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processed_tvb, pinfo, tree, TRUE, data);
                    }
                }
            }
            else if (current_msp && last == TAG_END_OF_ATTRIBUTES) {
                /* This is the last segment of the reassembled packet */

                ti = proto_tree_add_item(tree, proto_ippusb, tvb, offset, -1, 0);
                ippusb_tree = proto_item_add_subtree(ti, ett_ippusb);

                fragment_head * head = fragment_get_reassembled_id(&ippusb_reassembly_table, pinfo, current_msp->first_frame);

                tvbuff_t *processed_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPPUSB", head, &ippusb_frag_items, NULL, tree);

                pinfo->can_desegment = 0;

                if (current_msp->is_chunked) {
                    tvbuff_t *http_tvb = tvb_new_subset_length(processed_tvb, 0, current_msp->http_ipp_split);
                    tvbuff_t *ipp_tvb = tvb_new_subset_remaining(processed_tvb, current_msp->http_ipp_split);

                    dissector_try_uint_new(ippusb_dissector_table, HTTP, http_tvb, pinfo, tree, TRUE, data);
                    ret = dissector_try_uint_new(ippusb_dissector_table, IPP, ipp_tvb, pinfo, tree, TRUE, data);
                }
                else {
                    ret = dissector_try_uint_new(ippusb_dissector_table, HTTP, processed_tvb, pinfo, tree, TRUE, data);
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, "  Reassembled Data");

            }

            pinfo->fragmented = save_fragmented;
        }
    }

    if (ret) {
        return tvb_captured_length(tvb);
    }
    else {
        return 0;
    }
}

static gint
is_http_header(gint first_linelen, const guchar *first_line) {
    if ((first_linelen >= 5 && strncmp(first_line, "HTTP/", 5) == 0) ||
        (first_linelen >= 4 && strncmp(first_line, "POST", 4) == 0)) {

        return TRUE;
    }
    else {
        return FALSE;
    }
}

static void
ippusb_shutdown(void) {
    tvb_free(chunked_end_tvb);
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

    /* Register reassembly table. */
    reassembly_table_register(&ippusb_reassembly_table, &ippusb_reassembly_table_functions);

    /* Preferences */
     module_t *ippusb_module = prefs_register_protocol(proto_ippusb, NULL);

    /* Reassembly, made an option due to memory costs */
    prefs_register_bool_preference(ippusb_module, "attempt_reassembly", "Reassemble payload", "", &global_ippusb_reassemble);

    chunked_end_tvb = tvb_new_real_data(CHUNKED_END, sizeof(CHUNKED_END), sizeof(CHUNKED_END));

    register_shutdown_routine(ippusb_shutdown);
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