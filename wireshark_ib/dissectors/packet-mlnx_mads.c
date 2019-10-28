/* packet-mlnx_mads.c
 * Routines for Mellanox vendor-specific MAD dissection
 * Copyright 2009, Mellanox Technology Limited
 * Created by Slava Koyfman, slavak@mellanox.co.il
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

/* Forward declaration we need below */
void proto_reg_handoff_mlnx_mads(void);

/* definitions for protocol and registered fields */
static int proto_mlnx_mads = -1;

/* general info MAD */
static int subtree_generalinfo_hw = -1;
static int subtree_generalinfo_fw = -1;
static int subtree_generalinfo_sw = -1;

static int hf_mlnx_mads_gi_hw_rev = -1;
static int hf_mlnx_mads_gi_hw_devid = -1;
static int hf_mlnx_mads_gi_hw_uptime = -1;

static int hf_mlnx_mads_gi_fw_major = -1;
static int hf_mlnx_mads_gi_fw_minor = -1;
static int hf_mlnx_mads_gi_fw_subminor = -1;
static int hf_mlnx_mads_gi_fw_build = -1;
static int hf_mlnx_mads_gi_fw_month = -1;
static int hf_mlnx_mads_gi_fw_day = -1;
static int hf_mlnx_mads_gi_fw_year = -1;
static int hf_mlnx_mads_gi_fw_hour = -1;
static int hf_mlnx_mads_gi_fw_psid = -1;
static int hf_mlnx_mads_gi_fw_ini_ver = -1;
static int hf_mlnx_mads_gi_fw_ext_major = -1;
static int hf_mlnx_mads_gi_fw_ext_minor = -1;
static int hf_mlnx_mads_gi_fw_ext_subminor = -1;

static int hf_mlnx_mads_gi_sw_major = -1;
static int hf_mlnx_mads_gi_sw_minor = -1;
static int hf_mlnx_mads_gi_sw_subminor = -1;

/* subtree pointers */
static gint ett_mlnx_mads = -1;
static gint ett_generalinfo_hw = -1;
static gint ett_generalinfo_fw = -1;
static gint ett_generalinfo_sw = -1;

#define MLNX_MNGMT_CLASS    0x0A    /* Mellanox vendor-specific management class value */
#define MAD_INFO_TEST       "Mellanox VS MAD"   /* this will identify the protocol in the info column */

/* necessary forward declarations for all of the specific packet parsers */
static void parse_generalinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *head, gint *offset);

/* Code to actually dissect the packets */
static void
dissect_mlnx_mads(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *mlnx_mads_tree;

    gint offset = 0;    /* current offset in payload */

    /* important fields in the common MAD header */
    guint8 base_version, mgmt_class, class_version;
    guint16 mngmt_attr;

    /* general variables */
    /* ... */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_mlnx_mads, tvb, 0, -1, FALSE);
    mlnx_mads_tree = proto_item_add_subtree(ti, ett_mlnx_mads);

    /* do some basic heuristic checks to make sure this is a valid Mellanox MAD */

	/* Check legal payload size of MAD */
	if (tvb_length(tvb) != 256) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Illegal packet length");
        return;
    }

	base_version = tvb_get_guint8(tvb, offset++);
    mgmt_class = tvb_get_guint8(tvb, offset++);
    class_version = tvb_get_guint8(tvb, offset++);
	if (base_version != 1 ||                    /* IB spec defines this MUST be 1 */
        mgmt_class != MLNX_MNGMT_CLASS ||       /* Mellanox vendor class  */
        class_version != 1) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Illegal header field");
            return;
    }

    offset = 0x00020; /* move offset to point to start of payload */

    mngmt_attr = tvb_get_ntohs(tvb, 16);    /* extract management attribute from MAD header */
    switch (mngmt_attr) {   /* decide what kind of MAD this is based on the management attribute */
        case 0x0001:
            /* ClassPortInfo */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0011:
            /* PortPowerState */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0012:
            /* DeviceSoftReset */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0013:
            /* ExtPortAccess */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0014:
            /* PhyConfig */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0015:
            /* MFT */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0017:
            parse_generalinfo(tvb, pinfo, mlnx_mads_tree, ti, &offset);
            break;
        case 0x0050:
            /* ConfigSpaceAccess */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0060:
            /* PortRcvDataVL */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0061:
            /* PortXmitDataVL */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0062:
            /* PortRcvPktsVL */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0063:
            /* PortXmitPktsVL */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0090:
            /* CounterGroupInfo */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x0091:
            /* ConfigCounterGroup */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        case 0x00A0:
            /* EnhancedConfigSpaceAccess */
            expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_WARN, "Feature not implemented");
            break;
        default:
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Illegal management attribute");
            return;   /* this is not a valid Mellanox MAD */
    }

    return;

}


static void
parse_generalinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *head, gint *offset) {
    proto_item *hw_item, *fw_item, *sw_item;
    proto_tree *hw_subtree, *fw_subtree, *sw_subtree;
    gint local_offset = *offset;

    col_set_str(pinfo->cinfo, COL_INFO, MAD_INFO_TEST " (GeneralInfo)");

    proto_item_append_text(head, " (GeneralInfo)");

    if (!tree)
        return; /* operational dissection. do no in-depth parsing */

    /* create subtrees */
    hw_item = proto_tree_add_item(tree, subtree_generalinfo_hw, tvb, 0x0, 0x20, FALSE);
    hw_subtree = proto_item_add_subtree(hw_item, ett_generalinfo_hw);
    fw_item = proto_tree_add_item(tree, subtree_generalinfo_fw, tvb, 0x21, 0x40, FALSE);
    fw_subtree = proto_item_add_subtree(fw_item, ett_generalinfo_fw);
    sw_item = proto_tree_add_item(tree, subtree_generalinfo_sw, tvb, 0x61, 0x20, FALSE);
    sw_subtree = proto_item_add_subtree(sw_item, ett_generalinfo_sw);

    /* now we start adding the packet items to the tree */

    proto_tree_add_item(hw_subtree, hf_mlnx_mads_gi_hw_rev, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(hw_subtree, hf_mlnx_mads_gi_hw_devid, tvb, local_offset, 2, FALSE); local_offset += 2;
    local_offset += 0x18;   /* skip reserved field */
    proto_tree_add_item(hw_subtree, hf_mlnx_mads_gi_hw_uptime, tvb, local_offset, 4, FALSE); local_offset += 4;

    local_offset += 1;   /* skip reserved field */
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_major, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_minor, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_subminor, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_build, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_month, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_day, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_year, tvb, local_offset, 2, FALSE); local_offset += 2;
    local_offset += 2;   /* skip reserved field */
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_hour, tvb, local_offset, 2, FALSE); local_offset += 2;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_psid, tvb, local_offset, 0x10, FALSE); local_offset += 0x10;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_ini_ver, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_ext_major, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_ext_minor, tvb, local_offset, 4, FALSE); local_offset += 4;
    proto_tree_add_item(fw_subtree, hf_mlnx_mads_gi_fw_ext_subminor, tvb, local_offset, 4, FALSE); local_offset += 4;

    local_offset += 1;   /* skip reserved field */
    proto_tree_add_item(sw_subtree, hf_mlnx_mads_gi_sw_major, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(sw_subtree, hf_mlnx_mads_gi_sw_minor, tvb, local_offset, 1, FALSE); local_offset += 1;
    proto_tree_add_item(sw_subtree, hf_mlnx_mads_gi_sw_subminor, tvb, local_offset, 1, FALSE); local_offset += 1;

    *offset = local_offset;
}


void
proto_register_mlnx_mads(void)
{
    static const value_string hw_rev_strings[] = {
		{ 0x00A0, "MT47396 InfiniScale IV device step A0, FCC package" },
		{ 0x00A1, "MT47396 InfiniScale IV device step A1, FCC package" },
        { 0x01A1, "MT47396 InfiniScale IV device step A1, FDC package" },
		{ 0,       NULL }
	};
    static const value_string hw_devid_strings[] = {
		{ 0xB924, "Infiniscale IV" },
		{ 0,       NULL }
	};

    /* Setup list of header fields */
	static hf_register_info hf[] = {
        /* fields for GeneralInfo MAD */
        { &subtree_generalinfo_hw,
			{ "HW Info",           "mlnx_mads.hw",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Hardware information", HFILL }
		},
        { &subtree_generalinfo_fw,
			{ "FW Info",           "mlnx_mads.fw",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Firmware information", HFILL }
		},
        { &subtree_generalinfo_sw,
			{ "SW Info",           "mlnx_mads.sw",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Software information", HFILL }
		},
        { &hf_mlnx_mads_gi_hw_rev,
			{ "Revision",           "mlnx_mads.hw.rev",
			FT_UINT16, BASE_HEX, VALS(hw_rev_strings), 0x0,
			"Device HW Revision", HFILL }
		},
        { &hf_mlnx_mads_gi_hw_devid,
			{ "Device ID",           "mlnx_mads.hw.dev_id",
			FT_UINT16, BASE_HEX, VALS(hw_devid_strings), 0x0,
			"Device ID", HFILL }
		},
        { &hf_mlnx_mads_gi_hw_uptime,
			{ "Uptime",           "mlnx_mads.hw.uptime",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Time (in seconds) since last reset", HFILL }
		},
		{ &hf_mlnx_mads_gi_fw_major,
			{ "Major Version",           "mlnx_mads.fw.major",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Major firmware version number", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_minor,
			{ "Minor Version",           "mlnx_mads.fw.minor",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Minor firmware version number", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_subminor,
			{ "SubMinor Version",           "mlnx_mads.fw.subminor",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"SubMinor firmware version number", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_build,
			{ "Build ID",           "mlnx_mads.fw.build_id",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Firmware Build ID", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_month,
			{ "Month",           "mlnx_mads.fw.month",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"FW installation month", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_day,
			{ "Day",           "mlnx_mads.fw.day",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"FW installation day", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_year,
			{ "Year",           "mlnx_mads.fw.year",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"FW installation year", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_hour,
			{ "Hour",           "mlnx_mads.fw.hour",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"FW installation time", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_psid,
			{ "PSID",           "mlnx_mads.fw.psid",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"INI file identifier (PSID)", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_ini_ver,
			{ "INI Version",           "mlnx_mads.fw.ini_ver",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"INI file identifier (PSID)", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_ext_major,
			{ "Extended Major Version",           "mlnx_mads.fw.ext_major",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Major firmware version number in extended format", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_ext_minor,
			{ "Extended Minor Version",           "mlnx_mads.fw.ext_minor",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Minor firmware version number in extended format", HFILL }
		},
        { &hf_mlnx_mads_gi_fw_ext_subminor,
			{ "Extended SubMinor Version",           "mlnx_mads.fw.ext_subminor",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"SubMinor firmware version number in extended format", HFILL }
		},
        { &hf_mlnx_mads_gi_sw_major,
			{ "Major Version",           "mlnx_mads.sw.major",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Major Driver version number", HFILL }
		},
        { &hf_mlnx_mads_gi_sw_minor,
			{ "Minor Version",           "mlnx_mads.sw.minor",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Minor Driver version number", HFILL }
		},
        { &hf_mlnx_mads_gi_sw_subminor,
			{ "SubMinor Version",           "mlnx_mads.sw.subminor",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"SubMinor Driver version number", HFILL }
		}
	};

    /* Setup protocol subtree array */
	static gint *ett[] = {
        &ett_mlnx_mads,
        &ett_generalinfo_hw,
        &ett_generalinfo_fw,
        &ett_generalinfo_sw
	};

    /* Register the protocol name and description */
	proto_mlnx_mads = proto_register_protocol("Mellanox VS MAD",
	    "MLNX MADs", "mlnx_mads");

    /* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mlnx_mads, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_mlnx_mads(void)
{
	dissector_handle_t mlnx_mads_handle;

	mlnx_mads_handle = create_dissector_handle(dissect_mlnx_mads,
							 proto_mlnx_mads);
	dissector_add("infiniband.mad.vendor", MLNX_MNGMT_CLASS, mlnx_mads_handle);
}



