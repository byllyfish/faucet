"""Parse JSON for TFM based table config."""

# from faucet import valve_of
#
#
# class LoadRyuTables:
#     """Serialize table features messages from JSON."""
#     # pylint: disable=no-member
#
#     @staticmethod
#     def load_tables(dp): # pylint: disable=invalid-name
#         table_array = []
#         active_table_ids = sorted([valve_table.table_id for valve_table in dp.tables.values()])
#         for table_id in active_table_ids:
#             valve_table = dp.table_by_id(table_id)
#             table_attr = {
#                 'config': 3,
#                 'max_entries': valve_table.table_config.size,
#                 'metadata_match': 0,
#                 'metadata_write': 0,
#                 'name': valve_table.name.encode('utf-8'),
#                 'properties': [],
#                 'table_id': table_id,
#             }
#             new_table = valve_of.parser.OFPTableFeaturesStats(**table_attr)
#             # Match types
#             if valve_table.match_types:
#                 oxm_ids = [
#                     valve_of.parser.OFPOxmId(type_=match_type, hasmask=hasmask)
#                     for match_type, hasmask in list(valve_table.match_types.items())]
#                 new_table.properties.append(
#                     valve_of.parser.OFPTableFeaturePropOxm(
#                         oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_MATCH))
#                 # Not an exact match table, assume all fields wildcarded.
#                 if not valve_table.exact_match:
#                     new_table.properties.append(
#                         valve_of.parser.OFPTableFeaturePropOxm(
#                             oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_WILDCARDS))
#             # Next tables
#             next_tables = [
#                 table_id for table_id in active_table_ids if table_id > new_table.table_id]
#             if next_tables:
#                 new_table.properties.append(
#                     valve_of.parser.OFPTableFeaturePropNextTables(
#                         table_ids=next_tables, type_=valve_of.ofp.OFPTFPT_NEXT_TABLES))
#             # Instructions
#             insts = set([valve_of.ofp.OFPIT_APPLY_ACTIONS])
#             if next_tables:
#                 insts.add(valve_of.ofp.OFPIT_GOTO_TABLE)
#             if valve_table.table_config.meter:
#                 insts.add(valve_of.ofp.OFPIT_METER)
#             inst_ids = [
#                 valve_of.parser.OFPInstructionId(type_) for type_ in insts]
#             new_table.properties.append(
#                 valve_of.parser.OFPTableFeaturePropInstructions(
#                     type_=valve_of.ofp.OFPTFPT_INSTRUCTIONS, instruction_ids=inst_ids))
#             apply_actions = set()
#             # Set fields and apply actions
#             if valve_table.set_fields:
#                 apply_actions.add(valve_of.ofp.OFPAT_SET_FIELD)
#                 # TODO: only select push_vlan when VLAN VID in set_fields.
#                 apply_actions.add(valve_of.ofp.OFPAT_PUSH_VLAN)
#                 oxm_ids = [
#                     valve_of.parser.OFPOxmId(type_=field, hasmask=False)
#                     for field in valve_table.set_fields]
#                 new_table.properties.append(
#                     valve_of.parser.OFPTableFeaturePropOxm(
#                         oxm_ids=oxm_ids, type_=valve_of.ofp.OFPTFPT_APPLY_SETFIELD))
#             if valve_table.table_config.output:
#                 apply_actions.add(valve_of.ofp.OFPAT_OUTPUT)
#                 apply_actions.add(valve_of.ofp.OFPAT_POP_VLAN)
#                 if dp.group_table or dp.group_table_routing:
#                     apply_actions.add(valve_of.ofp.OFPAT_GROUP)
#             if apply_actions:
#                 action_ids = [
#                     valve_of.parser.OFPActionId(type_) for type_ in apply_actions]
#                 new_table.properties.append(
#                     valve_of.parser.OFPTableFeaturePropActions(
#                         type_=valve_of.ofp.OFPTFPT_APPLY_ACTIONS, action_ids=action_ids))
#             # Miss goto table option.
#             if valve_table.table_config.miss_goto:
#                 miss_table_id = dp.tables[valve_table.table_config.miss_goto].table_id
#                 new_table.properties.append(
#                     valve_of.parser.OFPTableFeaturePropNextTables(
#                         table_ids=[miss_table_id], type_=valve_of.ofp.OFPTFPT_NEXT_TABLES_MISS))
#                 inst_ids = [valve_of.parser.OFPInstructionId(valve_of.ofp.OFPIT_GOTO_TABLE)]
#                 new_table.properties.append(
#                     valve_of.parser.OFPTableFeaturePropInstructions(
#                         type_=valve_of.ofp.OFPTFPT_INSTRUCTIONS_MISS, instruction_ids=inst_ids))
#
#             table_array.append(new_table)
#         return table_array


class LoadZofTables:
    """Serialize table features message."""

    @staticmethod
    def load_tables(dp): # pylint: disable=invalid-name
        """Return table features message with active table_id's only."""
        table_array = []
        active_table_ids = sorted([valve_table.table_id for valve_table in dp.tables.values()])
        for table_id in active_table_ids:
            valve_table = dp.table_by_id(table_id)
            new_table = {
                'config': ['0x03'],
                'max_entries': valve_table.table_config.size,
                'metadata_match': 0,
                'metadata_write': 0,
                'name': valve_table.name,
                'table_id': table_id,
                'write_actions': [],
                'write_set_field': [],
                'apply_set_field': [],
                'wildcards': [],
            }
            # Match types
            if valve_table.match_types:
                oxm_ids = [_oxmid(match_type, hasmask) for match_type, hasmask
                           in valve_table.match_types.items()]
                new_table['match'] = oxm_ids
                # Not an exact match table, assume all fields wildcarded.
                if not valve_table.exact_match:
                    new_table['wildcards'] = oxm_ids
            # Next tables
            next_tables = [tid for tid in active_table_ids if tid > table_id]
            new_table['next_tables'] = next_tables
            # Instructions
            insts = ['APPLY_ACTIONS']
            if next_tables:
                insts.append('GOTO_TABLE')
            if valve_table.table_config.meter:
                insts.append('METER')
            new_table['instructions'] = insts
            apply_actions = []
            # Set fields and apply actions
            if valve_table.set_fields:
                oxm_ids = [_oxmid(field) for field in valve_table.set_fields]
                new_table['apply_set_field'] = oxm_ids
                apply_actions.append('SET_FIELD')
                if 'VLAN_VID' in oxm_ids:
                    apply_actions.append('PUSH_VLAN')
            if valve_table.table_config.output:
                apply_actions.append('OUTPUT')
                apply_actions.append('POP_VLAN')
                if dp.group_table or dp.group_table_routing:
                    apply_actions.append('GROUP')
            new_table['apply_actions'] = apply_actions
            # Miss goto table option.
            if valve_table.table_config.miss_goto:
                miss_table_id = dp.tables[valve_table.table_config.miss_goto].table_id
                new_table['next_tables_miss'] = [miss_table_id]
                new_table['instructions_miss'] = ['GOTO_TABLE']

            table_array.append(new_table)
        return table_array


def _oxmid(match_type, hasmask=False):
    """Convert to zof OXM ID format (where appended slash indicates mask)."""
    if hasmask:
        return '%s/' % match_type.upper()
    return match_type.upper()
