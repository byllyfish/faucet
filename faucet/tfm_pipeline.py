"""Configure switch tables with TFM messages."""


def load_tables(dp, valve_cl): # pylint: disable=invalid-name
    """Configure switch tables with TFM messages."""
    table_array = []
    active_table_ids = sorted([valve_table.table_id for valve_table in dp.tables.values()])
    for table_id in active_table_ids:
        valve_table = dp.table_by_id(table_id)
        new_table = {
            'config': ['0x03'],
            'max_entries': valve_table.table_config.size,
            'metadata_match': valve_table.metadata_match,
            'metadata_write': valve_table.metadata_write,
            'name': valve_table.name,
            'table_id': table_id,
            'write_actions': [],
            'write_set_field': [],
            'apply_set_field': [],
            'wildcards': [],
            'next_tables': [],
        }
        # Match types
        if valve_table.match_types:
            oxm_ids = [_oxmid(match_type, hasmask) for match_type, hasmask
                       in valve_table.match_types.items()]
            new_table['match'] = oxm_ids
            # Not an exact match table, assume all fields wildcarded.
            if not valve_table.exact_match:
                new_table['wildcards'] = oxm_ids
        insts = ['APPLY_ACTIONS']
        # Next tables
        if valve_table.next_tables:
            new_table['next_tables'] = valve_table.next_tables
            insts.append('GOTO_TABLE')
        # Instructions
        if valve_table.table_config.meter:
            insts.append('METER')
        new_table['instructions'] = insts
        apply_actions = []
        if valve_table.table_config.dec_ttl and valve_cl.DEC_TTL:
            apply_actions.append('DEC_NW_TTL')
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
            if valve_cl.GROUPS:
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
