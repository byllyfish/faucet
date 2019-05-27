"""Configure switch tables with TFM messages."""

#from faucet import valve_of

REQUIRED_PROPERTIES = set([
    'write_actions',
    'write_actions_miss',
    'apply_actions',
    'apply_actions_miss',
    'write_setfield',
    'write_setfield_miss',
    'match',
    'wildcards',
    'apply_setfield_miss',
    'apply_setfield',
    'next_tables',
    'next_tables_miss',
    'apply_setfield',
    'instructions',
    'instructions_miss'])


def fill_required_properties(new_table):
    """Ensure TFM has all required properties."""
    configured_props = {prop for prop in new_table}
    missing_props = REQUIRED_PROPERTIES - configured_props
    for prop in missing_props:
        new_table[prop] = None


def init_table(table_id, name, max_entries, metadata_match, metadata_write):
    """Initialize a TFM."""
    if not metadata_match:
        metadata_match = 0
    if not metadata_write:
        metadata_write = 0
    table_attr = {
        'config': ['0x03'],
        'max_entries': max_entries,
        'metadata_match': metadata_match,
        'metadata_write': metadata_write,
        'name': name,
        'table_id': table_id,
    }
    return table_attr


# pylint: disable=invalid-name
# pylint: disable=too-many-arguments
# pylint: disable=too-many-locals
def load_tables(dp, valve_cl, max_table_id, min_max_flows, use_oxm_ids, fill_req):
    """Configure switch tables with TFM messages."""
    table_array = []
    active_table_ids = sorted([valve_table.table_id for valve_table in dp.tables.values()])
    for table_id in active_table_ids:
        valve_table = dp.table_by_id(table_id)
        max_entries = max(min_max_flows, valve_table.table_config.size)
        new_table = init_table(
            table_id, valve_table.name, max_entries,
            valve_table.metadata_match, valve_table.metadata_write)
        # Match types
        if valve_table.match_types:
            oxm_ids = []
            if use_oxm_ids:
                oxm_ids = [
                    _oxmid(match_type, hasmask) 
                    for match_type, hasmask in valve_table.match_types.items()]
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
            apply_actions.append('SET_FIELD')
            if 'vlan_vid' in valve_table.set_fields:
                apply_actions.append('PUSH_VLAN')
            oxm_ids = []
            if use_oxm_ids:
                oxm_ids = [_oxmid(field) for field in valve_table.set_fields]
            new_table['apply_set_field'] = oxm_ids
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
        if fill_req:
            fill_required_properties(new_table)
        table_array.append(new_table)

    tfm_table_ids = {table.table_id for table in table_array}
    for missing_table_id in set(range(max_table_id+1)) - tfm_table_ids:
        new_table = init_table(
            missing_table_id, str(missing_table_id), min_max_flows, 0, 0)
        if fill_req:
            fill_required_properties(new_table)
        table_array.append(new_table)

    return table_array


def _oxmid(match_type, hasmask=False):
    """Convert to zof OXM ID format (where appended slash indicates mask)."""
    if hasmask:
        return '%s/' % match_type.upper()
    return match_type.upper()
