# Translate Table Features Message RYU JSON syntax to OFTR syntax.
#
# Convert to canonical YAML:
#
#   python ryu2yaml.py ../../etc/ryu/faucet/aruba_pipeline.json | oftr encode --roundtrip

import sys
import json


_ALL_PROPS = ['match', 'wildcards', 'instructions', 'write_actions', 
              'apply_actions', 'write_set_field', 'apply_set_field', 
              'next_tables']


def translate_property(tfm, prop):
    name = prop['name']
    if name == 'OFPTFPT_MATCH':
        tfm['match'] = translate_match(prop['oxm_ids'])
    elif name == 'OFPTFPT_WILDCARDS':
        tfm['wildcards'] = translate_match(prop['oxm_ids'])
    elif name == 'OFPTFPT_INSTRUCTIONS':
        tfm['instructions'] = translate_instructions(prop['instruction_ids'])
    elif name == 'OFPTFPT_INSTRUCTIONS_MISS':
        tfm['instructions_miss'] = translate_instructions(prop['instruction_ids'])
    elif name == 'OFPTFPT_WRITE_ACTIONS':
        tfm['write_actions'] = translate_actions(prop['action_ids'])
    elif name == 'OFPTFPT_WRITE_ACTIONS_MISS':
        tfm['write_actions_miss'] = translate_actions(prop['action_ids'])
    elif name == 'OFPTFPT_APPLY_ACTIONS':
        tfm['apply_actions'] = translate_actions(prop['action_ids'])
    elif name == 'OFPTFPT_APPLY_ACTIONS_MISS':
        tfm['apply_actions_miss'] = translate_actions(prop['action_ids'])
    elif name == 'OFPTFPT_WRITE_SETFIELD':
        tfm['write_set_field'] = translate_match(prop['oxm_ids'])
    elif name == 'OFPTFPT_WRITE_SETFIELD_MISS':
        tfm['write_set_field_miss'] = translate_match(prop['oxm_ids'])
    elif name == 'OFPTFPT_APPLY_SETFIELD':
        tfm['apply_set_field'] = translate_match(prop['oxm_ids'])
    elif name == 'OFPTFPT_APPLY_SETFIELD_MISS':
        tfm['apply_set_field_miss'] = translate_match(prop['oxm_ids'])
    elif name == 'OFPTFPT_NEXT_TABLES':
        tfm['next_tables'] = prop['table_ids']
    elif name == 'OFPTFPT_NEXT_TABLES_MISS':
        tfm['next_tables_miss'] = prop['table_ids']
    else:
        raise ValueError('Unknown property: %s' % name)


def translate_match(oxm_ids):
    return [translate_oxm(oxm) for oxm in oxm_ids]


def translate_oxm(oxm_id):
    mask = '/' if oxm_id.get('hasmask') else ''
    name = oxm_id['name'].upper()
    return '%s%s' % (name, mask)


def translate_instructions(instr_ids):
    return [translate_instr(instr) for instr in instr_ids]


def translate_instr(instr_id):
    name = instr_id['name']
    assert name.startswith('OFPIT_')
    return name[6:]


def translate_actions(action_ids):
    return [translate_action(action) for action in action_ids]


def translate_action(action_id):
    name = action_id['name']
    assert name.startswith('OFPAT_')
    return name[6:]


def default_missing_properties(tfm):
    # Set any missing properties to [].
    for prop in _ALL_PROPS:
        if prop not in tfm:
            tfm[prop] = []


def main(filename):
    # Load Table Features Message body from JSON file.
    tfm_body = json.load(filename)

    for tfm in tfm_body:
        # Config needs to be in a list.
        tfm['config'] = [hex(tfm['config'])]
        for prop in tfm['properties']:
            translate_property(tfm, prop)
        default_missing_properties(tfm)
        tfm['properties'] = []

    msg = { 
        'type': 'REQUEST.TABLE_FEATURES', 
        'version': 4,
        'msg': tfm_body 
    }
    print(json.dumps(msg, indent=2))


if __name__ == '__main__':
    main(open(sys.argv[1]))

