"""Translate Table Features Message RYU JSON syntax to OFTR syntax."""

# Convert to canonical YAML:
#
#   python ryu2yaml.py ../../etc/faucet/aruba_pipeline.json | oftr encode --roundtrip

import sys
import json


_ALL_PROPS = ['match', 'wildcards', 'instructions', 'write_actions',
              'apply_actions', 'write_set_field', 'apply_set_field',
              'next_tables']


def translate_property(tfm, prop):
    """Translate TFM property and store in `tfm`."""

    xlate = _TRANSLATE[prop['name']]
    tfm[xlate[0]] = xlate[1](prop[xlate[2]])


def translate_match(oxm_ids):
    """Translate oxm_ids to yaml format."""

    return [translate_oxm(oxm) for oxm in oxm_ids]


def translate_oxm(oxm_id):
    """Translate one oxm_id to yaml format."""

    mask = '/' if oxm_id.get('hasmask') else ''
    name = oxm_id['name'].upper()
    return '%s%s' % (name, mask)


def translate_instructions(instr_ids):
    """Translate instructions to yaml format."""

    return [translate_instr(instr) for instr in instr_ids]


def translate_instr(instr_id):
    """Translate one instruction to yaml format."""

    name = instr_id['name']
    assert name.startswith('OFPIT_')
    return name[6:]


def translate_actions(action_ids):
    """Translate actions to yaml format."""

    return [translate_action(action) for action in action_ids]


def translate_action(action_id):
    """Translate one action to yaml format."""

    name = action_id['name']
    assert name.startswith('OFPAT_')
    return name[6:]


def translate_tables(table_ids):
    """Translate tables to yaml format (identity function)."""

    return table_ids


_TRANSLATE = {
    'OFPTFPT_MATCH': ('match', translate_match, 'oxm_ids'),
    'OFPTFPT_WILDCARDS': ('wildcards', translate_match, 'oxm_ids'),
    'OFPTFPT_INSTRUCTIONS': ('instructions', translate_instructions, 'instruction_ids'),
    'OFPTFPT_INSTRUCTIONS_MISS': ('instructions_miss', translate_instructions, 'instruction_ids'),
    'OFPTFPT_WRITE_ACTIONS': ('write_actions', translate_actions, 'action_ids'),
    'OFPTFPT_WRITE_ACTIONS_MISS': ('write_actions_miss', translate_actions, 'action_ids'),
    'OFPTFPT_APPLY_ACTIONS': ('apply_actions', translate_actions, 'action_ids'),
    'OFPTFPT_APPLY_ACTIONS_MISS': ('apply_actions_miss', translate_actions, 'action_ids'),
    'OFPTFPT_WRITE_SETFIELD': ('write_set_field', translate_match, 'oxm_ids'),
    'OFPTFPT_WRITE_SETFIELD_MISS': ('write_set_field_miss', translate_match, 'oxm_ids'),
    'OFPTFPT_APPLY_SETFIELD': ('apply_set_field', translate_match, 'oxm_ids'),
    'OFPTFPT_APPLY_SETFIELD_MISS': ('apply_set_field_miss', translate_match, 'oxm_ids'),
    'OFPTFPT_NEXT_TABLES': ('next_tables', translate_tables, 'table_ids'),
    'OFPTFPT_NEXT_TABLES_MISS': ('next_tables_miss', translate_tables, 'table_ids')
}


def default_missing_properties(tfm):
    """Set any missing properties to []."""

    for prop in _ALL_PROPS:
        if prop not in tfm:
            tfm[prop] = []


def main(filename):
    """Load Table Features Message body from JSON file."""

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
