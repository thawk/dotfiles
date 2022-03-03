#!/usr/bin/env python
# vim: set fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4 softtabstop=4:
import logging
import os
import sys
import json
import yaml

TRIGGER_KEY = "spacebar"

def gen_simultaneous_key(cond_name, trigger_key, from_key, to_key):
    return {
        "type": "basic",
        "from": {
            "modifiers": {
                "optional": [
                    "any"
                ]
            },
            "simultaneous": [
                {
                    "key_code": trigger_key
                },
                {
                    "key_code": from_key 
                }
            ],
            "simultaneous_options": {
                "key_down_order": "strict",
                "key_up_order": "strict_inverse",
                "to_after_key_up": [
                    {
                        "set_variable": {
                            "name": cond_name,
                            "value": 0
                        }
                    }
                ]
            }
        },
        "to": [
            {
                "set_variable": {
                    "name": cond_name,
                    "value": 1
                }
            },
            {
                "key_code": to_key
            }
        ],
    }

def gen_single_key(cond_name, from_key, to_key):
    return {
        "type": "basic",
        "conditions": [
            {
                "name": cond_name,
                "type": "variable_if",
                "value": 1
            }
        ],
        "from": {
            "key_code": from_key,
            "modifiers": {
                "optional": [
                    "any"
                ]
            }
        },
        "to": [
            {
                "key_code": to_key
            }
        ],
    }


def gen_rule(rule, cond_name):
    manipulators = []

    for (from_key, to_key) in rule["keys"].items():
        manipulators.append(gen_simultaneous_key(
            cond_name, TRIGGER_KEY, from_key, to_key))
        manipulators.append(gen_single_key(
            cond_name, from_key, to_key))

    return {
        "description" : rule["description"],
        "manipulators" : manipulators,
    }

def gen_rules(rules, cond_name):
    return [gen_rule(rule, cond_name) for rule in rules]

def gen_function_keys():
    return [
        {
            "from": {
                "key_code": "f1"
            },
            "to": {
                "consumer_key_code": "display_brightness_decrement"
            }
        },
        {
            "from": {
                "key_code": "f2"
            },
            "to": {
                "consumer_key_code": "display_brightness_increment"
            }
        },
        {
            "from": {
                "key_code": "f3"
            },
            "to": {
                "key_code": "mission_control"
            }
        },
        {
            "from": {
                "key_code": "f4"
            },
            "to": {
                "key_code": "launchpad"
            }
        },
        {
            "from": {
                "key_code": "f5"
            },
            "to": {
                "key_code": "illumination_decrement"
            }
        },
        {
            "from": {
                "key_code": "f6"
            },
            "to": {
                "key_code": "illumination_increment"
            }
        },
        {
            "from": {
                "key_code": "f7"
            },
            "to": {
                "consumer_key_code": "rewind"
            }
        },
        {
            "from": {
                "key_code": "f8"
            },
            "to": {
                "consumer_key_code": "play_or_pause"
            }
        },
        {
            "from": {
                "key_code": "f9"
            },
            "to": {
                "consumer_key_code": "fastforward"
            }
        },
        {
            "from": {
                "key_code": "f10"
            },
            "to": {
                "consumer_key_code": "mute"
            }
        },
        {
            "from": {
                "key_code": "f11"
            },
            "to": {
                "consumer_key_code": "volume_decrement"
            }
        },
        {
            "from": {
                "key_code": "f12"
            },
            "to": {
                "consumer_key_code": "volume_increment"
            }
        }
    ]

def gen_profile(profile_name, rules):
    profile =  {
        "complex_modifications": {
            "parameters": {
                "basic.simultaneous_threshold_milliseconds": 200,
                "basic.to_delayed_action_delay_milliseconds": 500,
                "basic.to_if_alone_timeout_milliseconds": 1000,
                "basic.to_if_held_down_threshold_milliseconds": 500
            },
            "rules" : gen_rules(rules, profile_name),
        },
        "devices": [],
        "fn_function_keys": gen_function_keys(),
        "name": profile_name,
        "selected": False,
        "simple_modifications": [],
        "virtual_hid_keyboard": {
            "country_code": 0
        }
    }

    return profile

def load_cfg(cfg_file):
    with open(cfg_file, 'r') as f:
        cfg = yaml.safe_load(f)

    return cfg['profile_name'], cfg['rules']

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("need to specify the YAML config file")
        exit(1)

    profile_name, rules = load_cfg(sys.argv[1])

    print(json.dumps(
        gen_profile(profile_name, rules),
        indent=2
    ))
