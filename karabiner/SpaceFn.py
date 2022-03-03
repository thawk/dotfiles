#!/usr/bin/env python
# vim: set fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4 softtabstop=4:
import logging
import os
import sys
import json

PROFILE_NAME = "SpaceFN"
COND_NAME = "SpaceFN"
TRIGGER_KEY = "spacebar"

rules = [
    {
        "description": "SpaceFN: Space+b to Space",
        "keys": (
            ("b", "spacebar"),
        )
    },
    {
        "description": "SpaceFN: Space+[hjkl] to Left, Down, Up, Right",
        "keys": (
            ("h", "left_arrow"),
            ("j", "down_arrow"),
            ("k", "up_arrow"),
            ("l", "right_arrow"),
        )
    },
    {
        "description": "SpaceFN: Space+i to Page Up, Space+u to Page Down",
        "keys": (
            ("i", "page_up"),
            ("u", "page_down"),
        )
    },
    {
        "description": "SpaceFN: Space+y to Home, Space+o to End",
        "keys": (
            ("y", "home"),
            ("o", "end"),
        )
    },
    {
        "description": "SpaceFN: Space+Backquote (`) to Escape, Space+[1-9] to F[1-9], Space+0 to F10, Space+Hyphen (-) to F11, Space+Equal Sign (=) to F12, Space+Slash to BackSlash",
        "keys": (
            ("grave_accent_and_tilde", "escape"),
            #  ("grave_accent_and_tilde", "grave_accent_and_tilde"),
            ("slash", "backslash"),
            ("1", "f1"),
            ("2", "f2"),
            ("3", "f3"),
            ("4", "f4"),
            ("5", "f5"),
            ("6", "f6"),
            ("7", "f7"),
            ("8", "f8"),
            ("9", "f9"),
            ("0", "f10"),
            ("hyphen", "f11"),
            ("equal_sign", "f12"),
        )
    },
    {
        "description": "SpaceFN: Space+p to Print Screen, Space+Open Bracket ([) to Scroll Lock, Space+Close Bracket (]) to Pause, Space+Backspace to Forward Delete, Space+Backslash (\\) to Insert",
        "keys": (
            ("p", "print_screen"),
            ("open_bracket", "scroll_lock"),
            ("close_bracket", "pause"),
            ("backslash", "insert"),
            ("delete_or_backspace", "delete_forward"),
        )
    },
]

def gen_simultaneous_key(cond_name, trigger_key, from_key, to_key):
    return {
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
        "type": "basic"
    }

def gen_single_key(cond_name, from_key, to_key):
    return {
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
        "type": "basic"
    }


def gen_rule(rule):
    manipulators = []

    for (from_key, to_key) in rule["keys"]:
        manipulators.append(gen_simultaneous_key(
            COND_NAME, TRIGGER_KEY, from_key, to_key))
        manipulators.append(gen_single_key(
            COND_NAME, from_key, to_key))

    return {
        "description" : rule["description"],
        "manipulators" : manipulators,
    }

def gen_rules(rules):
    return [gen_rule(rule) for rule in rules]

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

def gen_profile(name, rules):
    profile =  {
        "complex_modifications": {
            "parameters": {
                "basic.simultaneous_threshold_milliseconds": 200,
                "basic.to_delayed_action_delay_milliseconds": 500,
                "basic.to_if_alone_timeout_milliseconds": 1000,
                "basic.to_if_held_down_threshold_milliseconds": 500
            },
            "rules" : gen_rules(rules),
        },
        "devices": [],
        "fn_function_keys": gen_function_keys(),
        "name": name,
        "selected": False,
        "simple_modifications": [],
        "virtual_hid_keyboard": {
            "country_code": 0
        }
    }

    return profile

if __name__ == '__main__':
    print(json.dumps(
        gen_profile(PROFILE_NAME, rules),
        indent=2
    ))
