# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""
tests/newman/cases/_helpers.py — reserved module for future per-domain helpers.

gen.py skips any file in tests/newman/cases/ whose name begins with '_', so this
file is NOT compiled into a collection. It exists as a stable home for helpers
that grow too large to live inline in gen.py or are too NLB-specific to share
with kacho-vpc.

Currently all reusable blocks live in scripts/gen.py:
  - Step / Case dataclasses
  - assert_status / assert_grpc_code / assert_field_violation
  - save_from_response / assert_operation_envelope
  - poll_operation_until_done
  - http_method_not_allowed_block
  - conf_alreadyexists_block

If you find yourself copy-pasting the same multi-step block across cases/*.py
files, lift it here, then explicitly inject it into the module namespace inside
gen.load_cases_module().
"""
