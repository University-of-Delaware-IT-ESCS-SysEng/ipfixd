"""
https://tools.ietf.org/html/rfc5101
"""

#
# WARNING, the header and the set header are hardcoded in the header
# module.  Changing them here will not impact the code in the header
# module.
#

netflow_v10_header_list = [
    [ 'exportProtocolVersion', 2 ],
    [ 'xx_length', 2 ],
    [ 'flowStartSeconds', 4 ],              # Current secs since 0000 UTC 1970
    [ 'flowId', 4 ],
    [ 'xx_obs_domain_id', 4 ]
]

netflow_v10_set_header_list = [
    [ 'xx_id', 2 ],
    [ 'xx_len', 2 ]
]

netflow_v10_template_header_list = [
    [ 'xx_id', 2 ],
    [ 'xx_field_cnt', 2 ]
]

netflow_v10_options_template_header_list = [
    [ 'xx_id', 2 ],
    [ 'xx_field_cnt', 2 ],
    [ 'xx_scope_field_cnt', 2 ]
]

netflow_v10_field_list = [
    [ 'xx_id', 2 ],
    [ 'xx_len', 2 ]
]

# End.
