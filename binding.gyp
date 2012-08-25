{
    'variables': {
        # Default for this variable, to get the right behavior for
        # Node versions <= 0.6.*.
        'node_shared_openssl%': 'true'
    },
    'targets': [
        {
            'target_name': 'ursaNative',
            'sources': [ 'src/ursaNative.cc' ],
            'conditions': [
                [ 'node_shared_openssl=="false"', {
                    'include_dirs': [
                        '<(node_root_dir)/deps/openssl/openssl/include'
                    ]
                }]
            ]
        }
    ]
}
