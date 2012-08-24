{
    'targets': [
        {
            'target_name': 'ursaNative',
            'sources': [ 'src/ursaNative.cc' ]
        }
    ],
    'conditions': [
        ['node_shared_openssl=="false"', {
            'include_dirs': [
                '<(node_root_dir)/deps/openssl/openssl/include'
            ]
        }]
    ]
}
