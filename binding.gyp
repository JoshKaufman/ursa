{
  "targets": [
    {
      'target_name': 'ursaNative',
      'sources': [ 'src/ursaNative.cc' ],
      'include_dirs': [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}

