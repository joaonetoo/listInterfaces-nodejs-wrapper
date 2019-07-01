{
    "targets": [{
        "target_name": "wrappercap",
        "sources": [ "./wrappercap.cpp" ],
      'include_dirs': [
        "<!(node -e \"require('nan')\")",
      ],
      'conditions': [
        [ 'OS=="win"', {
          'include_dirs': [
            'winpcap/Include',
          ],
          'defines': [
            'WPCAP',
            'HAVE_REMOTE'
          ],
          'conditions': [
            [ 'target_arch=="ia32"', {
              'link_settings': {
                'libraries': ['ws2_32.lib', '<(PRODUCT_DIR)/../../winpcap/Lib/wpcap.lib'],
              },
            }, {
              'link_settings': {
                'libraries': ['ws2_32.lib', '<(PRODUCT_DIR)/../../winpcap/Lib/x64/wpcap.lib'],
              },
            }],
          ],
        }, {
          # POSIX
          'link_settings': {
            'libraries': ['-lpcap'],
          },
        }],
      ],
    },
  ],
}