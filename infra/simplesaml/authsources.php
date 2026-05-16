<?php
$config = [
    'admin' => [
        'core:AdminPassword',
    ],
    'example-userpass' => [
        'exampleauth:UserPass',
        'user@example.com:user' => [
            'uid' => ['user@example.com'],
            'mail' => ['user@example.com'],
            'givenName' => ['Test'],
            'sn' => ['User'],
        ],
    ],
];
