#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from pocsuite3.lib.core.common import parse_target
from pocsuite3.lib.core.common import OrderedSet


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_domain(self):
        result = OrderedSet()
        result.add('example.com')
        self.assertEqual(parse_target('example.com'), result)

    def test_domain_url(self):
        result = OrderedSet()
        result.add('https://example.com/cgi-bin/test.cgi?a=b&c=d')
        self.assertEqual(parse_target('https://example.com/cgi-bin/test.cgi?a=b&c=d'), result)

    def test_domain_url_with_additional_ports(self):
        result = OrderedSet()
        result.add('https://example.com:8080/cgi-bin/test.cgi?a=b&c=d')
        result.add('https://example.com:8443/cgi-bin/test.cgi?a=b&c=d')
        result.add('http://example.com:10000/cgi-bin/test.cgi?a=b&c=d')
        self.assertEqual(parse_target('https://example.com/cgi-bin/test.cgi?a=b&c=d',
                                      [8080, 8443, 'http:10000'], True), result)

    def test_ipv4_url(self):
        result = OrderedSet()
        result.add('172.16.218.1/cgi-bin')
        self.assertEqual(parse_target('172.16.218.1/cgi-bin'), result)

    def test_ipv6_url(self):
        result = OrderedSet()
        result.add('https://[fd12:3456:789a:1::f0]:8443/test')
        self.assertEqual(parse_target('https://[fd12:3456:789a:1::f0]:8443/test'), result)

    def test_ipv4(self):
        result = OrderedSet()
        result.add('192.168.1.1')
        self.assertEqual(parse_target('192.168.1.1'), result)

    def test_ipv4_cidr(self):
        result = OrderedSet()
        result.add('192.168.1.0')
        result.add('192.168.1.1')
        self.assertEqual(parse_target('192.168.1.1/31'), result)

    def test_ipv4_cidr_with_host_32(self):
        result = OrderedSet()
        result.add('192.168.1.1')
        self.assertEqual(parse_target('192.168.1.1/32'), result)

    def test_ipv4_with_additional_ports(self):
        result = OrderedSet()
        result.add('172.16.218.0:8080')
        result.add('172.16.218.0:8443')
        result.add('https://172.16.218.0:10000')
        result.add('172.16.218.1:8080')
        result.add('172.16.218.1:8443')
        result.add('172.16.218.1:8443')
        result.add('https://172.16.218.1:10000')
        self.assertEqual(parse_target('172.16.218.1/31', [8080, 8443, 'https:10000'], True), result)

    def test_ipv6(self):
        result = OrderedSet()
        result.add('fd12:3456:789a:1::1')
        self.assertEqual(parse_target('fd12:3456:789a:1::1'), result)

    def test_ipv6_cidr(self):
        result = OrderedSet()
        result.add('fd12:3456:789a:1::1')
        result.add('fd12:3456:789a:1::2')
        result.add('fd12:3456:789a:1::3')
        self.assertEqual(parse_target('fd12:3456:789a:1::/126'), result)

    def test_ipv6_cidr_with_host_128(self):
        result = OrderedSet()
        result.add('fd12:3456:789a:1::')
        self.assertEqual(parse_target('fd12:3456:789a:1::/128'), result)

    def test_ipv6_with_additional_ports(self):
        result = OrderedSet()
        result.add('fd12:3456:789a:1::1')
        result.add('[fd12:3456:789a:1::1]:8080')
        result.add('[fd12:3456:789a:1::1]:8443')
        result.add('https://[fd12:3456:789a:1::1]:10000')
        result.add('fd12:3456:789a:1::2')
        result.add('[fd12:3456:789a:1::2]:8080')
        result.add('[fd12:3456:789a:1::2]:8443')
        result.add('https://[fd12:3456:789a:1::2]:10000')
        result.add('fd12:3456:789a:1::3')
        result.add('[fd12:3456:789a:1::3]:8080')
        result.add('[fd12:3456:789a:1::3]:8443')
        result.add('https://[fd12:3456:789a:1::3]:10000')
        self.assertEqual(parse_target('fd12:3456:789a:1::/126', [8080, 8443, 'https:10000']), result)

    def test_localhost(self):
        result = OrderedSet()
        result.add('localhost')
        self.assertEqual(parse_target('localhost'), result)

    def test_random_str(self):
        result = OrderedSet()
        result.add('!@#$%^&*()_-+=:::::<>""{}[]:::8080')
        self.assertEqual(parse_target('!@#$%^&*()_-+=:::::<>""{}[]:::8080'), result)
