import unittest
from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import *


class TestCase(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(base64("Hello"), "SGVsbG8=")

    def test_base64_decode(self):
        self.assertEqual(base64_decode("SGVsbG8="), b"Hello")

    def test_base64_py(self):
        self.assertEqual(base64_py("Hello"), "SGVsbG8=\n")

    def test_concat(self):
        self.assertEqual(concat("Hello", 123, "world"), "Hello123world")

    def test_compare_versions(self):
        self.assertTrue(compare_versions("v1.0.0", ">v0.0.1", "<v1.0.1"))

    def test_contains(self):
        self.assertEqual(contains("Hello", "lo"), True)

    def test_contains_all(self):
        self.assertEqual(contains_all("Hello everyone", "lo", "every"), True)

    def test_contains_any(self):
        self.assertEqual(contains_any("Hello everyone", "abc", "llo"), True)

    def test_dec_to_hex(self):
        self.assertEqual(dec_to_hex(7001), "1b59")

    def test_hex_to_dec(self):
        self.assertEqual(hex_to_dec("ff"), 255)
        self.assertEqual(hex_to_dec("0xff"), 255)

    def test_bin_to_dec(self):
        self.assertEqual(bin_to_dec("0b1010"), 10)
        self.assertEqual(bin_to_dec(1010), 10)

    def test_oct_to_dec(self):
        self.assertEqual(oct_to_dec("0o1234567"), 342391)
        self.assertEqual(oct_to_dec(1234567), 342391)

    @unittest.skip(reason='different output for the same input')
    def test_gzip(self):
        self.assertEqual(base64(gzip("Hello"))[10:], "H4sIAI9GUGMC//NIzcnJBwCCidH3BQAAAA=="[10:])

    def test_gzip_decode(self):
        self.assertEqual(
            gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000")),
            b"Hello",
        )

    def test_zlib(self):
        self.assertEqual(base64(zlib("Hello")), "eJzzSM3JyQcABYwB9Q==")

    def test_zlib_decode(self):
        self.assertEqual(zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5")), b"Hello")

    def test_hex_decode(self):
        self.assertEqual(hex_decode("6161"), b"aa")

    def test_hex_encode(self):
        self.assertEqual(hex_encode("aa"), "6161")

    def test_html_escape(self):
        self.assertEqual(html_escape("<body>test</body>"), "&lt;body&gt;test&lt;/body&gt;")

    def test_html_unescape(self):
        self.assertEqual(html_unescape("&lt;body&gt;test&lt;/body&gt;"), "<body>test</body>")

    def test_md5(self):
        self.assertEqual(md5("Hello"), "8b1a9953c4611296a827abf8c47804d7")

    def test_mmh3(self):
        self.assertEqual(mmh3("Hello"), "316307400")

    def test_rand_base(self):
        self.assertRegex(rand_base(5, "abc"), r"[abc]{5}")

    def test_rand_char(self):
        self.assertRegex(rand_char("abc"), r"[abc]")

    def test_rand_int(self):
        self.assertIn(rand_int(1, 10), range(1, 11))

    def test_rand_text_alpha(self):
        self.assertRegex(rand_text_alpha(10, "abc"), r"[^abc]{10}")

    def test_rand_text_alphanumeric(self):
        self.assertRegex(rand_text_alphanumeric(10, "ab12"), r"[^ab12]{10}")

    def test_rand_text_numeric(self):
        self.assertRegex(rand_text_numeric(10, "123"), r"[^123]{10}")

    def test_regex(self):
        self.assertTrue(regex("H([a-z]+)o", "Hello"))

    def test_remove_bad_chars(self):
        self.assertEqual(remove_bad_chars("abcd", "bc"), "ad")

    def test_repeat(self):
        self.assertEqual(repeat("../", 5), "../../../../../")

    def test_replace(self):
        self.assertEqual(replace("Hello", "He", "Ha"), "Hallo")

    def test_replace_regex(self):
        self.assertEqual(replace_regex("He123llo", "(\\d+)", ""), "Hello")

    def test_reverse(self):
        self.assertEqual(reverse("abc"), "cba")

    def test_sha1(self):
        self.assertEqual(sha1("Hello"), "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0")

    def test_sha256(self):
        self.assertEqual(
            sha256("Hello"),
            "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
        )

    def test_to_lower(self):
        self.assertEqual(to_lower("HELLO"), "hello")

    def test_to_upper(self):
        self.assertEqual(to_upper("hello"), "HELLO")

    def test_trim(self):
        self.assertEqual(trim("aaaHelloddd", "ad"), "Hello")

    def test_trim_left(self):
        self.assertEqual(trim_left("aaaHelloddd", "ad"), "Helloddd")

    def test_trim_prefix(self):
        self.assertEqual(trim_prefix("aaHelloaa", "aa"), "Helloaa")

    def test_trim_right(self):
        self.assertEqual(trim_right("aaaHelloddd", "ad"), "aaaHello")

    def test_trim_space(self):
        self.assertEqual(trim_space(" Hello "), "Hello")

    def test_trim_suffix(self):
        self.assertEqual(trim_suffix("aaHelloaa", "aa"), "aaHello")

    def test_unix_time(self):
        self.assertGreater(unix_time(10), 1639568278)

    def test_url_decode(self):
        self.assertEqual(
            url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1"),
            "https://projectdiscovery.io?test=1",
        )

    def test_url_encode(self):
        self.assertEqual(
            url_encode("https://projectdiscovery.io/test?a=1"),
            "https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1",
        )

    def test_join(self):
        self.assertEqual(join("_", 123, "hello", "world"), "123_hello_world")

    def test_hmac(self):
        self.assertEqual(hmac("sha1", "test", "scrt"), "8856b111056d946d5c6c92a21b43c233596623c6")

    @unittest.skip(reason="timezone")
    def test_date_time(self):
        self.assertEqual(date_time("%Y-%m-%d %H:%M", 1654870680), "2022-06-10 14:18")

    @unittest.skip(reason="timezone")
    def test_to_unix_time(self):
        self.assertEqual(to_unix_time("2022-01-13 16:30:10"), 1642120210)

    def test_starts_with(self):
        self.assertTrue(starts_with("Hello", "e", "He"))

    def test_line_starts_with(self):
        self.assertTrue(line_starts_with("Hi\nHello", "e", "He"))

    def test_ends_with(self):
        self.assertTrue(ends_with("Hello", "e", "lo"))

    def test_line_ends_with(self):
        self.assertTrue(line_ends_with("Hi\nHello", "e", "lo"))


if __name__ == "__main__":
    unittest.main()
