rule ObfuscatedCode
{
    meta:
        description = "Detect obfuscated code"
        author = "YourName"
        date = "2024-10-24"
    strings:
        $base64_decode = "base64_decode("
        $eval_function = "eval("
        $hex_encoding = "\\x"
        $short_var = /(\bvar\b|\bconst\b|\blet\b)\s+[a-zA-Z0-9_]{1,2}\s*=/
        $unicode_escape = "\\u"
        $string_from_charcode = "String.fromCharCode"
        $rot13 = "rot13"
    condition:
        2 of them
}
