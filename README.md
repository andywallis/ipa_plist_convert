# ipa_plist_convert
Convert iOS app plist file into XML. 

Convert an iOS plist to XML. Works with:
  1) A .plist file path (binary or XML) -> writes XML
  2) An .ipa file path -> extracts Payload/*/*.app/Info.plist and writes XML

# Usage:
  python ipa_plist_convert.py path/to/app.ipa -o out/Info.plist.xml
  python ipa_plist_convert.py path/to/Info.plist -o out/Info.plist.xml

If -o/--output is omitted, a sensible filename is chosen next to the input.

