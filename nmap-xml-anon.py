#!/usr/bin/env python2

import struct
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax
import xml.sax.saxutils

class NmapSanitizer(xml.sax.saxutils.XMLGenerator, object):
    """The xml.sax ContentHandler for the XML parser. Ensures only sanitized
    elements are written back out and addresses are rewritten."""
    def __init__(self, f):
        self.f = f
        self.block = 0
        self.block_elements = (
                u"output",
                u"script",
                u"hostscript",
                u"prescript",
                u"postscript",
                u"hostnames",
                u"service",
                u"os",
                u"uptime",
                u"tcpsequence",
                u"ipidsequence",
                u"tcptssequence",
                u"trace",
                )
        self.targetnum = 10 << 24
        super(NmapSanitizer, self).__init__(f)

    def startElement(self, name, attrs):
        if name in self.block_elements:
            self.block += 1
        if self.block > 0:
            return
        if name == u"address":
            if attrs[u"addrtype"] == u"mac":
                return
            else:
                attrs = dict(attrs)
                self.targetnum += 1
                addr = u".".join(map(unicode, struct.unpack("BBBB", struct.pack(">I", self.targetnum))))
                if attrs[u"addrtype"] == u"ipv6":
                    addr = u"::ffff:" + addr
                attrs[u"addr"] = addr
        super(NmapSanitizer, self).startElement(name, attrs)

    def endElement(self, name):
        if name in self.block_elements:
            self.block -= 1
            return
        if self.block > 0:
            return
        super(NmapSanitizer, self).endElement(name)

    def characters(self, content):
        if self.block > 0:
            return
        super(NmapSanitizer, self).characters(content)

if __name__ == "__main__":
    import sys
    parser = xml.sax.make_parser()
    handler = NmapSanitizer(sys.stdout)
    parser.setContentHandler(handler)
    try:
        parser.parse(sys.argv[1])
    except xml.sax.SAXParseException, e:
        # We expect to be processing half-completed XML files, so ignore parsing
        # errors.
        print >>sys.stderr, "Ignored SAXParseException: %s" % e.getMessage()
